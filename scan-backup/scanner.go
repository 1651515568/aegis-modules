package backup

// scanner.go —— 真实备份/敏感文件存在性探测引擎。
//
// 探测原则(与模块对外宣称一致,且代码层面强制保证):
//   * 仅判定「文件是否存在」,绝不下载文件体 —— 用 HEAD;需要识别类型时
//     仅用 Range: bytes=0-15 读取头部魔数,最多 16 字节。
//   * 不做任何鉴权 / 路径绕过 —— 遇到 401/403 仅记录「存在但受限」即止。
//   * soft-404 基线检测 —— 先对随机不存在路径打点,过滤「对什么都回 200」的站点。
//   * 带并发上限、单请求超时、每主机候选上限、可随时取消。

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"redops/core"
)

const (
	scanUserAgent = "RedOps-BackupScanner/0.2 (existence-probe; HEAD/Range-only)"
	probeReadCap  = 16 // Range 仅读前 16 字节做魔数识别,绝不下载文件体
	probeTextCap  = 64 // 文本型敏感文件扩展探针上限(字节),用于 .env/.sql/id_rsa 等模式识别
)

// scanOptions 来自前端 POST /scan 的请求体。
type scanOptions struct {
	Targets        []string `json:"targets"`        // 目标 URL / 域名列表
	MaxPerHost     int      `json:"maxPerHost"`     // 每主机候选上限(默认 60000,上限 200000)
	Concurrency    int      `json:"concurrency"`    // 并发数(默认 12,上限 128)
	TimeoutMs      int      `json:"timeoutMs"`      // 单请求超时(默认 6000ms)
	RatePerSec     float64  `json:"ratePerSec"`     // 全局请求限速(默认 10 req/s,上限 100;<=0 不限速)
	MaxDepth       int      `json:"maxDepth"`       // 递归目录发现深度(默认 1,上限 3;0 关闭递归)
	MaxDurationSec int      `json:"maxDurationSec"` // 扫描总时长上限(秒),0=不限;前端默认下发 1800
	Crawl          bool     `json:"crawl"`          // 是否启用智能爬取(提取真实文件名/目录派生候选)
	MaxCrawlPages  int      `json:"maxCrawlPages"`  // 爬取页面数上限(默认 25,上限 200)
	IncludeEditor  bool     `json:"includeEditor"`  // 是否对文件名套编辑器遗留后缀
	Cookie             string   `json:"cookie"`             // 鉴权 Cookie(格式: key=value; key2=value2)
	Authorization      string   `json:"authorization"`      // Authorization 头值(Bearer <token> / Basic <b64>)
	Proxy              string   `json:"proxy"`              // 上游代理 http(s):// 或 socks5://（空则取环境变量）
	ExtraWordlist      string   `json:"extraWordlist"`      // 外部字典: 内嵌预置名、下载预置名或 "custom"
	ExtraWordlistURL   string   `json:"extraWordlistURL"`   // 自定义外部字典 URL(ExtraWordlist="custom"时生效)
	CustomWordlistText []string `json:"customWordlistText"` // 用户粘贴的自定义字典(每行一条路径，与其他字典叠加)
}

func (o *scanOptions) applyDefaults() {
	if o.MaxPerHost <= 0 {
		o.MaxPerHost = 60000
	}
	if o.MaxPerHost > 200000 {
		o.MaxPerHost = 200000
	}
	// MaxDepth: 0=关闭递归;上限 3 防过深爆炸。前端默认下发 2(两层递归，命中率更高)。
	if o.MaxDepth < 0 {
		o.MaxDepth = 0
	}
	if o.MaxDepth > 3 {
		o.MaxDepth = 3
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 30
	}
	if o.Concurrency > 128 {
		o.Concurrency = 128
	}
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = 6000
	}
	// RatePerSec: 缺省 / 非法值取 50 req/s；HEAD 请求轻量，50 是合理默认；上限 500。
	if o.RatePerSec <= 0 {
		o.RatePerSec = 50
	}
	if o.RatePerSec > 500 {
		o.RatePerSec = 500
	}
	// MaxDurationSec: 0=不限时长;上限 24h 防异常长跑。前端默认下发 1800(30 分钟)。
	if o.MaxDurationSec < 0 {
		o.MaxDurationSec = 0
	}
	if o.MaxDurationSec > 86400 {
		o.MaxDurationSec = 86400
	}
	// MaxCrawlPages: 爬取页数上限。缺省 25,封顶 200 防长跑。
	if o.MaxCrawlPages <= 0 {
		o.MaxCrawlPages = 25
	}
	if o.MaxCrawlPages > 200 {
		o.MaxCrawlPages = 200
	}
}

type scanner struct {
	log   core.Logger
	store *store
	lim   *limiter // 每次 run 重建;限速器跨该次扫描的所有探测请求共享
}

func newScanner(log core.Logger, st *store) *scanner { return &scanner{log: log, store: st} }

// baseline 多样本基线 —— 对若干随机不存在路径打点,刻画站点的「不存在」响应特征,
// 用于过滤 soft-404(对什么都回 200)并判定 403 是否可信。
type baseline struct {
	connected  bool   // 是否至少连通一次(否则触发 http/https 回退)
	clean404   bool   // 所有连通样本都回 404/410 → 站点 404 行为干净
	blanket200 bool   // 存在 junk 回 2xx → soft-404 站点
	stableLen  bool   // soft-404 各样本长度是否稳定一致
	softLen    int64  // 稳定时的 soft-404 代表长度
	sample     []byte // soft-404 模板页头部样本(≤calibrateSampleCap),用于响应体相似度校准
}

// probeJob 是一个待探测单元: 目标 + 候选 + 该目标的基线。
type probeJob struct {
	u    *url.URL
	cand candidate
	base baseline
}

// run 发起一次全新扫描(不跳过任何目标)。
func (sc *scanner) run(ctx context.Context, opt scanOptions) {
	// 解析 ExtraWordlist="custom" → ExtraWordlistURL
	if opt.ExtraWordlist == "custom" {
		opt.ExtraWordlist = strings.TrimSpace(opt.ExtraWordlistURL)
	}
	sc.runScan(ctx, opt, nil)
}

// runScan 是后台扫描主流程。skip 中的 host 标签会被跳过(断点续扫:跳过已完成目标)。
func (sc *scanner) runScan(ctx context.Context, opt scanOptions, skip map[string]bool) {
	// flushStop 提前声明，确保 panic 路径的 defer 也能关闭它，防止 flush goroutine 泄漏。
	flushStop := make(chan struct{})
	var flushStopClosed bool
	closeFlushStop := func() {
		if !flushStopClosed {
			flushStopClosed = true
			close(flushStop)
		}
	}
	defer closeFlushStop() // 任何退出路径（含 panic-recover）均触发，防止 goroutine 泄漏
	defer func() {
		if r := recover(); r != nil {
			sc.store.finishScan(fmt.Sprintf("内部错误: %v", r))
		}
	}()
	opt.applyDefaults()

	// 扫描总时长上限:用带超时的子 ctx 包裹。保留 parentCtx 以区分「用户取消」与「超时」。
	parentCtx := ctx
	if opt.MaxDurationSec > 0 {
		var cancelTO context.CancelFunc
		ctx, cancelTO = context.WithTimeout(ctx, time.Duration(opt.MaxDurationSec)*time.Second)
		defer cancelTO()
	}

	// 解析 + 规范化目标。
	type tgt struct {
		u        *url.URL
		explicit bool
	}
	var targets []tgt
	var labels []string
	for _, t := range opt.Targets {
		if u, explicit, err := normalizeTarget(t); err == nil {
			targets = append(targets, tgt{u, explicit})
			labels = append(labels, u.Host)
		}
	}
	if len(targets) == 0 {
		sc.store.finishScan("无有效目标(需为 http(s) URL 或域名)")
		return
	}
	sc.store.setTarget(strings.Join(labels, ", "))

	sc.lim = newLimiter(opt.RatePerSec) // 全局限速器:本次扫描所有请求(含基线)统一过闸
	client := buildClient(opt)

	// 加载外部字典(内嵌预置/网络下载);失败降级为空列表。
	var extDict []string
	if opt.ExtraWordlist != "" {
		if words, err := LoadExternalDict(ctx, opt.ExtraWordlist, opt.Proxy, sc.log); err != nil {
			sc.log.Warn("backup extdict load failed, continuing without it", "err", err)
		} else {
			extDict = words
			sc.log.Info("backup extdict ready", "entries", len(extDict))
		}
	}
	// 用户粘贴的自定义字典（前端 string[]，与外部字典叠加，去重由 enqueue 保证）。
	if len(opt.CustomWordlistText) > 0 {
		extDict = append(extDict, opt.CustomWordlistText...)
		sc.log.Info("backup custom wordlist merged", "entries", len(opt.CustomWordlistText))
	}
	// 始终叠加全部内置 raft 字典（无需用户手选，一次性覆盖最大路径集合）。
	// enqueue 内 seen map 保证去重，不会重复探测。
	extDict = append(extDict, dictRaftMediumFiles...)
	extDict = append(extDict, dictRaftMediumDirs...)
	sc.log.Info("backup raft dicts auto-merged",
		"raft-files", len(dictRaftMediumFiles), "raft-dirs", len(dictRaftMediumDirs))

	run := &scanRun{sc: sc, ctx: ctx, client: client, opt: opt, sem: make(chan struct{}, opt.Concurrency)}

	// 增量落盘:扫描期间每 5s flush 一次命中,崩溃最多丢一个间隔的结果。
	// flushStop 已在函数顶部声明并由 defer 保证关闭，此处仅启动 goroutine。
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-flushStop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				sc.store.persist()
			}
		}
	}()

	// 为每个目标取基线,投放根候选 + (启用递归时)目录探测。候选总数随递归动态增长。
	reachable := 0
	for _, t := range targets {
		if ctx.Err() != nil {
			sc.store.finishScan("已取消")
			closeFlushStop()
			return
		}
		if skip != nil && skip[t.u.Host] {
			continue // 续扫:跳过已完成目标
		}
		u := t.u
		base := sc.measureBaseline(ctx, client, u)
		// http/https 自动回退: 默认 https 连不通且用户未显式指定 scheme → 改试 http。
		if !base.connected && !t.explicit && u.Scheme == "https" {
			alt := *u
			alt.Scheme = "http"
			if ab := sc.measureBaseline(ctx, client, &alt); ab.connected {
				sc.log.Info("backup scan scheme fallback", "host", u.Host, "https->http", true)
				u, base = &alt, ab
			}
		}
		if !base.connected {
			sc.log.Info("backup scan target unreachable", "host", u.Host)
			continue
		}
		reachable++
		// outstanding 起始为 1(seed token):enqueue 全部候选期间保持 ≥1,
		// 待本主机所有候选投放完毕再 hostDecr 移除,避免提前误判该主机完成。
		hc := &hostCtx{u: u, base: base, label: u.Host, seen: make(map[string]struct{}), budget: int64(opt.MaxPerHost), outstanding: 1}

		// 智能爬取:抓取普通页面/robots/sitemap,提取真实文件名与目录。
		disco := newDiscovery()
		if opt.Crawl {
			disco = sc.crawl(ctx, client, u, opt.MaxCrawlPages)
			if len(disco.files)+len(disco.dirs) > 0 {
				sc.log.Info("backup crawl discovered", "host", u.Host, "files", len(disco.files), "dirs", len(disco.dirs))
			}
		}

		// 爬取派生优先投放(命中率高,先消费有限时长/预算)。
		for f := range disco.files {
			for _, c := range backupVariantCandidates(f) {
				run.enqueue(hc, c, 0, false)
			}
			if looksSensitive(f) {
				run.enqueue(hc, candidate{rel: f, rule: "爬取发现: /" + f, kind: classifyKind(f, "", "")}, 0, false)
			}
		}
		// 字典候选(根文件,不消耗递归预算)。
		for _, c := range genCandidates(u, opt.MaxPerHost, opt.IncludeEditor) {
			run.enqueue(hc, c, 0, false)
		}
		// 外部字典(去重由 enqueue 内 seen map 保证)。
		for _, p := range extDict {
			run.enqueue(hc, candidate{rel: p, rule: "外部字典: " + p, kind: classifyKind(p, "", "")}, 0, false)
		}
		// 根目录探测 —— 仅在干净 404 站点上启用递归,避免 soft-404 站点误判爆炸。
		// 既探猜测目录,也探爬取发现的真实目录(命中率更高)。
		if opt.MaxDepth > 0 && base.clean404 {
			seenDir := make(map[string]struct{})
			enqueueDir := func(rel, rule string) {
				if _, ok := seenDir[rel]; ok {
					return
				}
				seenDir[rel] = struct{}{}
				run.enqueue(hc, candidate{rel: rel, rule: rule, isDir: true}, 0, false)
			}
			for _, d := range recurseDirs {
				enqueueDir(d+"/", "递归目录: /"+d+"/")
			}
			for d := range disco.dirs {
				rel := strings.TrimSuffix(d, "/") + "/"
				enqueueDir(rel, "爬取目录: /"+rel)
			}
		}
		run.hostDecr(hc) // 移除 seed token;若该主机候选已全部探完则即时 checkpoint
	}
	if reachable == 0 {
		closeFlushStop()
		if len(skip) > 0 {
			// 续扫:剩余目标都不可达或已无目标 → 视为完成。
			sc.store.finishScan("")
			sc.store.setJobStatus("done")
			return
		}
		sc.store.finishScan("目标不可达(http/https 均无响应)")
		return
	}
	sc.log.Info("backup scan started", "targets", reachable, "maxDepth", opt.MaxDepth, "crawl", opt.Crawl)

	run.wg.Wait()
	closeFlushStop()

	switch {
	case parentCtx.Err() != nil:
		sc.store.finishScan("已取消")
		sc.store.setJobStatus("canceled")
		sc.store.persist() // 取消时也保存已命中的结果
		return
	case ctx.Err() == context.DeadlineExceeded:
		sc.store.finishScan(fmt.Sprintf("已达扫描时长上限(%d 秒),已停止并保存已命中结果", opt.MaxDurationSec))
		sc.store.setJobStatus("timeout")
		sc.store.persist()
		sc.log.Info("backup scan hit time limit", "seconds", opt.MaxDurationSec, "found", sc.store.status().Found)
		return
	}
	sc.store.finishScan("")
	sc.store.setJobStatus("done")
	sc.store.persist() // 扫描完成后自动落盘,重启可恢复
	sc.log.Info("backup scan finished", "found", sc.store.status().Found)
}

// measureBaseline 对多个随机路径打点(覆盖归档 / 备份 / 无扩展名),刻画站点的「不存在」响应。
// 多样本能识别「按路径动态生成 soft-404 页(长度漂移)」的站点,显著降低误报。
func (sc *scanner) measureBaseline(ctx context.Context, client *http.Client, u *url.URL) baseline {
	var b baseline
	suffixes := []string{".zip", ".bak", ".sql", ""}
	codes := make([]int, 0, len(suffixes))
	var soft200Lens []int64
	for _, suf := range suffixes {
		if ctx.Err() != nil {
			break
		}
		junk := "rdx404-" + randToken() + suf // 几乎不可能真实存在
		code, clen, _, body := sc.sampleBody(ctx, client, probeURL(u, junk), calibrateSampleCap)
		if code == 0 {
			continue // 连接失败,不计入样本
		}
		b.connected = true
		codes = append(codes, code)
		if code == http.StatusOK || code == http.StatusPartialContent {
			soft200Lens = append(soft200Lens, clen)
			if len(b.sample) == 0 && len(body) > 0 {
				b.sample = body // 保留首个 soft-404 模板样本,供后续相似度校准
			}
		}
	}
	// 至少 2/4 个探测返回 2xx 才激活 blanket200 抑制，避免单次偶发 200（如随机路径碰巧存在）
	// 误触发 soft-404 模式，导致后续真实备份文件被相似度过滤掉（漏报）。
	b.blanket200 = len(soft200Lens) >= 2
	// 所有连通样本都回 404/410 → 干净 404 站点(403/200 命中才可信)。
	b.clean404 = len(codes) > 0
	for _, c := range codes {
		if c != http.StatusNotFound && c != http.StatusGone {
			b.clean404 = false
		}
	}
	// soft-404 长度稳定性: 各 2xx 样本长度一致(容差 64B)且 > 0 → 可用长度差异区分真实文件。
	if len(soft200Lens) > 0 {
		lo, hi := soft200Lens[0], soft200Lens[0]
		for _, l := range soft200Lens {
			if l < lo {
				lo = l
			}
			if l > hi {
				hi = l
			}
		}
		if lo > 0 && hi-lo <= 64 {
			b.stableLen = true
			b.softLen = hi
		}
	}
	return b
}

// acceptOn200 判定一个 2xx 候选是否为真实命中(已结合 soft-404 基线)。
func acceptOn200(b baseline, magic string, clen int64) bool {
	if magic != "" {
		return true // 魔数被识别 → 确为归档 / 配置文件
	}
	if !b.blanket200 {
		return true // 干净站点上的 2xx 即真实存在
	}
	// soft-404 站点: 仅当长度稳定且与软 404 长度明显不同才采信(动态 soft-404 则保守拒绝)。
	return b.stableLen && clen > 0 && absDiff(clen, b.softLen) > 64
}

// probe 探测单个候选,命中则返回 *Hit。
func (sc *scanner) probe(ctx context.Context, client *http.Client, j probeJob) *Hit {
	full := probeURL(j.u, j.cand.rel)

	// 先 HEAD。
	code, clen, ctype, allow := sc.do(ctx, client, http.MethodHead, full)

	accepted := false
	protected := false
	magic := ""

	switch {
	case code == http.StatusOK || code == http.StatusPartialContent:
		// 命中候选 —— 用 Range 读头部字节确认类型 / 在 soft-404 站点上做内容区分。
		// 文本型敏感文件（.env/.sql/id_rsa 等）读 probeTextCap(64B) 以启用文本模式识别；
		// 普通候选读 probeReadCap(16B) 做二进制魔数识别。
		sensitiveText := isSensitiveTextExt(j.cand.rel)
		var mcode int
		var mlen int64
		var mtype string
		var head []byte
		if sensitiveText {
			mcode, mlen, mtype, head = sc.doMagicN(ctx, client, full, probeTextCap)
		} else {
			mcode, mlen, mtype, head = sc.doMagic(ctx, client, full)
		}
		if mcode == http.StatusOK || mcode == http.StatusPartialContent {
			code, ctype = mcode, mtype
			if mlen > 0 {
				clen = mlen
			}
		}
		magic = magicLabel(head)
		if magic == "" && sensitiveText {
			magic = textPatternLabel(head) // 文本型敏感文件追加模式识别
		}
		accepted = sc.acceptCalibrated(ctx, client, full, j.base, magic, clen)
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		// 存在但受限 —— 仅当站点对随机路径回干净 404(能区分存在性)时才采信,绝不尝试绕过。
		if j.base.clean404 {
			accepted = true
			protected = true
		}
	case code == http.StatusMethodNotAllowed, code == http.StatusNotImplemented:
		// 不支持 HEAD,退回 Range 探测。
		mcode, mlen, mtype, head := sc.doMagic(ctx, client, full)
		if mcode == http.StatusOK || mcode == http.StatusPartialContent {
			code, ctype, clen, magic = mcode, mtype, mlen, magicLabel(head)
			accepted = sc.acceptCalibrated(ctx, client, full, j.base, magic, clen)
		}
	}
	_ = allow
	if !accepted {
		return nil
	}

	kind := classifyKind(j.cand.rel, ctype, magic)
	sev := severityFor(kind, code, j.cand.rel)
	file := fileLabel(j.cand.rel)

	h := Hit{
		ID:       hitID(j.u.Host, j.cand.rel),
		URL:      full,
		File:     file,
		Kind:     kind,
		Size:     humanSize(clen),
		Code:     code,
		Rule:     j.cand.rule,
		Host:     j.u.Host,
		Severity: sev,
		At:       nowStamp(),
		Note:     noteFor(kind, protected),
		Detail:   detailFor(kind, protected),
		Sample:   sampleFor(magic, ctype, protected),
		Evidence: Evidence{
			Request:  evidenceRequest(full, j.u.Host, protected),
			Response: evidenceResponse(code, ctype, clen, magic, protected),
			Note:     "默认仅 HEAD / Range(≤16B);文本型敏感文件(如 .env/.sql)另读 ≤64B 做类型识别;soft-404 站点会另读 ≤512B 头部做相似度校准。均不下载完整文件体,未尝试任何绕过。",
		},
		Remediation: remediationFor(kind, j.cand.rel),
		Refs:        refsFor(kind),
		Chain:       []string{"扫描打点: 目标收敛", "备份探测: " + j.cand.rule, "存在性探测: " + probeMethodNote(protected)},
	}
	return &h
}

// do 发一个 HEAD 请求,返回状态码 / Content-Length / Content-Type / Allow。
// 每次发请求前先过全局限速闸;命中 429/503 则带上限退避重试,绝不当作「不存在」。
// netAttempt / throttleAttempt 独立计数：网络抖动消耗 netAttempt 预算，不占用 throttleAttempt，
// 避免「2 次网络错误 → 1 次 429」场景下 429 重试预算被网络错误透支。
func (sc *scanner) do(ctx context.Context, client *http.Client, method, rawURL string) (int, int64, string, string) {
	var netAttempt, throttleAttempt int
	for {
		if sc.lim.wait(ctx) != nil {
			return 0, -1, "", ""
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return 0, -1, "", ""
		}
		req.Header.Set("User-Agent", scanUserAgent)
		req.Header.Set("Accept", "*/*")
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil && netAttempt < maxNetRetries {
				sc.netRetryWait(ctx, netAttempt)
				netAttempt++
				continue
			}
			return 0, -1, "", ""
		}
		code := resp.StatusCode
		if isThrottle(code) && throttleAttempt < maxRetries {
			ra := resp.Header.Get("Retry-After")
			_ = resp.Body.Close()
			if !sc.backoff(ctx, ra, throttleAttempt) {
				return code, -1, "", "" // 已取消
			}
			throttleAttempt++
			continue
		}
		// HEAD 响应理论无 body，但须完整排空才能让 Transport 复用连接（零长 LimitReader 不足）。
		_, _ = io.Copy(io.Discard, resp.Body)
		clen, ctype, allow := resp.ContentLength, resp.Header.Get("Content-Type"), resp.Header.Get("Allow")
		_ = resp.Body.Close()
		return code, clen, ctype, allow
	}
}

// doMagicN 用 Range 请求读取头部最多 cap 字节，返回状态码 / 长度 / 类型 / 头部字节。
// cap=probeReadCap(16) 用于二进制魔数识别；cap=probeTextCap(64) 用于文本型敏感文件模式识别。
// 同样经全局限速闸,并对 429/503 退避重试。
func (sc *scanner) doMagicN(ctx context.Context, client *http.Client, rawURL string, cap int) (int, int64, string, []byte) {
	var netAttempt, throttleAttempt int
	for {
		if sc.lim.wait(ctx) != nil {
			return 0, -1, "", nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return 0, -1, "", nil
		}
		req.Header.Set("User-Agent", scanUserAgent)
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", cap-1))
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil && netAttempt < maxNetRetries {
				sc.netRetryWait(ctx, netAttempt)
				netAttempt++
				continue
			}
			return 0, -1, "", nil
		}
		code := resp.StatusCode
		if isThrottle(code) && throttleAttempt < maxRetries {
			ra := resp.Header.Get("Retry-After")
			_ = resp.Body.Close()
			if !sc.backoff(ctx, ra, throttleAttempt) {
				return code, -1, "", nil // 已取消
			}
			throttleAttempt++
			continue
		}
		head := make([]byte, cap)
		n, _ := io.ReadFull(io.LimitReader(resp.Body, int64(cap)), head)
		// 关键安全保证:读满 cap 字节即停,绝不继续读取 body。
		// 切忌在此 io.Copy 排空 resp.Body —— 当服务器忽略 Range 直接回 200(整文件)时,
		// 排空会把整份备份/数据库文件经网络拉下,既违背「仅探存在性」承诺又会拖垮大文件。
		// 未读尽的连接随后由 Close 关闭(Transport 不复用该连接),这点代价可接受。
		// 206 的 ContentLength 是分块长度(≤cap);文件真实大小在 Content-Range 的 total 段,优先采用。
		clen := resp.ContentLength
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if total := parseContentRangeTotal(cr); total > 0 {
				clen = total
			}
		}
		ctype := resp.Header.Get("Content-Type")
		_ = resp.Body.Close()
		return code, clen, ctype, head[:n]
	}
}

// doMagic 用 Range 请求读取头部最多 probeReadCap(16) 字节，做二进制魔数识别。
func (sc *scanner) doMagic(ctx context.Context, client *http.Client, rawURL string) (int, int64, string, []byte) {
	return sc.doMagicN(ctx, client, rawURL, probeReadCap)
}

// backoff 收到 429/503 后:把全局排程温和后推(让所有并发请求一起降速),
// 再令本 goroutine 退避等待后重试。返回 false 表示扫描已被取消。
func (sc *scanner) backoff(ctx context.Context, retryAfter string, attempt int) bool {
	d := retryAfterDelay(retryAfter, attempt)
	// 全局降速取温和上限,避免单个限流主机把整轮多目标扫描冻死。
	pen := d
	if pen > globalPenaltyCap {
		pen = globalPenaltyCap
	}
	sc.lim.penalize(pen)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// netRetryWait 在瞬时网络错误后做一小段退避(指数,尊重 ctx 取消)。
func (sc *scanner) netRetryWait(ctx context.Context, attempt int) {
	t := time.NewTimer(netRetryDelay(attempt))
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// sampleBody 读取响应头部最多 limit 字节(GET 带 Range 限制),用于 soft-404 相似度校准。
// 经限速闸,对 429/503 退避、对网络错误重试;绝不读取超过 limit 字节,不下载完整文件体。
func (sc *scanner) sampleBody(ctx context.Context, client *http.Client, rawURL string, limit int) (int, int64, string, []byte) {
	var netAttempt, throttleAttempt int
	for {
		if sc.lim.wait(ctx) != nil {
			return 0, -1, "", nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return 0, -1, "", nil
		}
		req.Header.Set("User-Agent", scanUserAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil && netAttempt < maxNetRetries {
				sc.netRetryWait(ctx, netAttempt)
				netAttempt++
				continue
			}
			return 0, -1, "", nil
		}
		code := resp.StatusCode
		if isThrottle(code) && throttleAttempt < maxRetries {
			ra := resp.Header.Get("Retry-After")
			_ = resp.Body.Close()
			if !sc.backoff(ctx, ra, throttleAttempt) {
				return code, -1, "", nil
			}
			throttleAttempt++
			continue
		}
		buf := make([]byte, limit)
		n, _ := io.ReadFull(io.LimitReader(resp.Body, int64(limit)), buf)
		// 读满 cap 即停,绝不继续读取文件体(同 doMagic 的安全保证)。
		clen := resp.ContentLength
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			if total := parseContentRangeTotal(cr); total > 0 {
				clen = total
			}
		}
		ctype := resp.Header.Get("Content-Type")
		_ = resp.Body.Close()
		return code, clen, ctype, buf[:n]
	}
}

// acceptCalibrated 判定 soft-404 站点上的 2xx 候选是否真实命中。
// 优先做相似度比对；无法比对时退回长度启发；实在无法判定则接受（不漏报真实文件）。
func (sc *scanner) acceptCalibrated(ctx context.Context, client *http.Client, full string, b baseline, magic string, clen int64) bool {
	if magic != "" || !b.blanket200 {
		return true // 魔数已识别 / 干净站点 2xx
	}
	if len(b.sample) >= 2 {
		_, _, _, samp := sc.sampleBody(ctx, client, full, calibrateSampleCap)
		if len(samp) > 0 {
			return similarity(samp, b.sample) < calibrateThreshold
		}
		// 取不到候选体（网络抖动）：宁可上报一条，不漏掉真实文件
		return true
	}
	// 无模板样本，退回长度启发
	if b.stableLen && clen > 0 {
		diff := absDiff(clen, b.softLen)
		// 绝对差异 > 32B 或相对差异 > 10%（对小文件友好，32B 以上即接受）
		return diff > 32 || (b.softLen > 0 && float64(diff)/float64(b.softLen) > 0.10)
	}
	// 无样本且长度不稳定：无法判定，接受候选（避免漏报备份文件）
	return true
}

// ---- 探测辅助 ----

// authTransport 在每个请求上注入 Cookie / Authorization 头,不改变其它行为。
type authTransport struct {
	base          http.RoundTripper
	cookie        string
	authorization string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if t.cookie != "" {
		r.Header.Set("Cookie", t.cookie)
	}
	if t.authorization != "" {
		r.Header.Set("Authorization", t.authorization)
	}
	return t.base.RoundTrip(r)
}

func buildClient(opt scanOptions) *http.Client {
	proxyFn := http.ProxyFromEnvironment
	if opt.Proxy != "" {
		if pu, err := url.Parse(opt.Proxy); err == nil && pu.Host != "" &&
			(pu.Scheme == "http" || pu.Scheme == "https" || pu.Scheme == "socks5") {
			proxyFn = http.ProxyURL(pu)
		}
	}
	tr := &http.Transport{
		// 扫描器只判存在性、不传输任何敏感数据,目标常带自签 / 过期证书,故跳过证书校验。
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 16,
		Proxy:               proxyFn,
	}
	var transport http.RoundTripper = tr
	if opt.Cookie != "" || opt.Authorization != "" {
		transport = &authTransport{base: tr, cookie: opt.Cookie, authorization: opt.Authorization}
	}
	return &http.Client{
		Timeout:   time.Duration(opt.TimeoutMs) * time.Millisecond,
		Transport: transport,
		// 不跟随跳转 —— 3xx 多半被导向登录页,会污染命中判定。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// normalizeTarget 把用户输入规范成带 scheme 的 URL(缺省 https)。
// 第二个返回值表示用户是否显式写了 scheme —— 未显式时允许 https→http 回退。
func normalizeTarget(s string) (*url.URL, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false, fmt.Errorf("empty")
	}
	explicit := strings.Contains(s, "://")
	if !explicit {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, false, err
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, false, fmt.Errorf("invalid target: %s", s)
	}
	return u, explicit, nil
}

// probeURL 把站点根相对路径拼到目标 host 上。
func probeURL(u *url.URL, rel string) string {
	b := *u
	b.Path = "/" + strings.TrimPrefix(rel, "/")
	b.RawQuery = ""
	b.Fragment = ""
	return b.String()
}

func randToken() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

// magicLabel 依头部魔数识别归档 / 配置类型(仅前 16 字节)。
func magicLabel(b []byte) string {
	switch {
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4:
		return "zip"
	case len(b) >= 4 && string(b[:4]) == "Rar!":
		return "rar"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case len(b) >= 6 && b[0] == '7' && b[1] == 'z' && b[2] == 0xBC && b[3] == 0xAF:
		return "7z"
	case len(b) >= 3 && string(b[:3]) == "BZh":
		return "bzip2"
	case len(b) >= 15 && strings.HasPrefix(string(b), "SQLite format 3"):
		return "sqlite"
	case hasPHPTag(b):
		return "php"
	case len(b) >= 2 && b[0] == '[' && hasCloseBracket(b, 32):
		return "git-config"
	case len(b) >= 10 && strings.HasPrefix(string(b), "-----BEGIN"):
		return "pem"
	}
	return ""
}

func parseContentRangeTotal(cr string) int64 {
	// 形如 "bytes 0-15/50535219"
	if i := strings.LastIndex(cr, "/"); i >= 0 && i+1 < len(cr) {
		var n int64
		_, err := fmt.Sscan(cr[i+1:], &n)
		if err == nil {
			return n
		}
	}
	return -1
}

// ---- 文本型敏感文件检测 ----

// hasPHPTag 检测 PHP 起始标签，支持 UTF-8 BOM（EF BB BF）前缀。
func hasPHPTag(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	off := 0
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		off = 3
	}
	return len(b) >= off+5 && strings.HasPrefix(string(b[off:]), "<?php")
}

// hasCloseBracket 判定字节切片头部 limit 字节内是否含 ']'（用于 git config 节区检测）。
func hasCloseBracket(b []byte, limit int) bool {
	end := len(b)
	if end > limit {
		end = limit
	}
	for _, c := range b[:end] {
		if c == ']' {
			return true
		}
	}
	return false
}

// 高价值文本型敏感文件的扩展名与文件名列表（无固定二进制魔数）。
var (
	sensitiveTextExts = []string{
		".env", ".sql", ".key", ".pem", ".conf", ".cfg", ".ini",
		".log", ".passwd", ".htpasswd", ".netrc", ".npmrc", ".pgpass",
		".sh", ".bash_history",
		".yml", ".yaml", ".toml", ".json", ".xml",
	}
	sensitiveTextNames = []string{
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		"authorized_keys", "known_hosts",
		".env", ".env.local", ".env.development", ".env.production",
		"credentials", "secrets",
		"docker-compose.yml", "docker-compose.yaml",
		"application.yml", "application.yaml",
		"config.yml", "config.yaml", "config.toml", "config.json", "config.xml",
		"appsettings.json", "settings.json", "secrets.json",
	}
)

// isSensitiveTextExt 判定候选路径是否为高价值文本型敏感文件（无固定魔数但意义重大）。
func isSensitiveTextExt(rel string) bool {
	lp := strings.ToLower(rel)
	base := lp
	if i := strings.LastIndex(lp, "/"); i >= 0 {
		base = lp[i+1:]
	}
	for _, n := range sensitiveTextNames {
		if base == n {
			return true
		}
	}
	for _, ext := range sensitiveTextExts {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}

// textPatternLabel 对 ≤64B 的头部字节做文本型敏感文件模式识别（补充 magicLabel 的二进制魔数）。
func textPatternLabel(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	s := string(b)
	if strings.HasPrefix(s, "-----BEGIN") {
		return "pem"
	}
	for _, pfx := range []string{"-- ", "CREATE ", "INSERT ", "DROP ", "ALTER ", "USE "} {
		if strings.HasPrefix(s, pfx) {
			return "sql"
		}
	}
	if looksLikeEnvContent(b) {
		return "env"
	}
	// JSON 先于 git-config：looksLikeJSON 对 [ 开头的数组要求第二字节为 { / " / 数字等
	// 才返回 true，而 git-config [section] 的第二字节是字母，不会误判。
	if looksLikeJSON(b) {
		return "json"
	}
	if len(b) >= 2 && b[0] == '[' && hasCloseBracket(b, 32) {
		return "git-config"
	}
	if looksLikeYAML(b) {
		return "yaml"
	}
	if looksLikeXML(b) {
		return "xml"
	}
	if looksLikeTOML(b) {
		return "toml"
	}
	return ""
}

// looksLikeEnvContent 判定字节是否以 KEY=value 格式开头（.env 文件特征）。
func looksLikeEnvContent(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	s := string(b)
	for _, line := range strings.SplitN(s, "\n", 6) {
		line = strings.TrimRight(line, "\r \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return false
		}
		key := line[:eq]
		if len(key) == 0 || len(key) > 80 {
			return false
		}
		for _, c := range key {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true
	}
	return false
}

// looksLikeYAML 检测 YAML 文档特征。
// 原先用 strings.Contains(s, ": ") 过于宽泛（普通 HTML/JSON 均含此模式），
// 改为要求文档以 "---" 开头，或第一行包含 "key: " 模式（字母/数字/下划线冒号空格）。
func looksLikeYAML(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) < 3 {
		return false
	}
	if strings.HasPrefix(s, "---") {
		return true
	}
	// 匹配第一行的 "word: " 模式（YAML key: value），排除 HTML 属性/URL 等含冒号的场景
	firstLine := s
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		firstLine = s[:idx]
	}
	if idx := strings.Index(firstLine, ": "); idx > 0 {
		key := firstLine[:idx]
		// key 只含字母、数字、下划线、连字符才认为是 YAML key
		for _, c := range key {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return len(key) > 0 && len(key) <= 64
	}
	return false
}

// looksLikeJSON 检测 JSON 对象或数组起始。
// JSON 对象：{ 开头。
// JSON 数组：[ 后须紧跟 {/"/'['/数字/]/空白，与 git-config 的 [section] 区分开来。
func looksLikeJSON(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) == 0 {
		return false
	}
	if s[0] == '{' {
		return true
	}
	if s[0] == '[' && len(s) > 1 {
		c := s[1]
		return c == '{' || c == '"' || c == '[' || c == ']' || (c >= '0' && c <= '9') ||
			c == ' ' || c == '\t' || c == '\n'
	}
	return false
}

// looksLikeXML 检测 XML 声明（<?xml）或元素起始标签。
func looksLikeXML(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) < 2 {
		return false
	}
	if strings.HasPrefix(s, "<?xml") || strings.HasPrefix(s, "<?XML") {
		return true
	}
	// 元素起始标签 <Letter，排除 <!-- 注释 和 <!DOCTYPE
	return s[0] == '<' && len(s) > 1 && (s[1] >= 'A' && s[1] <= 'Z' || s[1] >= 'a' && s[1] <= 'z')
}

// looksLikeTOML 检测 TOML key = "value" 格式（[section] 已由 git-config 分支覆盖）。
// 原先用 strings.Contains(s, " = ") 过于宽泛（Base64、HTML 属性、SQL 等均含此模式），
// 改为要求第一行形如 identifier = ... 且标识符只含合法 TOML 字符。
func looksLikeTOML(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) < 3 {
		return false
	}
	firstLine := s
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		firstLine = s[:idx]
	}
	idx := strings.Index(firstLine, " = ")
	if idx <= 0 {
		return false
	}
	key := strings.TrimSpace(firstLine[:idx])
	if len(key) == 0 || len(key) > 64 {
		return false
	}
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
