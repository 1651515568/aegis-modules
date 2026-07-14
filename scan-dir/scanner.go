package scandir

// scanner.go —— 目录/文件爆破核心引擎。
//
// 流程(每个目标独立):规范化目标为基 URL → 建词条(预设/自定义 × 扩展名展开)→
// 先打软 404(wildcard)基线 → 并发逐路径 HTTP 探测,按状态码过滤 + 软 404 抑制 →
// 命中入库;目录型命中按 BFS 递归到下一层(受深度与基数上限约束)。
//
// 安全约束:全局限速 + 429/503 退避(limiter.go)、并发上限、词条/递归基数硬上限、
// 响应体读取上限。尊重 ctx 取消,可随时停止;绝不向 AEGIS 之外回连/上报。

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"redops/core"
)

// 安全上限(防资源耗尽 / 递归爆炸)。
const (
	maxWordsPerScan = 260000      // 单次扫描展开后的词条上限(容纳 directory-list-2.3-medium 等超大字典)
	maxBasesPerScan = 200         // 单次扫描(含递归)处理的基目录上限
	maxBodyRead     = 512 * 1024  // 单响应最多读取字节数(用于长度/词/行统计与软 404 比对)
	lenTolerance    = 48          // 软 404 长度容差(字节):与基线长度相差不超过此值视为同质页面
	defaultUA       = "AEGIS-DirScan/0.1 (+authorized-assessment)"
)

// scanOptions 是一次扫描的全部参数。json tag 与前端 ParamSpec.Name 一致。
type scanOptions struct {
	Targets        []string `json:"targets"`
	Name           string   `json:"name"`
	Scene          string   `json:"scene"`          // 场景预设:自动填充 Wordlist+Extensions;用户手动设置的 Wordlist 优先
	Wordlist       string   `json:"wordlist"`       // 主字典 id(关键字 FUZZ);custom 用 customWords
	CustomWords    []string `json:"customWords"`    // wordlist=custom 时的词条(多行)
	Wordlist2      string   `json:"wordlist2"`      // 第二字典 id(关键字 FUZ2Z);空=不启用多关键字
	CustomWords2   []string `json:"customWords2"`   // wordlist2=custom 时的词条
	FuzzMode       string   `json:"fuzzMode"`       // ffuf:clusterbomb(笛卡尔积)| pitchfork(按下标并行)
	Extensions     string   `json:"extensions"`     // 逗号分隔,如 "php,bak,txt"
	Concurrency    int      `json:"concurrency"`    // 并发数
	Rate           int      `json:"rate"`           // 全局限速 req/s,0=不限
	Timeout        int      `json:"timeout"`        // 单请求超时 ms
	StatusInclude  string   `json:"statusInclude"`  // 仅保留这些状态码(逗号分隔);空=保留除排除外的全部
	StatusExclude  string   `json:"statusExclude"`  // 排除这些状态码;默认 "404"
	FilterLength   string   `json:"filterLength"`   // ffuf -fs:过滤掉这些响应体字节数(逗号分隔)
	FilterWords    string   `json:"filterWords"`    // ffuf -fw:过滤掉这些词数
	FilterLines    string   `json:"filterLines"`    // ffuf -fl:过滤掉这些行数
	FilterRegex    string   `json:"filterRegex"`    // ffuf -fr / dirsearch --exclude-texts:正文匹配则剔除
	MatchRegex     string   `json:"matchRegex"`     // ffuf -mr:仅保留正文匹配者
	MinLength      int64    `json:"minLength"`      // dirsearch --minimal:响应体小于此值剔除(0=不限)
	MaxLength      int64    `json:"maxLength"`      // dirsearch --maximal:响应体大于此值剔除(0=不限)
	FollowRedirect bool     `json:"followRedirect"` // 是否跟随 30x
	Recursion      int      `json:"recursion"`      // 递归深度,0=关闭
	Crawl          bool     `json:"crawl"`          // feroxbuster --extract-links / dirsearch --crawl:从响应抽取链接再探
	CollectBackups bool     `json:"collectBackups"` // feroxbuster --collect-backups:命中文件时自动探备份/源码泄露变体
	Method         string   `json:"method"`         // 任意 HTTP 方法,默认 GET(HEAD 不读响应体)
	RequestBody    string   `json:"requestBody"`    // ffuf -d:请求体(非 GET/HEAD 时发送;FUZZ 模式下可含 FUZZ)
	Proxy          string   `json:"proxy"`          // ffuf -x / dirsearch --proxy:上游代理 http(s)://… 或 socks5://…
	UserAgent      string   `json:"userAgent"`
	RandomAgent    bool     `json:"randomAgent"`    // dirsearch random-agent:每请求随机 UA
	Prefixes       string   `json:"prefixes"`       // dirsearch --prefixes:为每词条加前缀(逗号分隔)
	Suffixes       string   `json:"suffixes"`       // dirsearch --suffixes:为每词条加后缀(逗号分隔)
	Headers        []string `json:"headers"`        // 附加请求头,每行 "Key: Value"
}

type scanner struct {
	log   core.Logger
	store *store
}

func newScanner(log core.Logger, st *store) *scanner { return &scanner{log: log, store: st} }

// baseNode 是 BFS 队列里的一个基目录(URL + 递归深度)。
type baseNode struct {
	url   string
	depth int
}

// probeResult 是单次 HTTP 探测的归一结果。
type probeResult struct {
	status   int
	length   int64
	words    int
	lines    int
	redirect string
	ctype    string
	body     []byte // 响应体快照(受 maxBodyRead 限),供正则过滤与链接抽取;不入库,用后即弃
}

// baseline 是某个基目录的软 404(wildcard)基线:对随机不存在路径的典型响应。
type baseline struct {
	active bool   // 该基目录是否表现出 wildcard(对随机路径也回 found-like 状态)
	status int    // wildcard 响应状态码
	length int64  // wildcard 响应体长度(静态软 404 同质判定)
	sample []byte // wildcard 响应体头部样本(动态软 404 相似度判定;HEAD 时为空)
}

// respFilters 收束响应过滤规则:状态码白/黑名单 + ffuf 风格 size/words/lines/regex 过滤 + 长度区间。
type respFilters struct {
	include, exclude map[int]struct{}
	length           map[int64]struct{}
	words, lines     map[int]struct{}
	filterRe         *regexp.Regexp // ffuf -fr:正文匹配则剔除
	matchRe          *regexp.Regexp // ffuf -mr:仅保留正文匹配者
	minLen, maxLen   int64          // dirsearch --minimal/--maximal:长度区间(0=不限)
}

// busterArgs 收束 bustJobs 的参数,避免过长签名。
type busterArgs struct {
	method     string
	ua         string // 固定 UA;randomAgent 为真时按请求随机覆盖
	randomUA   bool
	headers    map[string]string
	filters    respFilters
	conc       int
	base       baseline
	crawl      bool
	backups    bool
}

// job 是一次待探测的请求:目标 URL + 关联词条 + 展示路径(+ FUZZ 模式下的请求体/请求头覆盖)。
type job struct {
	url, word, path string
	body            string            // 该请求的请求体(FUZZ 已替换);空=按 busterArgs 默认
	headers         map[string]string // 该请求的请求头(FUZZ 已替换);nil=用 busterArgs.headers
}

// reqSpec 描述一次具体 HTTP 请求,收束 probe/doRequest 的参数。
type reqSpec struct {
	url, method, ua, body string
	headers               map[string]string
}

// run 执行一次完整扫描(阻塞至结束/取消),进度与命中写入 store。
func (sc *scanner) run(ctx context.Context, opt scanOptions) { sc.runResumable(ctx, opt, false) }

// runResumable 执行扫描;resume=true 时从 store 中断点续扫(恢复待扫基目录队列与已完成集合)。
func (sc *scanner) runResumable(ctx context.Context, opt scanOptions, resume bool) {
	var runErr string
	defer func() { sc.store.finishScan(runErr); sc.store.persist() }()

	// --- 1. 组装词条 ---
	var templates []string
	if strings.EqualFold(opt.Wordlist, "custom") {
		templates = parseWordlist(strings.Join(opt.CustomWords, "\n"))
	} else {
		id := opt.Wordlist
		if id == "" {
			id = "combined"
		}
		tpl, ok := loadTemplates(id)
		if !ok {
			runErr = "未知字典: " + id
			return
		}
		templates = tpl
	}
	words := expandTemplates(templates, parseExtensions(opt.Extensions))
	// 前缀/后缀变体(dirsearch --prefixes/--suffixes)。
	words = applyAffixes(words, parseAffix(opt.Prefixes), parseAffix(opt.Suffixes))
	if len(words) == 0 {
		runErr = "词条为空(请选择字典或填写自定义词条;若字典含 %EXT% 占位符,需提供扩展名)"
		return
	}
	if len(words) > maxWordsPerScan {
		sc.log.Warn("scan-dir wordlist truncated", "from", len(words), "to", maxWordsPerScan)
		words = words[:maxWordsPerScan]
	}

	// --- 2. 过滤器、限速器、HTTP 客户端 ---
	exclude := parseCodeSet(opt.StatusExclude)
	if len(exclude) == 0 && opt.StatusExclude == "" {
		exclude = map[int]struct{}{404: {}} // 默认排除 404
	}
	filters := respFilters{
		include: parseCodeSet(opt.StatusInclude),
		exclude: exclude,
		length:  parseInt64Set(opt.FilterLength),
		words:   parseIntSet(opt.FilterWords),
		lines:   parseIntSet(opt.FilterLines),
		minLen:  opt.MinLength,
		maxLen:  opt.MaxLength,
	}
	if opt.FilterRegex != "" {
		re, err := regexp.Compile(opt.FilterRegex)
		if err != nil {
			runErr = "filterRegex 无效: " + err.Error()
			return
		}
		filters.filterRe = re
	}
	if opt.MatchRegex != "" {
		re, err := regexp.Compile(opt.MatchRegex)
		if err != nil {
			runErr = "matchRegex 无效: " + err.Error()
			return
		}
		filters.matchRe = re
	}

	rate := opt.Rate
	if rate < 0 {
		rate = 0
	}
	sc.store.setRate(rate)
	lim := newLimiter(float64(rate))

	conc := opt.Concurrency
	if conc < 1 {
		conc = 20
	}
	if conc > 256 {
		conc = 256
	}
	// 上游代理校验(对标 ffuf -x / dirsearch --proxy):支持 http(s)://… 与 socks5://…
	if opt.Proxy != "" {
		pu, err := url.Parse(opt.Proxy)
		if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https" && pu.Scheme != "socks5") {
			runErr = "proxy 无效(需 http(s):// 或 socks5://): " + opt.Proxy
			return
		}
	}
	client := buildClient(opt)
	method := strings.ToUpper(strings.TrimSpace(opt.Method))
	if method == "" {
		method = http.MethodGet
	}
	// HEAD 模式下 body 为空，-fw/-fl 过滤器永远匹配到 0，实际不生效；自动切换 GET 修正。
	if method == http.MethodHead && (opt.FilterWords != "" || opt.FilterLines != "") {
		method = http.MethodGet
		sc.log.Info("scan-dir auto-switched HEAD→GET: filterWords/filterLines require response body")
		sc.store.setPhase("注意: HEAD 已自动切换为 GET（-fw/-fl 需读响应体）")
	}
	headers := parseHeaders(opt.Headers)
	ua := opt.UserAgent
	if strings.TrimSpace(ua) == "" {
		ua = defaultUA
	}
	a := busterArgs{
		method: method, ua: ua, randomUA: opt.RandomAgent, headers: headers,
		filters: filters, conc: conc, crawl: opt.Crawl, backups: opt.CollectBackups,
	}

	// 第二字典(关键字 FUZ2Z;ffuf 多关键字)。仅 FUZZ 模式生效。
	var words2 []string
	if id := strings.TrimSpace(opt.Wordlist2); id != "" && !strings.EqualFold(id, "none") {
		if strings.EqualFold(id, "custom") {
			words2 = parseWordlist(strings.Join(opt.CustomWords2, "\n"))
		} else if tpl, ok := loadTemplates(id); ok {
			words2 = tpl
		} else {
			runErr = "未知第二字典: " + id
			return
		}
		words2 = expandTemplates(words2, nil) // 第二字典通常为值,不做扩展名展开
	}

	// --- 3. 目标分流 / 续扫队列恢复 ---
	var queue []baseNode
	visited := map[string]struct{}{}
	completed := map[string]struct{}{}
	crawlSeen := map[string]struct{}{}

	if resume {
		q, comp, ok := sc.store.resumeState()
		if !ok {
			runErr = "无可续扫的任务"
			return
		}
		queue, completed = q, comp
		for _, n := range queue {
			visited[n.url] = struct{}{}
		}
		for c := range completed {
			visited[c] = struct{}{}
		}
		sc.log.Info("scan-dir resuming", "pending", len(queue), "completed", len(completed))
	} else {
		// FUZZ 目标(扁平、不进 BFS 队列、不参与续扫);其余作为基目录入全局队列。
		bodyHasFuzz := strings.Contains(opt.RequestBody, "FUZZ")
		headersHaveFuzz := mapHasFuzz(headers)
		for _, raw := range opt.Targets {
			if ctx.Err() != nil {
				runErr = "已取消"
				return
			}
			if strings.Contains(raw, "FUZZ") || bodyHasFuzz || headersHaveFuzz {
				if strings.Contains(raw, "FUZZ") && !validFuzzTarget(raw) {
					sc.log.Warn("scan-dir skip invalid FUZZ target", "target", raw)
					continue
				}
				sc.store.setTarget(raw)
				sc.store.setPhase("FUZZ 探测")
				rawT := raw
				// 单关键字:逐词替换 FUZZ。多关键字(配置了第二字典):按 clusterbomb/pitchfork
				// 组合 FUZZ×FUZ2Z(combo 以 NUL 编码两值,mk 内拆分),对标 ffuf 多 -w 模式。
				mk := func(w string) job {
					w1, w2, multi := splitCombo(w)
					rep := func(s string) string {
						s = strings.ReplaceAll(s, "FUZZ", w1)
						if multi {
							s = strings.ReplaceAll(s, "FUZ2Z", w2)
						}
						return s
					}
					jb := job{url: rep(rawT), word: w1, path: comboLabel(w1, w2, multi), body: opt.RequestBody}
					if bodyHasFuzz {
						jb.body = rep(opt.RequestBody)
					}
					if headersHaveFuzz {
						jb.headers = replaceFuzzMulti(headers, w1, w2, multi)
					}
					return jb
				}
				items := words
				if len(words2) > 0 {
					items = combineWords(words, words2, opt.FuzzMode)
				}
				sc.bustWords(ctx, client, lim, items, mk, 0, a)
				continue
			}
			base, ok := normalizeTarget(raw)
			if !ok {
				sc.log.Warn("scan-dir skip invalid target", "target", raw)
				continue
			}
			if _, seen := visited[base]; seen {
				continue
			}
			visited[base] = struct{}{}
			queue = append(queue, baseNode{url: base, depth: 0})
		}
		sc.store.setPending(snapshotQueue(queue)) // 首检查点:覆盖第一基目录的崩溃/取消
	}

	// --- 4. 全局 BFS 爆破(每基目录完成即检查点落盘,支持断点续扫) ---
	basesDone := 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			runErr = "已取消"
			break
		}
		if basesDone >= maxBasesPerScan {
			sc.log.Warn("scan-dir base limit reached", "limit", maxBasesPerScan)
			break
		}
		cur := queue[0]
		queue = queue[1:]
		basesDone++
		if _, done := completed[cur.url]; done {
			continue // 续扫安全:已完成的基目录跳过
		}

		sc.store.setTarget(cur.url)
		sc.store.setPhase("基线探测")
		bl := sc.calibrate(ctx, client, lim, cur.url, a)
		sc.store.setPhase("爆破中")

		ja := a
		ja.base = bl
		curURL, curDepth := cur.url, cur.depth
		dirHits, crawlURLs := sc.bustWords(ctx, client, lim, words, func(w string) job {
			return job{url: joinURL(curURL, w), word: w, path: pathOf(curDepth, w, curURL), body: opt.RequestBody}
		}, cur.depth, ja)

		// 递归:目录型命中加入下一层(去重、限深、限基数)。
		if opt.Recursion > 0 && cur.depth < opt.Recursion {
			for _, h := range dirHits {
				nb := ensureSlash(h)
				if _, seen := visited[nb]; seen {
					continue
				}
				visited[nb] = struct{}{}
				queue = append(queue, baseNode{url: nb, depth: cur.depth + 1})
			}
		}

		// 扩展发现:把抽链/备份衍生的同主机新 URL 直接探测一遍(扁平,不再衍生,防放大)。
		if (a.crawl || a.backups) && len(crawlURLs) > 0 {
			extra := make([]string, 0, len(crawlURLs))
			for _, u := range crawlURLs {
				if _, seen := crawlSeen[u]; seen {
					continue
				}
				crawlSeen[u] = struct{}{}
				extra = append(extra, u)
			}
			if len(extra) > 0 {
				sc.store.setPhase("扩展发现")
				na := a
				na.crawl = false   // 不对衍生结果再抽链
				na.backups = false // 不对备份再衍生备份,避免无界放大
				na.base = bl
				sc.bustWords(ctx, client, lim, extra, func(u string) job {
					return job{url: u, word: lastSeg(u), path: urlPath(u)}
				}, cur.depth, na)
			}
		}

		if ctx.Err() != nil { // 本基目录被中途取消:不标记完成,留待续扫
			runErr = "已取消"
			break
		}
		completed[cur.url] = struct{}{}
		sc.store.markBaseDone(cur.url, snapshotQueue(queue)) // 检查点:落盘剩余队列
	}

	if ctx.Err() != nil {
		runErr = "已取消"
	}
}

// snapshotQueue 把 BFS 队列转为可序列化快照(断点续扫检查点用)。
func snapshotQueue(q []baseNode) []PendingBase {
	out := make([]PendingBase, len(q))
	for i, n := range q {
		out[i] = PendingBase{URL: n.url, Depth: n.depth}
	}
	return out
}

// bustWords 并发执行一批请求(由 items 经 mk 流式构造 job,不预先物化大 job 切片,
// 以容纳超大字典);记录命中,返回(目录型命中 URL 列表,抽链/备份衍生的同主机 URL 列表)。
func (sc *scanner) bustWords(ctx context.Context, client *http.Client, lim *limiter,
	items []string, mk func(string) job, depth int, a busterArgs) ([]string, []string) {

	sc.store.addTotal(len(items))

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, a.conc)
		mu        sync.Mutex
		dirHits   []string
		crawlURLs []string
	)

	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		jb := mk(it)
		wg.Add(1)
		sem <- struct{}{}
		go func(jb job) {
			defer wg.Done()
			defer func() { <-sem }()

			hdrs := jb.headers
			if hdrs == nil {
				hdrs = a.headers
			}
			res, err := sc.probe(ctx, client, lim, reqSpec{
				url: jb.url, method: a.method, ua: pickUA(a), headers: hdrs, body: jb.body,
			})
			sc.store.incProbed()
			if err != nil {
				return
			}
			// 抽链对「可抓取」响应进行(即便最终被过滤掉也可能含有价值链接)。
			var links []string
			if a.crawl && isCrawlable(res) {
				links = extractLinks(jb.url, res.body)
			}
			if !sc.interesting(res, a.filters, a.base) {
				sc.store.incFiltered()
				if len(links) > 0 {
					mu.Lock()
					crawlURLs = append(crawlURLs, links...)
					mu.Unlock()
				}
				return
			}
			isDir := looksLikeDir(jb.word, res)
			sev, kind := classify(jb.path)
			isNew := sc.store.addHit(Hit{
				URL: jb.url, Path: jb.path, Status: res.status,
				Length: res.length, Words: res.words, Lines: res.lines,
				Redirect: res.redirect, ContentType: res.ctype, Depth: depth, IsDir: isDir,
				Severity: sev, Kind: kind,
			})
			if !isNew {
				return // 重复命中(递归/抽链/续扫):不重复衍生,防环
			}
			// 命中文件(非目录、2xx、含扩展名)时衍生备份/源码泄露变体(feroxbuster --collect-backups)。
			var backs []string
			if a.backups && !isDir && res.status >= 200 && res.status < 300 && strings.Contains(jb.word, ".") {
				backs = generateBackups(jb.url)
			}
			if isDir || len(links) > 0 || len(backs) > 0 {
				mu.Lock()
				if isDir {
					dirHits = append(dirHits, jb.url)
				}
				crawlURLs = append(crawlURLs, links...)
				crawlURLs = append(crawlURLs, backs...)
				mu.Unlock()
			}
		}(jb)
	}
	wg.Wait()
	return dirHits, crawlURLs
}

// calibrate 对基目录打 4 个随机不存在路径,推断 wildcard(软 404)基线。
// 需要至少 3/4 的探测返回"存在类"状态且状态码一致才激活 wildcard 抑制，
// 避免单次偶发命中或网络抖动导致误触发 wildcard 从而大量漏报。
func (sc *scanner) calibrate(ctx context.Context, client *http.Client, lim *limiter,
	base string, a busterArgs) baseline {
	// 使用 crypto/rand 生成每个探测路径的随机后缀，防止同一纳秒内四次时钟读取
	// 返回相同值，导致四个探测路径实际相同，误激活 wildcard 抑制而大量漏报。
	probes := make([]string, 4)
	suffixes := [4]string{"", ".html", ".php", ""}
	for i := range probes {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		probes[i] = fmt.Sprintf("aegis_probe%d_%s%s", i, hex.EncodeToString(b), suffixes[i])
	}
	var first probeResult
	foundCount := 0
	for _, p := range probes {
		if ctx.Err() != nil {
			return baseline{}
		}
		res, err := sc.probe(ctx, client, lim, reqSpec{url: joinURL(base, p), method: a.method, ua: pickUA(a), headers: a.headers})
		if err != nil {
			continue
		}
		if !isFoundLike(res.status) {
			continue
		}
		if foundCount == 0 {
			first = res
		} else if res.status != first.status {
			// 不同探测返回不同状态码，行为不一致，不能确认 wildcard
			continue
		}
		foundCount++
	}
	// 至少 3 次探测都返回相同的"存在类"状态码才确认 wildcard，防止偶发误触发
	if foundCount >= 3 {
		sample := headSample(first.body)
		// HEAD 模式下探测无响应体：额外发一次 GET 获取 soft-404 模板，启用相似度过滤
		if len(sample) == 0 && ctx.Err() == nil {
			getSamp := "aegis_smpl_" + strconv.FormatInt(time.Now().UnixNano()+12347, 36)
			if gr, gerr := sc.probe(ctx, client, lim, reqSpec{
				url: joinURL(base, getSamp), method: http.MethodGet,
				ua: pickUA(a), headers: a.headers,
			}); gerr == nil {
				sample = headSample(gr.body)
			}
		}
		return baseline{active: true, status: first.status, length: first.length, sample: sample}
	}
	return baseline{}
}

// probe 发起单次 HTTP 探测,含 429/503 退避与瞬时网络错误重试。
func (sc *scanner) probe(ctx context.Context, client *http.Client, lim *limiter, rs reqSpec) (probeResult, error) {
	var netAttempt int
	for {
		if err := lim.wait(ctx); err != nil {
			return probeResult{}, err
		}
		res, status, retryAfter, err := sc.doRequest(ctx, client, rs)
		if err != nil {
			if ctx.Err() != nil {
				return probeResult{}, ctx.Err()
			}
			if netAttempt < maxNetRetries && isTemporary(err) {
				d := netRetryDelay(netAttempt)
				netAttempt++
				if !sleepCtx(ctx, d) {
					return probeResult{}, ctx.Err()
				}
				continue
			}
			return probeResult{}, err
		}
		// 限流:退避后重试(最多 maxRetries 次)。
		for attempt := 0; attempt < maxRetries && isThrottle(status); attempt++ {
			d := retryAfterDelay(retryAfter, attempt)
			lim.penalize(clampCap(d, globalPenaltyCap))
			if !sleepCtx(ctx, d) {
				return probeResult{}, ctx.Err()
			}
			if err := lim.wait(ctx); err != nil {
				return probeResult{}, err
			}
			res, status, retryAfter, err = sc.doRequest(ctx, client, rs)
			if err != nil {
				break // 退出内层 429 重试循环，由下方 err != nil 判断交还外层循环处理
			}
		}
		if err != nil {
			// 429 退避重试中遇到网络错误，交由外层循环的 isTemporary 路径决策是否重试；
			// 不能 return nil error，否则 status=0 的零值结果会被当作有效命中写库。
			continue
		}
		return res, nil
	}
}

// doRequest 执行一次请求并归一为 probeResult。返回 (结果, 状态码, Retry-After, error)。
func (sc *scanner) doRequest(ctx context.Context, client *http.Client, rs reqSpec) (probeResult, int, string, error) {
	var bodyReader io.Reader
	if rs.body != "" {
		bodyReader = strings.NewReader(rs.body)
	}
	req, err := http.NewRequestWithContext(ctx, rs.method, rs.url, bodyReader)
	if err != nil {
		return probeResult{}, 0, "", err
	}
	req.Header.Set("User-Agent", rs.ua)
	req.Header.Set("Accept", "*/*")
	if rs.body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // 可被 headers 覆盖
	}
	for k, v := range rs.headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{}, 0, "", err
	}
	defer resp.Body.Close()

	res := probeResult{
		status:   resp.StatusCode,
		redirect: resp.Header.Get("Location"),
		ctype:    resp.Header.Get("Content-Type"),
	}
	var body []byte
	if rs.method != http.MethodHead {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, e := strconv.ParseInt(cl, 10, 64); e == nil {
			res.length = n
		}
	}
	if res.length == 0 {
		res.length = int64(len(body))
	}
	res.words = countWords(body)
	res.lines = countLines(body)
	res.body = body // 供正则过滤/抽链;随 probeResult 在请求处理后即弃,不入库
	return res, resp.StatusCode, resp.Header.Get("Retry-After"), nil
}

// interesting 判定一条响应是否应作为命中(状态过滤 + ffuf 风格 size/words/lines 过滤 + 软 404 抑制)。
func (sc *scanner) interesting(res probeResult, f respFilters, bl baseline) bool {
	if _, ex := f.exclude[res.status]; ex {
		return false
	}
	if len(f.include) > 0 {
		if _, in := f.include[res.status]; !in {
			return false
		}
	}
	if _, ok := f.length[res.length]; ok {
		return false // ffuf -fs
	}
	if _, ok := f.words[res.words]; ok {
		return false // ffuf -fw
	}
	if _, ok := f.lines[res.lines]; ok {
		return false // ffuf -fl
	}
	if f.minLen > 0 && res.length < f.minLen {
		return false // dirsearch --minimal
	}
	if f.maxLen > 0 && res.length > f.maxLen {
		return false // dirsearch --maximal
	}
	if f.filterRe != nil && f.filterRe.Match(res.body) {
		return false // ffuf -fr / dirsearch --exclude-texts
	}
	if f.matchRe != nil && !f.matchRe.Match(res.body) {
		return false // ffuf -mr:不匹配则丢弃
	}
	if bl.active && res.status == bl.status {
		if len(bl.sample) > 0 && len(res.body) > 0 {
			// 有响应体：仅靠内容相似度判定，避免「长度近似却是真实文件」的漏报。
			// simThreshold=0.92 确保只有与模板高度相同的页面才被过滤。
			if similarity(headSample(res.body), bl.sample) >= simThreshold {
				return false
			}
		} else {
			// 无响应体（HEAD 模式）：退回长度启发，误差容限 ±lenTolerance 字节。
			if absInt64(res.length-bl.length) <= lenTolerance {
				return false
			}
		}
	}
	return true
}

// ---- HTTP 客户端与辅助 ----

func buildClient(opt scanOptions) *http.Client {
	to := time.Duration(opt.Timeout) * time.Millisecond
	if to <= 0 {
		to = 8 * time.Second
	}
	proxyFn := http.ProxyFromEnvironment
	if opt.Proxy != "" {
		if pu, err := url.Parse(opt.Proxy); err == nil && pu.Host != "" {
			proxyFn = http.ProxyURL(pu) // http(s)/socks5 均由 Transport 原生支持
		}
	}
	tr := &http.Transport{
		Proxy:                 proxyFn,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // 评估场景:容忍自签/过期证书
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   to,
		ExpectContinueTimeout: time.Second,
		DialContext:           (&net.Dialer{Timeout: to, KeepAlive: 30 * time.Second}).DialContext,
	}
	c := &http.Client{Timeout: to, Transport: tr}
	if !opt.FollowRedirect {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// parseCodeSet 解析逗号分隔的状态码集合(支持 "200,301-302" 区间)。空输入返回空集。
func parseCodeSet(s string) map[int]struct{} {
	out := make(map[int]struct{})
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if i := strings.IndexByte(f, '-'); i > 0 {
			lo, e1 := strconv.Atoi(strings.TrimSpace(f[:i]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(f[i+1:]))
			if e1 == nil && e2 == nil && lo <= hi {
				for c := lo; c <= hi; c++ {
					out[c] = struct{}{}
				}
			}
			continue
		}
		if c, e := strconv.Atoi(f); e == nil {
			out[c] = struct{}{}
		}
	}
	return out
}

// parseIntSet 解析逗号/空白分隔的整数集合(用于 words/lines 过滤)。空输入返回空集。
func parseIntSet(s string) map[int]struct{} {
	out := make(map[int]struct{})
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if n, e := strconv.Atoi(strings.TrimSpace(f)); e == nil {
			out[n] = struct{}{}
		}
	}
	return out
}

// parseInt64Set 解析逗号/空白分隔的 int64 集合(用于响应体长度过滤)。空输入返回空集。
func parseInt64Set(s string) map[int64]struct{} {
	out := make(map[int64]struct{})
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if n, e := strconv.ParseInt(strings.TrimSpace(f), 10, 64); e == nil {
			out[n] = struct{}{}
		}
	}
	return out
}

// parseAffix 解析逗号分隔的前缀/后缀列表。
func parseAffix(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, f := range strings.Split(s, ",") {
		v := strings.TrimSpace(f)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// applyAffixes 为每个词条追加前缀/后缀变体(dirsearch --prefixes/--suffixes)。保留原词条。
func applyAffixes(words, prefixes, suffixes []string) []string {
	if len(prefixes) == 0 && len(suffixes) == 0 {
		return words
	}
	out := make([]string, 0, len(words)*(1+len(prefixes)+len(suffixes)))
	seen := make(map[string]struct{})
	add := func(w string) {
		if w == "" {
			return
		}
		if _, ok := seen[w]; ok {
			return
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	for _, w := range words {
		add(w)
		for _, p := range prefixes {
			add(p + w)
		}
		for _, s := range suffixes {
			add(w + s)
		}
	}
	return out
}

// uaPool 是 randomAgent 的 UA 备选池（多平台/多版本，降低被 UA 指纹封锁的概率）。
var uaPool = []string{
	// Chrome — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	// Chrome — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	// Chrome — Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Firefox — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
	// Firefox — macOS / Linux
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Safari — macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	// Edge — Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	// Chrome — Android
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
	// Safari — iPhone
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
	// Opera
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
	// Googlebot / crawler-like（部分站点对爬虫友好）
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	// curl-like（适合 API 端点）
	"curl/8.5.0",
}

var uaSeq uint32

// pickUA 在 randomAgent 模式下轮转 UA 池(避免引入随机源,用原子序号轮转即可),否则返回固定 UA。
func pickUA(a busterArgs) string {
	if !a.randomUA {
		return a.ua
	}
	n := atomic.AddUint32(&uaSeq, 1)
	return uaPool[int(n)%len(uaPool)]
}

// validFuzzTarget 校验 FUZZ 目标:替换占位符后须为合法 http(s) URL。
func validFuzzTarget(raw string) bool {
	probe := strings.ReplaceAll(raw, "FUZZ", "aegisfuzz")
	u, err := url.Parse(probe)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// urlPath 取 URL 的 path(用于抽链命中的展示路径);解析失败回退原串。
func urlPath(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	return raw
}

// lastSeg 取 URL 路径末段(用于把衍生 URL 的「词」还原,使 looksLikeDir 能据扩展名判文件)。
func lastSeg(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return path.Base(u.Path)
	}
	return raw
}

// backupSuffixes 是命中文件后衍生的备份/源码泄露后缀(feroxbuster --collect-backups 同款思路)。
var backupSuffixes = []string{".bak", "~", ".old", ".save", ".orig", ".swp", ".tmp", ".1", ".zip", ".tar.gz", ".rar"}

// generateBackups 为一个命中的文件 URL 生成备份/编辑器遗留变体候选 URL(含 vim .swp)。
func generateBackups(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	seg := path.Base(u.Path)
	if seg == "" || seg == "/" || seg == "." {
		return nil
	}
	out := make([]string, 0, len(backupSuffixes)+1)
	for _, s := range backupSuffixes {
		out = append(out, raw+s)
	}
	// vim 交换文件:同目录下 .<name>.swp
	if i := len(raw) - len(seg); i >= 0 {
		out = append(out, raw[:i]+"."+seg+".swp")
	}
	return out
}

// comboSep 是多关键字组合的内部分隔符(NUL,正常词条不含)。
const comboSep = "\x00"

// combineWords 把两份字典按 ffuf 模式组合:
//   - clusterbomb(默认):笛卡尔积 N×M;
//   - pitchfork:按下标并行 zip,取较短长度。
// 结果每项为 "w1<NUL>w2",受 maxWordsPerScan 上限保护。
func combineWords(w1s, w2s []string, mode string) []string {
	if strings.EqualFold(mode, "pitchfork") {
		n := len(w1s)
		if len(w2s) < n {
			n = len(w2s)
		}
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, w1s[i]+comboSep+w2s[i])
		}
		return out
	}
	// clusterbomb
	out := make([]string, 0, min(len(w1s)*len(w2s), maxWordsPerScan))
	for _, a := range w1s {
		for _, b := range w2s {
			out = append(out, a+comboSep+b)
			if len(out) >= maxWordsPerScan {
				return out
			}
		}
	}
	return out
}

// splitCombo 拆分 combineWords 编码的组合项;无分隔符时为单关键字(multi=false)。
func splitCombo(s string) (w1, w2 string, multi bool) {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// comboLabel 给出命中展示用的词标签。
func comboLabel(w1, w2 string, multi bool) string {
	if multi {
		return w1 + " | " + w2
	}
	return w1
}

// replaceFuzzMulti 在请求头里替换 FUZZ(及多关键字下的 FUZ2Z)。
func replaceFuzzMulti(h map[string]string, w1, w2 string, multi bool) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		nk := strings.ReplaceAll(k, "FUZZ", w1)
		nv := strings.ReplaceAll(v, "FUZZ", w1)
		if multi {
			nk = strings.ReplaceAll(nk, "FUZ2Z", w2)
			nv = strings.ReplaceAll(nv, "FUZ2Z", w2)
		}
		out[nk] = nv
	}
	return out
}

// mapHasFuzz 判断请求头里是否存在 FUZZ 关键字(键或值)。
func mapHasFuzz(h map[string]string) bool {
	for k, v := range h {
		if strings.Contains(k, "FUZZ") || strings.Contains(v, "FUZZ") {
			return true
		}
	}
	return false
}

// replaceFuzzHeaders 用词 w 替换请求头键/值里的 FUZZ,返回新 map(不改原 map)。
func replaceFuzzHeaders(h map[string]string, w string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ReplaceAll(k, "FUZZ", w)] = strings.ReplaceAll(v, "FUZZ", w)
	}
	return out
}

// parseHeaders 解析多行 "Key: Value" 附加请求头。
func parseHeaders(lines []string) map[string]string {
	out := make(map[string]string)
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		i := strings.IndexByte(ln, ':')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(ln[:i])
		v := strings.TrimSpace(ln[i+1:])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// isFoundLike 判定状态码是否「存在类」(非 404/400 客户端否定区间)。用于 wildcard 推断。
// 5xx 服务器错误不视为路径存在——部分站点对所有不存在路径回 500，
// 若将 5xx 纳入 wildcard 基线，会把真实命中（如返回 500 的 PHP 配置文件）全部误抑制。
func isFoundLike(code int) bool {
	if code == 404 || code == 400 || code == 0 {
		return false
	}
	if code >= 500 {
		return false
	}
	return code >= 200 && code < 500
}

// looksLikeDir 判定一条命中是否为可递归的目录。
func looksLikeDir(word string, res probeResult) bool {
	// 3xx 跳到尾斜杠 → 确认是目录（最可靠的判定）。
	if res.status >= 300 && res.status < 400 && res.redirect != "" {
		if strings.HasSuffix(strings.TrimRight(res.redirect, "?#"), "/") {
			return true
		}
	}
	if res.status == 200 {
		// 无扩展名词条（如 admin、api）→ 推断为目录。
		if !strings.Contains(word, ".") {
			return true
		}
		// 修正：旧逻辑把以点开头的词（.git/.svn/.hg/.htaccess 等）一律排除。
		// 以点开头的词条多为 VCS 目录或配置文件，应纳入目录探测。
		if strings.HasPrefix(word, ".") {
			return true
		}
	}
	return false
}

func ensureSlash(u string) string {
	if strings.HasSuffix(u, "/") {
		return u
	}
	return u + "/"
}

// pathOf 给出命中相对站点根的展示路径(递归层带上基目录路径前缀)。
func pathOf(depth int, word, base string) string {
	if depth == 0 {
		return "/" + strings.TrimPrefix(word, "/")
	}
	if i := strings.Index(base, "://"); i >= 0 {
		rest := base[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[j:] + strings.TrimPrefix(word, "/")
		}
	}
	return "/" + strings.TrimPrefix(word, "/")
}

func countWords(b []byte) int { return len(strings.Fields(string(b))) }

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return strings.Count(string(b), "\n") + 1
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func clampCap(d, limit time.Duration) time.Duration {
	if d > limit {
		return limit
	}
	return d
}

// sleepCtx 睡 d,期间 ctx 取消则提前返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// isTemporary 判定是否为可重试的瞬时网络错误(超时 / 连接重置 / EOF)。
func isTemporary(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	if strings.Contains(s, "connection refused") {
		return false // refused 多为稳定结果,不重试
	}
	return strings.Contains(s, "reset") || strings.Contains(s, "EOF") || strings.Contains(s, "timeout")
}
