package vulnscan

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"redops/core"
)

var nucleiBinCandidates = []string{
	"/home/sshuser/.local/bin/nuclei",
	"/usr/local/bin/nuclei",
	"/usr/bin/nuclei",
	"nuclei",
}

func findNuclei() (string, error) {
	// 优先使用内嵌二进制（保证版本一致，无需预装）
	if p, err := ensureNuclei(); err == nil {
		return p, nil
	}
	// fallback: PATH / 固定路径
	for _, p := range nucleiBinCandidates {
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "bin", "nuclei")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("nuclei 未找到，请先安装：https://github.com/projectdiscovery/nuclei/releases")
}

func templateRoots() []templateDir {
	var roots []templateDir
	home, err := os.UserHomeDir()
	if err != nil {
		return roots
	}
	candidates := []templateDir{
		{path: filepath.Join(home, "nuclei-templates"), label: "官方"},
		{path: filepath.Join(home, "custom-templates"), label: "自定义"},
		{path: filepath.Join(home, "xinchuang-templates"), label: "信创"},
	}
	for _, c := range candidates {
		if _, err := os.Stat(c.path); err == nil {
			roots = append(roots, c)
		}
	}
	return roots
}

type templateDir struct {
	path  string
	label string
}

func templateRoot() string {
	if roots := templateRoots(); len(roots) > 0 {
		return roots[0].path
	}
	return ""
}

// nucleiOutput 解析 nuclei -jsonl 输出的单行。
type nucleiOutput struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Tags     string `json:"tags"`
	} `json:"info"`
	Type      string `json:"type"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	Request   string `json:"request"`
	Response  string `json:"response"`
	IP        string `json:"ip"`
	CurlCmd   string `json:"curl-command"`
	Timestamp string `json:"timestamp"`
}

// nucleiStatsJSON nuclei v3 -stats-json 格式输出。
type nucleiStatsJSON struct {
	Duration  string  `json:"duration"`
	Percent   float64 `json:"percent"`
	RPS       float64 `json:"rps"`
	Requests  struct {
		Total     int `json:"total"`
		Completed int `json:"completed"`
	} `json:"requests"`
	RemainingDuration string `json:"remaining_duration"`
}

type scanOptions struct {
	Targets   []string `json:"targets"`
	Templates string   `json:"templates"`
	Severity  string   `json:"severity"`
	RateLimit int      `json:"rateLimit"`
	Timeout   int      `json:"timeout"`
	Tags      string   `json:"tags"`
	Insecure  bool     `json:"insecure"` // -insecure 跳过 TLS 验证
	Proxy     string   `json:"proxy"`    // socks5://host:port 或 http://host:port
	// Headers: 自定义请求头，每条格式 "Name: Value"（如 "Cookie: session=xxx"）
	Headers  []string `json:"headers,omitempty"`
	QueueID  string   `json:"queueId,omitempty"`             // 由队列自动填入，前端勿传
	ScanMode string   `json:"scanMode,omitempty"`            // "full"(默认) | "fingerprint"(先指纹再扫描)
}

// ── nuclei 版本检测 ──────────────────────────────────────────────────────────

var (
	nucleiVerOnce  sync.Once
	nucleiVerMajor int // 0 = 未知/检测失败
)

// detectNucleiMajorVersion 检测 nuclei 主版本号，结果全局缓存。
func detectNucleiMajorVersion(bin string) int {
	nucleiVerOnce.Do(func() {
		out, _ := exec.Command(bin, "-version").CombinedOutput()
		re := regexp.MustCompile(`v(\d+)\.`)
		if m := re.FindStringSubmatch(string(out)); m != nil {
			nucleiVerMajor, _ = strconv.Atoi(m[1])
		}
		if nucleiVerMajor == 0 {
			nucleiVerMajor = 2 // 安全降级到 v2 兼容模式
		}
	})
	return nucleiVerMajor
}

func newTaskID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── stderr 进度解析 ──────────────────────────────────────────────────────────

var (
	reStderrProgress  = regexp.MustCompile(`(\d+)\s*/\s*(\d+)`)
	reStderrPct       = regexp.MustCompile(`([\d]+(?:\.[\d]+)?)\s*%`)
	reStderrRPS       = regexp.MustCompile(`(\d+)\s*(?:req(?:uest)?s?/s|rps|RPS)`)
	reStderrETA       = regexp.MustCompile(`(?i)eta[:\s]+([0-9][0-9hms ]+?)(?:\s*\||\s*$|\s*\n)`)
	reStderrTargets   = regexp.MustCompile(`(?i)targets?\s+(?:loaded|count)[:\s]+(\d+)`)
)

func parseProgressLine(line string, fallbackTotal int) *ScanProgress {
	// 优先尝试 nuclei v3 -stats-json 格式（JSON行）
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		var js nucleiStatsJSON
		if json.Unmarshal([]byte(line), &js) == nil && js.Requests.Total > 0 {
			eta := strings.TrimSpace(js.RemainingDuration)
			return &ScanProgress{
				Scanned: js.Requests.Completed,
				Total:   js.Requests.Total,
				Percent: js.Percent,
				RPS:     int(js.RPS),
				ETA:     eta,
			}
		}
	}

	// 降级：文本进度行解析（nuclei v2/v3 均支持）
	m := reStderrProgress.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	scanned, _ := strconv.Atoi(m[1])
	total, _ := strconv.Atoi(m[2])
	if total == 0 {
		total = fallbackTotal
	}
	if scanned == 0 || total == 0 {
		return nil
	}
	pct := float64(scanned) / float64(total) * 100.0
	if pm := reStderrPct.FindStringSubmatch(line); pm != nil {
		if v, err := strconv.ParseFloat(pm[1], 64); err == nil && v >= 0 {
			pct = v
		}
	}
	rps := 0
	if rm := reStderrRPS.FindStringSubmatch(line); rm != nil {
		rps, _ = strconv.Atoi(rm[1])
	}
	eta := ""
	if em := reStderrETA.FindStringSubmatch(line); em != nil {
		eta = strings.TrimSpace(em[1])
	}
	return &ScanProgress{
		Scanned: scanned, Total: total, Percent: pct, RPS: rps, ETA: eta,
	}
}

type scanner struct {
	log          core.Logger
	store        *store
	engineCtx    context.Context    // 随引擎 OnDisable 取消，用于队列任务
	engineCancel context.CancelFunc // 由 Module.OnDisable 调用
}

func newScanner(log core.Logger, st *store) *scanner {
	ctx, cancel := context.WithCancel(context.Background())
	return &scanner{log: log, store: st, engineCtx: ctx, engineCancel: cancel}
}

// readStderr 在单独 goroutine 中解析 nuclei stderr 进度输出。
func (sc *scanner) readStderr(r io.Reader, targetCount int) {
	total := targetCount
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 256*1024), 256*1024)
	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r")
		// 检测 nuclei 自报的目标数量
		if m := reStderrTargets.FindStringSubmatch(line); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > 0 {
				total = n
			}
		}
		if prog := parseProgressLine(line, total); prog != nil {
			sc.store.updateProgress(*prog)
		}
		sc.log.Info("nuclei stderr", "line", line)
	}
}

// ── 模板树 ───────────────────────────────────────────────────────────────────

type TemplateTreeResp struct {
	Sources map[string]map[string][]string `json:"sources"`
	Roots   map[string]string              `json:"roots"`
	Counts  map[string]map[string]int      `json:"counts"` // source → {category → yaml文件数}
}

var (
	treeCache     *TemplateTreeResp
	treeCacheMu   sync.Mutex
	treeCacheTime time.Time
)

func countYAMLFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n += countYAMLFiles(filepath.Join(dir, e.Name()))
		} else if strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			n++
		}
	}
	return n
}

func (sc *scanner) TemplateTree() (*TemplateTreeResp, error) {
	treeCacheMu.Lock()
	if treeCache != nil && time.Since(treeCacheTime) < 10*time.Minute {
		resp := treeCache
		treeCacheMu.Unlock()
		return resp, nil
	}
	treeCacheMu.Unlock()

	roots := templateRoots()
	if len(roots) == 0 {
		return nil, fmt.Errorf("未找到任何模板目录（~/nuclei-templates 或 ~/custom-templates）")
	}
	resp := &TemplateTreeResp{
		Sources: make(map[string]map[string][]string),
		Roots:   make(map[string]string),
		Counts:  make(map[string]map[string]int),
	}
	for _, rd := range roots {
		resp.Roots[rd.label] = rd.path
		tree := make(map[string][]string)
		counts := make(map[string]int)
		entries, err := os.ReadDir(rd.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			top := e.Name()
			topPath := filepath.Join(rd.path, top)
			subs, _ := os.ReadDir(topPath)
			var subNames []string
			for _, s := range subs {
				if s.IsDir() && !strings.HasPrefix(s.Name(), ".") {
					subNames = append(subNames, s.Name())
				}
			}
			tree[top] = subNames
			counts[top] = countYAMLFiles(topPath)
		}
		resp.Sources[rd.label] = tree
		resp.Counts[rd.label] = counts
	}

	treeCacheMu.Lock()
	treeCache = resp
	treeCacheTime = time.Now()
	treeCacheMu.Unlock()
	return resp, nil
}

// ── 主扫描逻辑 ───────────────────────────────────────────────────────────────

func (sc *scanner) Run(ctx context.Context, opt scanOptions) {
	bin, err := findNuclei()
	if err != nil {
		sc.store.endScan(err.Error())
		if opt.QueueID != "" {
			sc.store.finishQueueItem(opt.QueueID, "", err.Error())
		}
		sc.tryStartNextQueued()
		return
	}

	rateLimit := opt.RateLimit
	if rateLimit <= 0 {
		rateLimit = 150
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	// 写目标文件
	tmpTargets, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		sc.store.endScan("创建临时目标文件失败: " + err.Error())
		if opt.QueueID != "" {
			sc.store.finishQueueItem(opt.QueueID, "", err.Error())
		}
		sc.tryStartNextQueued()
		return
	}
	for _, t := range opt.Targets {
		_, _ = fmt.Fprintln(tmpTargets, t)
	}
	tmpTargets.Close()
	defer os.Remove(tmpTargets.Name())

	args := []string{
		"-list", tmpTargets.Name(),
		"-jsonl",
		"-silent",
		"-no-color",
		"-rate-limit", fmt.Sprintf("%d", rateLimit),
		"-timeout", fmt.Sprintf("%d", timeout),
		"-retries", "1",
		"-stats",
		"-stats-interval", "5",
	}
	// -stats-json 仅 nuclei v3+ 支持，v2 传入会报错
	if detectNucleiMajorVersion(bin) >= 3 {
		args = append(args, "-stats-json")
	}

	if opt.Insecure {
		args = append(args, "-insecure")
	}
	if opt.Proxy != "" {
		args = append(args, "-proxy", opt.Proxy)
	}
	// 自定义请求头（认证凭证等）；拒绝含换行符的值防止参数注入
	for _, h := range opt.Headers {
		h = strings.TrimSpace(h)
		if h == "" || !strings.Contains(h, ":") || strings.ContainsAny(h, "\r\n") {
			continue
		}
		args = append(args, "-H", h)
	}

	roots := templateRoots()
	root := templateRoot()

	// ── 指纹模式：先探指纹，再缩减模板范围 ────────────────────────────────
	var fpResult *FingerprintResult
	if opt.ScanMode == "fingerprint" {
		sc.store.setPhase("fingerprint", nil)
		sc.log.Info("指纹模式：开始探测目标技术栈", "targets", len(opt.Targets))

		fr := sc.RunFingerprint(ctx, opt.Targets)
		fpResult = &fr

		if ctx.Err() != nil {
			sc.store.endScan("已手动停止")
			if opt.QueueID != "" {
				sc.store.finishQueueItem(opt.QueueID, "", "已手动停止")
			}
			sc.tryStartNextQueued()
			return
		}

		logFingerprintResult(sc.log, fr)
		sc.store.setPhase("scan", fr.Tags)

		// 如果指纹检测到了产品，用检测到的模板路径替换原始模板选择
		if len(fr.TemplatePaths) > 0 {
			sc.log.Info("指纹模式：按检测结果缩减模板", "paths", len(fr.TemplatePaths), "categories", fr.Categories)
			// 清空原来的模板选项，用指纹推导出的路径代替
			opt.Templates = strings.Join(fr.TemplatePaths, ",")
			// 同时用检测到的标签进一步在文件名层面过滤
			if len(fr.Tags) > 0 && opt.Tags == "" {
				opt.Tags = strings.Join(fr.Tags, ",")
			}
		} else {
			sc.log.Warn("指纹模式：未检测到已知产品，回退到全量扫描")
		}
	}
	_ = fpResult // 供后续引用（如上报到前端）

	switch {
	case opt.Templates != "":
		for _, t := range strings.Split(opt.Templates, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if filepath.IsAbs(t) {
				// 校验绝对路径必须位于允许的模板根目录内，防止路径穿越
				safe := false
				for _, rd := range roots {
					rel, err := filepath.Rel(rd.path, t)
					if err == nil && !strings.HasPrefix(rel, "..") {
						safe = true
						break
					}
				}
				if !safe {
					sc.log.Warn("模板路径超出允许范围，已忽略", "path", t)
					continue
				}
			} else {
				for _, rd := range roots {
					full := filepath.Join(rd.path, t)
					if _, err := os.Stat(full); err == nil {
						t = full
						break
					}
				}
			}
			args = append(args, "-t", t)
		}
	case opt.Tags != "":
		args = append(args, "-tags", opt.Tags)
	default:
		if root != "" {
			args = append(args, "-t", filepath.Join(root, "http"))
		}
	}

	// 指纹模式下标签已包含在模板路径策略里，不重复 -tags
	if opt.Severity != "" {
		args = append(args, "-severity", opt.Severity)
	}

	sc.log.Info("nuclei scan start", "bin", bin, "targets", len(opt.Targets), "mode", opt.ScanMode, "proxy", opt.Proxy)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sc.store.endScan("stdout pipe: " + err.Error())
		if opt.QueueID != "" {
			sc.store.finishQueueItem(opt.QueueID, "", err.Error())
		}
		sc.tryStartNextQueued()
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		sc.store.endScan("stderr pipe: " + err.Error())
		if opt.QueueID != "" {
			sc.store.finishQueueItem(opt.QueueID, "", err.Error())
		}
		sc.tryStartNextQueued()
		return
	}

	if err := cmd.Start(); err != nil {
		sc.store.endScan("启动 nuclei 失败: " + err.Error())
		if opt.QueueID != "" {
			sc.store.finishQueueItem(opt.QueueID, "", err.Error())
		}
		sc.tryStartNextQueued()
		return
	}

	go sc.readStderr(stderr, len(opt.Targets))

	// 30 秒定时落盘（防扫描中途引擎崩溃丢数据）
	saveTicker := time.NewTicker(30 * time.Second)
	go func() {
		defer saveTicker.Stop()
		for {
			select {
			case <-saveTicker.C:
				sc.store.save()
				sc.log.Info("periodic save", "results", sc.store.count())
			case <-ctx.Done():
				return
			}
		}
	}()

	sc.store.updateProgress(ScanProgress{
		Scanned: 0,
		Total:   len(opt.Targets),
		Percent: 0,
	})

	taskID := sc.store.getStatus().TaskID
	linescanner := bufio.NewScanner(stdout)
	linescanner.Buffer(make([]byte, 1<<20), 1<<20)

	for linescanner.Scan() {
		line := linescanner.Bytes()
		var out nucleiOutput
		if err := json.Unmarshal(line, &out); err != nil {
			continue
		}
		tags := splitTags(out.Info.Tags)
		r := &Result{
			ID:         newTaskID(),
			TemplateID: out.TemplateID,
			Name:       out.Info.Name,
			Severity:   out.Info.Severity,
			Tags:       tags,
			Host:       out.Host,
			MatchedAt:  out.MatchedAt,
			CurlCmd:    out.CurlCmd,
			Request:    truncate(out.Request, 4096),
			Response:   truncate(out.Response, 4096),
			IP:         out.IP,
			FoundAt:    time.Now(),
			TaskID:     taskID,
			Status:     "pending",
		}
		sc.store.append(r)
		sc.log.Info("nuclei hit", "id", out.TemplateID, "severity", out.Info.Severity, "host", out.Host)
	}

	_ = cmd.Wait()

	errMsg := ""
	if ctx.Err() != nil {
		errMsg = "已手动停止"
	}
	sc.store.endScan(errMsg)

	if opt.QueueID != "" {
		sc.store.finishQueueItem(opt.QueueID, taskID, errMsg)
	}

	sc.log.Info("nuclei scan done", "total", sc.store.count())

	// 自动从队列启动下一个任务
	sc.tryStartNextQueued()
}

// tryStartNextQueued 检查队列，如有 pending 项则自动启动。
func (sc *scanner) tryStartNextQueued() {
	next := sc.store.dequeueNext()
	if next == nil {
		return
	}
	sc.log.Info("queue: 自动启动下一任务", "queueId", next.ID, "targets", next.TargetCount)

	taskID := newTaskID()
	now := time.Now()
	task := &Task{
		ID:          taskID,
		Name:        next.Name,
		Targets:     next.Opt.Targets,
		TargetCount: next.TargetCount,
		Templates:   next.Opt.Templates,
		Severity:    next.Opt.Severity,
		RateLimit:   next.Opt.RateLimit,
		TimeoutSec:  next.Opt.Timeout,
		Tags:        next.Opt.Tags,
		Proxy:       next.Opt.Proxy,
		StartedAt:   now,
		Running:     true,
	}
	sc.store.beginScanTask(task)
	sc.store.updateQueueItemTaskID(next.ID, taskID)

	// 以引擎上下文为父，使 OnDisable 可取消队列任务
	ctx, cancel := context.WithCancel(sc.engineCtx)
	sc.store.setCancel(cancel)

	next.Opt.QueueID = next.ID
	go sc.Run(ctx, next.Opt)
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "…[截断]"
	}
	return s
}

// updateTemplates 在后台运行 nuclei -update-templates。
func (sc *scanner) updateTemplates(log core.Logger) {
	bin, err := findNuclei()
	if err != nil {
		log.Error("update-templates: nuclei not found", "err", err)
		return
	}
	log.Info("update-templates: start")
	cmd := exec.Command(bin, "-update-templates", "-no-color")
	out, err := cmd.CombinedOutput()
	preview := string(out)
	if len(preview) > 300 {
		preview = preview[:300]
	}
	if err != nil {
		log.Error("update-templates: failed", "err", err, "out", preview)
	} else {
		log.Info("update-templates: done", "out", preview)
	}
}
