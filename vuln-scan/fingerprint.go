package vulnscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

func tlsSkipVerify() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

// ── 指纹规则结构 ─────────────────────────────────────────────────────────────

//go:embed fingerprints.json
var fingerprintsData []byte

type fpRule struct {
	Name     string    `json:"name"`
	Category string    `json:"category"` // 对应 custom-templates 目录前缀
	Tags     []string  `json:"tags"`     // 在模板路径/文件名里搜索的关键词
	Priority int       `json:"priority"` // 1=高 2=中 3=低
	Probes   []fpProbe `json:"probes"`
}

type fpProbe struct {
	Path    string      `json:"path"`
	Method  string      `json:"method"`
	Headers map[string]string `json:"request_headers,omitempty"`
	Matchers []fpMatcher `json:"matchers"`
}

type fpMatcher struct {
	Type     string   `json:"type"`     // body|header|title|status|favicon
	Keywords []string `json:"keywords"` // body/header/title 匹配（OR）
	Status   int      `json:"status"`   // status 类型时使用
	Favicon  []string `json:"favicon"`  // favicon 哈希列表
}

// ── 全局规则缓存 ─────────────────────────────────────────────────────────────

var (
	fpRules     []fpRule
	fpRulesOnce sync.Once
)

func loadFPRules() []fpRule {
	fpRulesOnce.Do(func() {
		if err := json.Unmarshal(fingerprintsData, &fpRules); err != nil {
			fpRules = nil
			return
		}
		// 合并运行时学习到的 favicon hash（不影响编译期嵌入规则）
		loadLearnedFavicons(fpRules)
	})
	return fpRules
}

// ── murmur3 + favicon hash（与 Shodan/FOFA icon_hash 算法完全一致）────────────

// murmur3_32 计算 MurmurHash3 32-bit，返回有符号 int32（Shodan/FOFA 算法）。
func murmur3_32(data []byte) int32 {
	const c1, c2 = uint32(0xcc9e2d51), uint32(0x1b873593)
	h1 := uint32(0)
	n := len(data)
	for i := 0; i < (n/4)*4; i += 4 {
		k := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		k = (k * c1)
		k = bits.RotateLeft32(k, 15)
		k = (k * c2)
		h1 ^= k
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[(n/4)*4:]
	k := uint32(0)
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k = k * c1
		k = bits.RotateLeft32(k, 15)
		k = k * c2
		h1 ^= k
	}
	h1 ^= uint32(n)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}

// mimeBase64 模拟 Python base64.encodebytes：每 76 字节插一个 \n，末尾也有 \n。
func mimeBase64(data []byte) []byte {
	raw := base64.StdEncoding.EncodeToString(data)
	var buf bytes.Buffer
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		buf.WriteString(raw[i:end])
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// computeFaviconHash 返回 Shodan/FOFA icon_hash 字符串（有符号十进制）。
func computeFaviconHash(faviconBytes []byte) string {
	return strconv.FormatInt(int64(murmur3_32(mimeBase64(faviconBytes))), 10)
}

// ── HTTP 探针客户端 ──────────────────────────────────────────────────────────

func newFPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     tlsSkipVerify(),
		MaxIdleConnsPerHost: 10,
		DisableKeepAlives:   false,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// ── 单目标探针 ───────────────────────────────────────────────────────────────

type fpHit struct {
	Target   string   `json:"target"`
	Products []fpProduct `json:"products"`
}

type fpProduct struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
	Priority int      `json:"priority"`
}

// probeTarget 对单个目标执行所有探针规则，返回匹配的产品列表。
func probeTarget(ctx context.Context, client *http.Client, target string, rules []fpRule) []fpProduct {
	// 规范化 target：确保有协议前缀
	baseURL := target
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	type probeResult struct {
		status  int
		body    []byte
		headers http.Header
	}

	// 缓存每个路径的 HTTP 响应，避免重复请求
	cache := make(map[string]*probeResult)
	var cacheMu sync.Mutex

	fetchPath := func(path, method string, reqHeaders map[string]string) *probeResult {
		key := method + ":" + path
		cacheMu.Lock()
		if r, ok := cache[key]; ok {
			cacheMu.Unlock()
			return r
		}
		cacheMu.Unlock()

		url := baseURL + path
		if method == "" {
			method = "GET"
		}
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		for k, v := range reqHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		// 最多读 64KB body
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		r := &probeResult{status: resp.StatusCode, body: body, headers: resp.Header}

		cacheMu.Lock()
		cache[key] = r
		cacheMu.Unlock()
		return r
	}

	matched := make(map[string]fpProduct) // name → product

	for _, rule := range rules {
		if ctx.Err() != nil {
			break
		}
		for _, probe := range rule.Probes {
			pr := fetchPath(probe.Path, probe.Method, probe.Headers)
			if pr == nil {
				continue
			}

			allMatch := true
			for _, m := range probe.Matchers {
				if !matcherHit(m, pr.status, pr.body, pr.headers) {
					allMatch = false
					break
				}
			}
			if allMatch && len(probe.Matchers) > 0 {
				matched[rule.Name] = fpProduct{
					Name:     rule.Name,
					Category: rule.Category,
					Tags:     rule.Tags,
					Priority: rule.Priority,
				}
				break // 该规则已命中，跳到下一个规则
			}
		}
	}

	result := make([]fpProduct, 0, len(matched))
	for _, p := range matched {
		result = append(result, p)
	}
	return result
}

// matcherHit 判断单个 matcher 是否命中响应。
func matcherHit(m fpMatcher, status int, body []byte, headers http.Header) bool {
	switch m.Type {
	case "status":
		return m.Status > 0 && status == m.Status
	case "body":
		return bodyContainsAny(body, m.Keywords)
	case "header":
		return headersContainAny(headers, m.Keywords)
	case "title":
		title := extractTitle(body)
		for _, kw := range m.Keywords {
			if strings.Contains(strings.ToLower(title), strings.ToLower(kw)) {
				return true
			}
		}
		return false
	case "favicon":
		if status != 200 || len(body) < 64 {
			return false
		}
		hashStr := computeFaviconHash(body)
		for _, fh := range m.Favicon {
			if fh == hashStr {
				return true
			}
		}
		return false
	}
	return false
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([\s\S]{0,512}?)</title>`)

func extractTitle(body []byte) string {
	if m := titleRe.FindSubmatch(body); m != nil {
		t := string(m[1])
		t = strings.TrimSpace(t)
		if !utf8.ValidString(t) {
			return ""
		}
		return t
	}
	return ""
}

func bodyContainsAny(body []byte, keywords []string) bool {
	lower := bytes.ToLower(body)
	for _, kw := range keywords {
		if bytes.Contains(lower, bytes.ToLower([]byte(kw))) {
			return true
		}
	}
	return false
}

func headersContainAny(headers http.Header, keywords []string) bool {
	// 把所有头拼在一起检查
	var sb strings.Builder
	for k, vs := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(vs, "; "))
		sb.WriteString("\n")
	}
	all := strings.ToLower(sb.String())
	for _, kw := range keywords {
		if strings.Contains(all, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// ── 批量并发指纹检测 ─────────────────────────────────────────────────────────

const (
	fpWorkers      = 30  // 并发目标数
	fpTimeout      = 8   // 单探针超时秒数
	fpMaxProbesCap = 800 // 每目标最多执行的探针数（性能保护）
)

// FingerprintResult 单次指纹扫描的汇总结果。
type FingerprintResult struct {
	Hits          []fpHit  `json:"hits"`
	Categories    []string `json:"categories"`    // 去重后的分类列表
	TemplatePaths []string `json:"templatePaths"` // 推导出的模板目录
	Tags          []string `json:"tags"`          // 推导出的标签关键词（供搜索模板文件名）
}

// RunFingerprint 对多个目标并发执行指纹探测。
func (sc *scanner) RunFingerprint(ctx context.Context, targets []string) FingerprintResult {
	rules := loadFPRules()
	if len(rules) == 0 {
		sc.log.Warn("指纹库为空，跳过指纹检测")
		return FingerprintResult{}
	}

	// 限制每目标最多执行的规则数（优先级高的先探）
	cappedRules := rules
	if len(cappedRules) > fpMaxProbesCap {
		cappedRules = cappedRules[:fpMaxProbesCap]
	}

	client := newFPClient(time.Duration(fpTimeout) * time.Second)

	type work struct {
		idx    int
		target string
	}
	jobs := make(chan work, len(targets))
	type res struct {
		idx int
		hit fpHit
	}
	results := make(chan res, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < fpWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				products := probeTarget(ctx, client, job.target, cappedRules)
				// 异步学习：对识别到的产品，抓 /favicon.ico 记录 hash 供下次使用
				if len(products) > 0 {
					go learnFavicons(ctx, client, job.target, products)
				}
				results <- res{idx: job.idx, hit: fpHit{Target: job.target, Products: products}}
			}
		}()
	}

	for i, t := range targets {
		jobs <- work{i, t}
	}
	close(jobs)

	go func() { wg.Wait(); close(results) }()

	hits := make([]fpHit, len(targets))
	for r := range results {
		hits[r.idx] = r.hit
	}

	// 汇总分类 + 模板路径 + 标签
	catSet := make(map[string]bool)
	tagSet := make(map[string]bool)
	for _, h := range hits {
		for _, p := range h.Products {
			if p.Category != "" {
				catSet[p.Category] = true
			}
			for _, t := range p.Tags {
				tagSet[t] = true
			}
		}
	}

	cats := make([]string, 0, len(catSet))
	for c := range catSet {
		cats = append(cats, c)
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}

	// 把分类映射到 custom-templates 目录
	tplPaths := resolveFPTemplatePaths(cats, tags)

	fr := FingerprintResult{
		Hits:          hits,
		Categories:    cats,
		TemplatePaths: tplPaths,
		Tags:          tags,
	}
	return fr
}

// resolveFPTemplatePaths 把检测到的分类/标签映射到具体的模板目录/文件。
func resolveFPTemplatePaths(categories []string, tags []string) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	customRoot := filepath.Join(home, "custom-templates")
	officialRoot := filepath.Join(home, "nuclei-templates", "http")

	seen := make(map[string]bool)
	var paths []string

	add := func(p string) {
		if seen[p] {
			return
		}
		if _, err := os.Stat(p); err == nil {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// 1. 先按分类加入 custom-templates 目录
	for _, cat := range categories {
		add(filepath.Join(customRoot, cat))
	}

	// 2. 在 custom-templates 里按标签搜索匹配文件
	if len(paths) == 0 {
		// 如果没有匹配的分类目录，全量搜 custom-templates
		add(customRoot)
	} else {
		// 否则在已有分类目录里用标签进一步缩小
		// （此步骤在调用方通过 -tags 实现，这里只返回目录）
	}

	// 3. 加入官方 http 模板里与检测到标签相关的子目录
	officialSubs := map[string]string{
		"wordpress":  filepath.Join(officialRoot, "cves"),
		"spring":     filepath.Join(officialRoot, "cves"),
		"shiro":      filepath.Join(officialRoot, "vulnerabilities"),
		"struts":     filepath.Join(officialRoot, "cves"),
		"weblogic":   filepath.Join(officialRoot, "cves"),
		"jboss":      filepath.Join(officialRoot, "cves"),
		"confluence": filepath.Join(officialRoot, "cves"),
		"exchange":   filepath.Join(officialRoot, "cves"),
		"gitlab":     filepath.Join(officialRoot, "cves"),
		"jenkins":    filepath.Join(officialRoot, "cves"),
	}
	for _, tag := range tags {
		for kw, subPath := range officialSubs {
			if strings.Contains(strings.ToLower(tag), kw) {
				add(subPath)
			}
		}
	}

	return paths
}

// ── 从 SSE / 日志输出指纹结果 ───────────────────────────────────────────────

func logFingerprintResult(log interface{ Info(string, ...any) }, fr FingerprintResult) {
	var detected []string
	seen := make(map[string]bool)
	for _, h := range fr.Hits {
		for _, p := range h.Products {
			if !seen[p.Name] {
				seen[p.Name] = true
				detected = append(detected, p.Name)
			}
		}
	}
	log.Info("指纹检测完成",
		"targets", len(fr.Hits),
		"products", len(detected),
		"categories", fr.Categories,
		"detected", strings.Join(detected, ", "),
	)
}

// ── 从文件目录中用标签关键词筛选模板路径 ────────────────────────────────────

// findTemplatesByTags 在给定目录列表里按标签关键词找 YAML 文件，
// 返回包含任一 tag 关键词的文件路径列表（大文件列表时会返回目录而非文件）。
func findTemplatesByTags(dirs []string, tags []string, maxFiles int) []string {
	if len(tags) == 0 || len(dirs) == 0 {
		return dirs
	}
	lowerTags := make([]string, len(tags))
	for i, t := range tags {
		lowerTags[i] = strings.ToLower(t)
	}

	var matched []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
				continue
			}
			name := strings.ToLower(e.Name())
			for _, tag := range lowerTags {
				if strings.Contains(name, tag) {
					matched = append(matched, filepath.Join(dir, e.Name()))
					break
				}
			}
			if len(matched) >= maxFiles {
				return matched
			}
		}
	}

	// 如果匹配文件太少（<10），回退到整个目录
	if len(matched) < 10 {
		return dirs
	}
	return matched
}

// ── 从 io.Reader 读指纹 JSON（供调试用）──────────────────────────────────────

func dumpFingerprintResult(fr FingerprintResult, w io.Writer) {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "指纹检测结果：\n")
	for _, h := range fr.Hits {
		if len(h.Products) == 0 {
			fmt.Fprintf(bw, "  %-40s  未识别\n", h.Target)
			continue
		}
		var names []string
		for _, p := range h.Products {
			names = append(names, p.Name)
		}
		fmt.Fprintf(bw, "  %-40s  %s\n", h.Target, strings.Join(names, " | "))
	}
	fmt.Fprintf(bw, "分类: %s\n", strings.Join(fr.Categories, ", "))
	fmt.Fprintf(bw, "模板路径: %d 个\n", len(fr.TemplatePaths))
	_ = bw.Flush()
}
