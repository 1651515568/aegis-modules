package jsextract

// crawler.go — 并行 JS 爬取引擎（对标 getJS + LinkFinder 爬虫部分）
//
// 功能：
//   1. 支持所有 JS 加载方式：<script src>、<script type="module">、<link rel="modulepreload">
//   2. 同源递归爬页面（maxDepth 控制）
//   3. 并发抓取 JS 文件内容（最多 10 协程）
//   4. Source Map 自动跟进（发现 .map URL 后自动下载，视为伪 JS 文件）

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"redops/core"
)

// JSFile 是单个 JS 文件（或 Source Map）的元数据 + 内容。
type JSFile struct {
	URL     string
	PageURL string
	Content string
	IsMap   bool // 是否为 Source Map 文件（.map）
}

type crawlOpts struct {
	Targets   []string
	MaxDepth  int
	TimeoutMs int
	Cookie    string
	Auth      string
	FullSite  bool // 全站模式：忽略 MaxDepth，按 MaxPages 封顶
	MaxPages  int  // 全站模式下最多爬取的页面数，0 表示使用默认值 200
}

var (
	reScriptSrc     = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+\.js(?:[^"'<>]*)?)["']`)
	reModulePreload = regexp.MustCompile(`(?i)<link[^>]+rel\s*=\s*["']modulepreload["'][^>]*href\s*=\s*["']([^"']+\.js[^"']*)["']`)
	rePreloadHref   = regexp.MustCompile(`(?i)<link[^>]+href\s*=\s*["']([^"']+\.js[^"']*)["'][^>]*rel\s*=\s*["']modulepreload["']`)
	reLinkHref      = regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']([^"'#?]+)["']`)
	reSourceMapURL  = regexp.MustCompile(`//[#@] sourceMappingURL=(\S+\.map[^\s]*)`)

	// 内联 <script> 块（排除带 src 属性的外链脚本）
	reInlineScript = regexp.MustCompile(`(?i)<script([^>]*)>([\s\S]*?)</script`)
	reHasSrcAttr   = regexp.MustCompile(`(?i)\bsrc\s*=`)

	// webpack / CRA chunk 文件引用（路径中含 8 位以上小写十六进制内容哈希）
	reChunkJS = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_/.-]*[a-f0-9]{8,32}\.(?:chunk\.)?js)["'` + "`" + `]`)

	// Next.js App Router chunks（/_next/static/ 路径，hash 含大写字母，reChunkJS 无法覆盖）
	reNextJSChunk = regexp.MustCompile(`["'` + "`" + `](/_next/static/(?:chunks|media|css)/[a-zA-Z0-9_/.-]+\.js)["'` + "`" + `]`)
)

// 常见 JSON 配置文件路径（Firebase 配置、Swagger、前端 config.json 等）
var commonConfigPaths = []string{
	"/config.json", "/app.config.json", "/app-config.json",
	"/__/firebase/init.json",
	"/swagger.json", "/api/openapi.json", "/openapi.json",
}

var staticExts = []string{
	".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
	".zip", ".gz", ".tar", ".mp4", ".mp3", ".webp",
}

func isStaticAsset(rawURL string) bool {
	lower := strings.ToLower(strings.Split(rawURL, "?")[0])
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func resolveHref(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "data:") {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(r).String()
}

func newClient(timeoutMs int) *http.Client {
	if timeoutMs <= 0 {
		timeoutMs = 10000
	}
	return &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 10,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(timeoutMs/2) * time.Millisecond,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func setHeaders(req *http.Request, cookie, auth string) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
}

// fetchText 抓取 URL 内容，非 2xx 响应返回错误而非返回错误页 HTML。
func fetchText(ctx context.Context, client *http.Client, targetURL, cookie, auth string, limitMB int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	setHeaders(req, cookie, auth)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limitMB)*1024*1024))
	return string(body), err
}

// jsTask 是待抓取 JS 文件的任务单元
type jsTask struct {
	jsURL   string
	pageURL string
	isMap   bool
}

// Crawl 从种子 URL 并行爬取所有可发现的 JS（及 Source Map）文件内容。
func Crawl(ctx context.Context, opts crawlOpts, log core.Logger, progressFn func(string)) []JSFile {
	client := newClient(opts.TimeoutMs)
	seenPages := make(map[string]bool)
	seenJS := make(map[string]bool)
	var jsTasks []jsTask
	var inlineFiles []JSFile // 页面内联 <script> 块（无需抓取，直接作为 JSFile）
	var mu sync.Mutex

	addJS := func(jsURL, pageURL string, isMap bool) {
		mu.Lock()
		defer mu.Unlock()
		if seenJS[jsURL] {
			return
		}
		seenJS[jsURL] = true
		jsTasks = append(jsTasks, jsTask{jsURL, pageURL, isMap})
	}

	// 从 HTML 内容收集 JS URL（含各种加载方式）
	collectJS := func(html string, base *url.URL, pageURL string) {
		for _, pat := range []*regexp.Regexp{reScriptSrc, reModulePreload, rePreloadHref} {
			for _, m := range pat.FindAllStringSubmatch(html, -1) {
				if len(m) < 2 {
					continue
				}
				jsURL := resolveHref(base, m[1])
				if jsURL != "" {
					addJS(jsURL, pageURL, false)
				}
			}
		}
	}

	// Phase 1: 串行爬页面，收集 JS URL 列表
	type queueItem struct {
		pageURL string
		depth   int
	}

	// 全站模式页面上限：用户指定或默认 200
	fullSitePageLimit := opts.MaxPages
	if opts.FullSite && fullSitePageLimit <= 0 {
		fullSitePageLimit = 200
	}

	queue := make([]queueItem, 0, len(opts.Targets))
	for _, t := range opts.Targets {
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "http://" + t
		}
		queue = append(queue, queueItem{t, 0})
	}

	pagesCrawled := 0
	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			goto fetchPhase
		default:
		}

		// 全站模式：按页数封顶
		if opts.FullSite && pagesCrawled >= fullSitePageLimit {
			log.Info("full-site page limit reached", "limit", fullSitePageLimit)
			break
		}

		item := queue[0]
		queue = queue[1:]
		if seenPages[item.pageURL] {
			continue
		}
		seenPages[item.pageURL] = true
		pagesCrawled++

		if progressFn != nil {
			if opts.FullSite {
				progressFn(fmt.Sprintf("爬取第 %d 页 %s", pagesCrawled, truncateStr(item.pageURL, 60)))
			} else {
				progressFn("爬取 " + truncateStr(item.pageURL, 80))
			}
		}
		log.Info("crawling page", "url", item.pageURL, "depth", item.depth)

		html, err := fetchText(ctx, client, item.pageURL, opts.Cookie, opts.Auth, 2)
		if err != nil {
			log.Info("page fetch failed", "url", item.pageURL, "err", err)
			continue
		}
		base, err := url.Parse(item.pageURL)
		if err != nil {
			continue
		}

		collectJS(html, base, item.pageURL)

		// 提取页面内联 <script> 块（Phase 1 串行，无竞态）
		for idx, sm := range reInlineScript.FindAllStringSubmatch(html, -1) {
			if len(sm) < 3 {
				continue
			}
			attrs, scriptContent := sm[1], strings.TrimSpace(sm[2])
			// 跳过带 src 属性的外链脚本（已由 collectJS 处理）
			if reHasSrcAttr.MatchString(attrs) || len(scriptContent) < 30 {
				continue
			}
			synURL := fmt.Sprintf("%s#inline-%d", item.pageURL, idx)
			if !seenJS[synURL] {
				seenJS[synURL] = true
				inlineFiles = append(inlineFiles, JSFile{
					URL: synURL, PageURL: item.pageURL, Content: scriptContent,
				})
			}
		}

		// 递归同源链接：全站模式无深度限制，普通模式受 MaxDepth 约束
		if opts.FullSite || item.depth < opts.MaxDepth {
			for _, m := range reLinkHref.FindAllStringSubmatch(html, -1) {
				href := resolveHref(base, m[1])
				if href == "" || seenPages[href] || isStaticAsset(href) {
					continue
				}
				linkURL, err := url.Parse(href)
				if err != nil || linkURL.Host != base.Host {
					continue
				}
				queue = append(queue, queueItem{href, item.depth + 1})
			}
		}
	}

	// 补充：尝试抓取常见 JSON 配置文件（config.json / swagger.json 等），
	// 这些文件常包含 API 密钥和端点地址，但不会出现在 <script src> 标签中。
	{
		origins := make(map[string]bool)
		for _, t := range opts.Targets {
			if u, err := url.Parse(t); err == nil && u.Host != "" {
				origins[u.Scheme+"://"+u.Host] = true
			}
		}
		for origin := range origins {
			for _, cfgPath := range commonConfigPaths {
				cfgURL := origin + cfgPath
				mu.Lock()
				dup := seenJS[cfgURL]
				if !dup {
					seenJS[cfgURL] = true
				}
				mu.Unlock()
				if !dup {
					jsTasks = append(jsTasks, jsTask{jsURL: cfgURL, pageURL: origin})
				}
			}
		}
	}

fetchPhase:
	// Phase 2: 并发抓取所有 JS 文件（最多 10 协程）。
	//
	// 并发控制注意事项：
	//   1. select-break 只跳出 select 不跳出 for——使用标签 break loop 正确退出。
	//   2. sem <- 在 ctx cancel 后会永久阻塞——在 select 中与 ctx.Done() 竞争。
	//   3. 子 goroutine（Source Map）的 sem send 同样需要 ctx 保护防死锁。
	const concurrency = 10
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	var results []JSFile

loop:
	for _, task := range jsTasks {
		if ctx.Err() != nil {
			break loop
		}
		wg.Add(1)
		select {
		case sem <- struct{}{}:
			// 获得 semaphore 槽位，下方 go func 负责释放
		case <-ctx.Done():
			wg.Done() // 撤销 Add，避免 Wait 永久阻塞
			break loop
		}
		go func(t jsTask) {
			defer func() { <-sem; wg.Done() }()
			if progressFn != nil {
				progressFn("抓取 " + truncateStr(t.jsURL, 80))
			}
			content, err := fetchText(ctx, client, t.jsURL, opts.Cookie, opts.Auth, 5)
			if err != nil {
				log.Info("js fetch failed", "url", t.jsURL, "err", err)
				return
			}

			resultMu.Lock()
			results = append(results, JSFile{URL: t.jsURL, PageURL: t.pageURL, Content: content, IsMap: t.isMap})
			resultMu.Unlock()

			// 发现 Source Map 引用，自动跟进
			for _, m := range reSourceMapURL.FindAllStringSubmatch(content, -1) {
				if len(m) < 2 {
					continue
				}
				base, _ := url.Parse(t.jsURL)
				mapURL := resolveHref(base, m[1])
				if mapURL == "" {
					continue
				}
				mu.Lock()
				already := seenJS[mapURL]
				if !already {
					seenJS[mapURL] = true
				}
				mu.Unlock()
				if already {
					continue
				}

				wg.Add(1)
				// 子 goroutine 的 sem send 必须与 ctx.Done() 竞争，否则：
				// 若 10 个父 goroutine 均在此阻塞且 ctx 已取消，会形成死锁。
				select {
				case sem <- struct{}{}:
					go func(mURL, pageURL string) {
						defer func() { <-sem; wg.Done() }()
						mapContent, err := fetchText(ctx, client, mURL, opts.Cookie, opts.Auth, 10)
						if err != nil {
							return
						}
						resultMu.Lock()
						results = append(results, JSFile{URL: mURL, PageURL: pageURL, Content: mapContent, IsMap: true})
						resultMu.Unlock()
					}(mapURL, t.pageURL)
				case <-ctx.Done():
					wg.Done() // 撤销 Add
				}
			}
		}(task)
	}
	wg.Wait()

	// Phase 3: webpack chunk 文件发现。
	// 扫描已抓取 JS 内容中形如 /static/js/2.a1b2c3d4.chunk.js 的路径，
	// 这些 chunk 通常包含实际业务代码，静态 HTML 中不会直接引用。
	// 单次最多追踪 50 个 chunk，避免大型应用产生过多请求。
	if ctx.Err() == nil {
		var chunkTasks []jsTask
		resultMu.Lock()
		for _, jf := range results {
			base, err := url.Parse(jf.URL)
			if err != nil || base.Host == "" {
				continue
			}
			origin := base.Scheme + "://" + base.Host
			// 同时扫描 webpack/CRA 哈希 chunk 和 Next.js App Router chunk
			for _, chunkPat := range []*regexp.Regexp{reChunkJS, reNextJSChunk} {
				for _, m := range chunkPat.FindAllStringSubmatch(jf.Content, -1) {
					if len(m) < 2 {
						continue
					}
					chunkURL := origin + m[1]
					mu.Lock()
					dup := seenJS[chunkURL]
					if !dup {
						seenJS[chunkURL] = true
					}
					mu.Unlock()
					if !dup {
						chunkTasks = append(chunkTasks, jsTask{jsURL: chunkURL, pageURL: jf.PageURL})
					}
				}
			}
		}
		resultMu.Unlock()

		if len(chunkTasks) > 50 {
			log.Info("chunk discovery capped", "found", len(chunkTasks), "cap", 50)
			chunkTasks = chunkTasks[:50]
		}

		if len(chunkTasks) > 0 {
			log.Info("fetching webpack chunks", "count", len(chunkTasks))
			var wg3 sync.WaitGroup
			sem3 := make(chan struct{}, concurrency)
		loop3:
			for _, ct := range chunkTasks {
				if ctx.Err() != nil {
					break loop3
				}
				wg3.Add(1)
				select {
				case sem3 <- struct{}{}:
				case <-ctx.Done():
					wg3.Done()
					break loop3
				}
				go func(t jsTask) {
					defer func() { <-sem3; wg3.Done() }()
					content, err := fetchText(ctx, client, t.jsURL, opts.Cookie, opts.Auth, 5)
					if err != nil {
						log.Info("chunk fetch failed", "url", t.jsURL, "err", err)
						return
					}
					resultMu.Lock()
					results = append(results, JSFile{URL: t.jsURL, PageURL: t.pageURL, Content: content})
					resultMu.Unlock()
				}(ct)
			}
			wg3.Wait()
		}
	}

	// 将内联 <script> 块加入结果集（无需抓取，Phase 1 已提取内容）
	results = append(results, inlineFiles...)

	return results
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
