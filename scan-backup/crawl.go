package backup

// crawl.go —— 智能爬取 / 链接提取。
//
// 纯字典/递归只能盲猜路径;真正高价值的发现往往来自「目标自己暴露的真实文件名与目录」:
//   * 抓取目标的普通页面(HTML)、robots.txt、sitemap.xml,提取站内链接 → 得到真实路径;
//   * 对真实文件派生备份变体(OWASP WSTG-CONF-04 的核心手法:已知文件名 → 探其 .bak/~/.old…);
//   * 对真实目录喂给递归引擎,比盲猜目录命中率高得多;
//   * 真实文件中本身就像备份/敏感的(.sql/.zip/.env…)直接探。
//
// 安全边界:爬取只获取目标的「普通页面」(HTML/robots/sitemap,单页 ≤maxPageBytes),用于提取
// 链接与文件名;对疑似「备份/敏感文件」本身仍只做 ≤16/512B 探测,绝不下载其文件体。

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const (
	maxPageBytes     = 256 << 10 // 单页爬取读取上限(普通页面,用于提链)
	maxDiscoverFiles = 600       // 发现文件数上限
	maxDiscoverDirs  = 200       // 发现目录数上限
)

// discovery 是一次爬取的产物:真实文件 / 真实目录(均为站点根相对路径)。
type discovery struct {
	files map[string]struct{}
	dirs  map[string]struct{}
}

func newDiscovery() discovery {
	return discovery{files: map[string]struct{}{}, dirs: map[string]struct{}{}}
}

var (
	// 提取 href/src/action 与 CSS url(...) 中的链接。
	linkRe   = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']?([^"'>\s]+)`)
	cssURLRe = regexp.MustCompile(`(?i)url\(\s*["']?([^"')]+)`)
)

// crawl 从目标根/入口页 BFS 抓取最多 maxPages 个页面,提取站内链接,返回发现的文件与目录。
func (sc *scanner) crawl(ctx context.Context, client *http.Client, u *url.URL, maxPages int) discovery {
	d := newDiscovery()
	visited := map[string]struct{}{}
	// 种子:站点根、目标自身路径、robots.txt、sitemap.xml、常见构建清单。
	queue := []string{"", "robots.txt", "sitemap.xml", "asset-manifest.json"}
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		queue = append([]string{p}, queue...)
	}
	pages := 0

	for len(queue) > 0 && pages < maxPages {
		if ctx.Err() != nil {
			break
		}
		p := queue[0]
		queue = queue[1:]
		if _, seen := visited[p]; seen {
			continue
		}
		visited[p] = struct{}{}

		readCap := maxPageBytes
		if isJSAsset(p, "") || isSourceMap(p) || isManifestJSON(p) {
			readCap = maxJSBytes // JS/map/manifest 可较大
		}
		code, body, ctype := sc.fetchPage(ctx, client, probeURL(u, p), readCap)
		if code == 0 || len(body) == 0 {
			continue
		}
		pages++
		pageURL := probeURL(u, p)

		switch {
		case p == "robots.txt":
			for _, np := range parseRobots(body) {
				record(&d, np)
				queue = enqueueCrawl(queue, visited, np)
			}
		case strings.Contains(p, "sitemap") && strings.Contains(string(peek(body)), "<"):
			for _, loc := range parseSitemap(body) {
				if rel := resolveSameHost(u, pageURL, loc); rel != "" {
					record(&d, rel)
					queue = enqueueCrawl(queue, visited, rel)
				}
			}
		case isSourceMap(p):
			// source map:原始源码文件路径 → 真实文件名/目录(派生备份/喂递归)。
			for _, src := range mineSourceMap(body) {
				record(&d, src)
			}
		case isJSAsset(p, ctype) || isManifestJSON(p):
			// 静态 JS 挖掘:bundle/清单里的路径字面量。
			for _, np := range mineJS(body) {
				if rel := resolveSameHost(u, pageURL, np); rel != "" {
					record(&d, rel)
				}
			}
			if isJSAsset(p, ctype) && !isSourceMap(p) {
				queue = enqueueCrawl(queue, visited, p+".map") // 顺带尝试同名 source map
			}
		case strings.Contains(strings.ToLower(ctype), "html") || ctype == "":
			for _, link := range extractLinks(body) {
				rel := resolveSameHost(u, pageURL, link)
				if rel == "" {
					continue
				}
				record(&d, rel)
				if isCrawlable(rel) {
					queue = enqueueCrawl(queue, visited, rel)
				}
			}
		}
		if len(d.files) >= maxDiscoverFiles && len(d.dirs) >= maxDiscoverDirs {
			break
		}
	}
	return d
}

// fetchPage 抓取一个普通页面/资源,读取至多 cap 字节(经限速 + 退避 + 网络重试)。
func (sc *scanner) fetchPage(ctx context.Context, client *http.Client, rawURL string, limit int) (int, []byte, string) {
	var netAttempt, throttleAttempt int
	for {
		if sc.lim.wait(ctx) != nil {
			return 0, nil, ""
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return 0, nil, ""
		}
		req.Header.Set("User-Agent", scanUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil && netAttempt < maxNetRetries {
				sc.netRetryWait(ctx, netAttempt)
				netAttempt++
				continue
			}
			return 0, nil, ""
		}
		code := resp.StatusCode
		if isThrottle(code) && throttleAttempt < maxRetries {
			ra := resp.Header.Get("Retry-After")
			_ = resp.Body.Close()
			if !sc.backoff(ctx, ra, throttleAttempt) {
				return code, nil, ""
			}
			throttleAttempt++
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
		ctype := resp.Header.Get("Content-Type")
		// 排空剩余 body，使 Transport 能复用 TCP 连接（不排空则关闭时丢弃连接）。
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return code, body, ctype
	}
}

// record 把一个站点根相对路径登记为文件或目录(带上限,防爆炸)。
func record(d *discovery, rel string) {
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	if rel == "" {
		return
	}
	if strings.HasSuffix(rel, "/") {
		if len(d.dirs) < maxDiscoverDirs {
			d.dirs[rel] = struct{}{}
		}
		return
	}
	base := path.Base(rel)
	if strings.Contains(base, ".") {
		if len(d.files) < maxDiscoverFiles {
			d.files[rel] = struct{}{}
		}
		// 文件所在目录也是一个真实目录。
		if dir := path.Dir(rel); dir != "." && dir != "/" && len(d.dirs) < maxDiscoverDirs {
			d.dirs[dir+"/"] = struct{}{}
		}
	} else {
		// 无扩展名 → 视为目录(clean URL)。
		if len(d.dirs) < maxDiscoverDirs {
			d.dirs[rel+"/"] = struct{}{}
		}
	}
}

// enqueueCrawl 把可继续爬取的页面加入队列(已访问则跳过)。
func enqueueCrawl(queue []string, visited map[string]struct{}, rel string) []string {
	rel = strings.TrimPrefix(rel, "/")
	if _, seen := visited[rel]; seen {
		return queue
	}
	if isCrawlable(rel) {
		return append(queue, rel)
	}
	return queue
}

// isCrawlable 判断一个路径是否值得继续抓取(只跟 HTML 类页面与目录,跳过图片/归档等)。
func isCrawlable(rel string) bool {
	if rel == "" || strings.HasSuffix(rel, "/") {
		return true
	}
	if isJSAsset(rel, "") || isSourceMap(rel) || isManifestJSON(rel) {
		return true // JS / source map / 构建清单 也抓取以做静态挖掘
	}
	ext := strings.ToLower(path.Ext(rel))
	switch ext {
	case "", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".shtml":
		return true
	}
	return false
}

// extractLinks 从页面正文提取所有候选链接(href/src/action + css url())。
func extractLinks(body []byte) []string {
	var out []string
	for _, m := range linkRe.FindAllSubmatch(body, -1) {
		out = append(out, string(m[1]))
	}
	for _, m := range cssURLRe.FindAllSubmatch(body, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// resolveSameHost 把链接解析为「同主机、站点根相对」的路径;跨域/非 http 链接返回空。
func resolveSameHost(host *url.URL, pageURL, link string) string {
	link = strings.TrimSpace(link)
	if link == "" || strings.HasPrefix(link, "#") {
		return ""
	}
	low := strings.ToLower(link)
	for _, bad := range []string{"mailto:", "javascript:", "data:", "tel:", "sms:", "ftp:"} {
		if strings.HasPrefix(low, bad) {
			return ""
		}
	}
	pu, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(link)
	if err != nil {
		return ""
	}
	abs := pu.ResolveReference(ref)
	if abs.Host != host.Host {
		return "" // 仅同主机(含端口)
	}
	p := abs.Path
	if strings.HasSuffix(link, "/") && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return strings.TrimPrefix(p, "/")
}

// peek 取正文前若干字节用于轻量判别(如是否 XML)。
func peek(b []byte) []byte {
	if len(b) > 256 {
		return b[:256]
	}
	return b
}

// parseRobots 提取 robots.txt 的 Disallow / Allow 路径与 Sitemap 链接路径。
func parseRobots(body []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(body), "\n") {
		ln = strings.TrimSpace(ln)
		low := strings.ToLower(ln)
		switch {
		case strings.HasPrefix(low, "disallow:"), strings.HasPrefix(low, "allow:"):
			v := strings.TrimSpace(ln[strings.Index(ln, ":")+1:])
			v = strings.TrimSuffix(v, "*")
			if v != "" && v != "/" {
				out = append(out, strings.TrimPrefix(v, "/"))
			}
		case strings.HasPrefix(low, "sitemap:"):
			v := strings.TrimSpace(ln[strings.Index(ln, ":")+1:])
			if i := strings.Index(v, "://"); i >= 0 {
				if j := strings.Index(v[i+3:], "/"); j >= 0 {
					out = append(out, strings.TrimPrefix(v[i+3+j:], "/"))
				}
			}
		}
	}
	return out
}

// parseSitemap 提取 sitemap.xml 中 <loc>…</loc> 的 URL。
func parseSitemap(body []byte) []string {
	var out []string
	s := string(body)
	for {
		i := strings.Index(s, "<loc>")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "</loc>")
		if j < 0 {
			break
		}
		out = append(out, strings.TrimSpace(s[i+5:i+j]))
		s = s[i+j+6:]
	}
	return out
}

// backupVariantCandidates 为一个真实文件派生备份变体候选(file + 各编辑器/遗留后缀)。
func backupVariantCandidates(file string) []candidate {
	base := path.Base(file)
	out := make([]candidate, 0, len(editorSuffixes))
	for _, suf := range editorSuffixes {
		rel := file + suf
		out = append(out, candidate{rel: rel, rule: "爬取派生备份: " + base + suf, kind: classifyKind(rel, "", "")})
	}
	return out
}

// looksSensitive 判断一个爬取到的真实文件本身是否像「可下载的泄露文件」(值得直接探测)。
// 关键:动态/可执行页面(.php/.asp/.jsp…)是被服务端解析后输出的页面,本身不是泄露
// (其源码/备份才是,由 backupVariantCandidates 覆盖),故排除,避免把正常页面误报为命中。
func looksSensitive(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".php", ".php5", ".phtml", ".asp", ".aspx", ".jsp", ".jspx",
		".do", ".action", ".cgi", ".pl", ".py", ".rb", ".html", ".htm", ".shtml":
		return false
	}
	lp := strings.ToLower(rel)
	for _, e := range archiveExts {
		if strings.HasSuffix(lp, e) {
			return true
		}
	}
	return classifyKind(rel, "", "") != "其它" // .sql/.bak/.env/.git/config/.yml/.pem…
}
