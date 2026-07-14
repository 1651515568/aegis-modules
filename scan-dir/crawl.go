package scandir

// crawl.go —— 响应链接抽取(参考 feroxbuster --extract-links / dirsearch --crawl)。
//
// 从命中的 HTML/JS/文本响应体里挖出更多端点(href/src/action 属性、JS 里以 / 开头的引号串、
// robots.txt 的 Allow/Disallow 路径),解析为「同主机绝对 URL」回灌扫描队列——
// 把纯爆破升级为「爆破 + 已链接/未链接内容发现」的混合式探测。

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// HTML 属性里的引用:href= / src= / action= 后接引号或裸值。
	reAttr = regexp.MustCompile(`(?i)(?:href|src|action|data-url|formaction)\s*=\s*["']?([^"'>\s]+)`)
	// JS/文本里以 / 开头的引号串(常见 API/资源路径)。
	reQuotedPath = regexp.MustCompile(`["'](/[A-Za-z0-9_\-./~%]{1,256})["']`)
	// robots.txt 的 Allow/Disallow 行。
	reRobots = regexp.MustCompile(`(?im)^\s*(?:Allow|Disallow)\s*:\s*(\S+)`)
)

// maxLinksPerResp 限制单个响应抽取的链接数,防恶意/超大页面拖垮扫描。
const maxLinksPerResp = 200

// extractLinks 从一个响应体里抽取同主机绝对 URL(去重、去 fragment/query、限量)。
// pageURL 为该响应自身 URL,用于相对路径解析与同主机判定。
func extractLinks(pageURL string, body []byte) []string {
	base, err := url.Parse(pageURL)
	if err != nil || body == nil {
		return nil
	}
	text := string(body)
	cands := make([]string, 0, 32)
	collect := func(re *regexp.Regexp) {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 {
				cands = append(cands, m[1])
			}
		}
	}
	collect(reAttr)
	collect(reQuotedPath)
	if strings.Contains(strings.ToLower(base.Path), "robots") {
		collect(reRobots)
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" || strings.HasPrefix(c, "#") ||
			strings.HasPrefix(c, "data:") || strings.HasPrefix(c, "javascript:") ||
			strings.HasPrefix(c, "mailto:") || strings.HasPrefix(c, "tel:") {
			continue
		}
		ref, err := url.Parse(c)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		if abs.Host != base.Host { // 仅同主机,绝不外联
			continue
		}
		abs.RawQuery = ""
		abs.Fragment = ""
		u := abs.String()
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
		if len(out) >= maxLinksPerResp {
			break
		}
	}
	return out
}

// isCrawlable 判定响应是否值得抽链(2xx/3xx 且为文本/HTML/JS/JSON 类)。
func isCrawlable(res probeResult) bool {
	if res.status < 200 || res.status >= 400 {
		return false
	}
	if len(res.body) == 0 {
		return false
	}
	ct := strings.ToLower(res.ctype)
	if ct == "" {
		return true // 无 Content-Type 也尝试(很多接口不带)
	}
	return strings.Contains(ct, "html") || strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "json") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "text/")
}
