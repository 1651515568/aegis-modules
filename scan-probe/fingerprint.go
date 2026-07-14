package probe

// fingerprint.go — JSON-driven CMS / WAF fingerprint engine.
//
// Rule data sources (embedded at build time):
//   data/fingers.json  — CMS/product rules, format inspired by EHole (棱洞) / TideFinger
//   data/wafs.json     — WAF/CDN detection rules, inspired by wafw00f
//
// Rule schema:
//   product/waf  string            — product name
//   category     string            — grouping label
//   rules        []matchRule       — OR logic: match if ANY rule passes
//     location   string            — "body"|"header"|"title"|"cookie"
//     key        string            — for "header": header name (case-insensitive via http.Header.Get)
//     keywords   []string          — AND logic: all must appear in the target (lowercase compare)
//                                    empty keywords + location=header → header-exists check

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/fingers.json
var fingersJSON []byte

//go:embed data/wafs.json
var wafsJSON []byte

//go:embed data/ehole_raw.json
var eholeJSON []byte

//go:embed data/iot.json
var iotJSON []byte

type matchRule struct {
	Location string   `json:"location"` // body | header | title | cookie
	Key      string   `json:"key"`      // header name (any case)
	Keywords []string `json:"keywords"` // all must match (AND); empty = header-exists only
}

type productEntry struct {
	Product  string      `json:"product"`
	Category string      `json:"category"`
	Rules    []matchRule `json:"rules"` // OR: first matching rule wins
}

type wafEntry struct {
	WAF   string      `json:"waf"`
	Rules []matchRule `json:"rules"`
}

var (
	fpOnce        sync.Once
	fpProducts    []productEntry
	fpWAFs        []wafEntry
	eholeHashSigs map[int32]string // EHole faviconhash 规则：hash → 产品名

	versionReOnce sync.Once
	versionReMap  map[string][]*regexp.Regexp
)

func fpLoad() {
	fpOnce.Do(func() {
		_ = json.Unmarshal(fingersJSON, &fpProducts)
		_ = json.Unmarshal(wafsJSON, &fpWAFs)
		// 合并 EHole keyword 规则
		if extra := parseEHoleRules(eholeJSON); len(extra) > 0 {
			fpProducts = append(fpProducts, extra...)
		}
		// 加载 EHole faviconhash 规则（favicon.go 中的 probeFavicon 会查此表）
		eholeHashSigs = parseEHoleFaviconSigs(eholeJSON)
		// 合并 IoT/工控/设备专项规则
		var iotExtra []productEntry
		if err := json.Unmarshal(iotJSON, &iotExtra); err == nil {
			fpProducts = append(fpProducts, iotExtra...)
		}
	})
}

// parseEHoleFaviconSigs 从 EHole 3.x 格式中提取 faviconhash 规则，
// 返回 signed-int32 hash → 产品名 映射。与 favicon.go 的 faviconSignatures 格式一致。
func parseEHoleFaviconSigs(data []byte) map[int32]string {
	if len(data) == 0 {
		return nil
	}
	var raw eholeNewFile
	if err := json.Unmarshal(data, &raw); err != nil || len(raw.Fingerprint) == 0 {
		return nil
	}
	out := make(map[int32]string)
	for _, e := range raw.Fingerprint {
		if e.Method != "faviconhash" || len(e.Keyword) == 0 || e.CMS == "" {
			continue
		}
		n, err := strconv.ParseInt(e.Keyword[0], 10, 32)
		if err != nil {
			continue
		}
		h := int32(n)
		if _, exists := out[h]; !exists { // 保留先出现的条目，不覆盖
			out[h] = e.CMS
		}
	}
	return out
}

// ── EHole 规则导入 ────────────────────────────────────────────────────────────
//
// 支持 EHole 3.x 新格式（主分支 finger.json）：
//   {"fingerprint":[{"cms":"产品名","method":"keyword","location":"body","keyword":["..."]}]}
// 也兼容旧格式：[{"name":"产品名","rule":[{"body":"...","location":"body","keyword":["..."]}]}]
//
// 下载方式：wget -O engine/modules/scan-probe/data/ehole_raw.json
//            https://raw.githubusercontent.com/EdgeSecurityTeam/EHole/main/finger.json
// 下载后重新编译引擎即自动生效（数据文件在编译期已 embed）。
// 注意：ehole_raw.json 为空时不追加任何规则；faviconhash 类型规则由 favicon.go 单独处理，此处跳过。

// EHole 3.x 格式
type eholeNewFile struct {
	Fingerprint []eholeNewEntry `json:"fingerprint"`
}

type eholeNewEntry struct {
	CMS      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

// EHole 旧格式（兼容）
type eholeOldEntry struct {
	Name string        `json:"name"`
	Rule []eholeOldRule `json:"rule"`
}

type eholeOldRule struct {
	Body     string   `json:"body"`
	Header   string   `json:"header"`
	Keyword  []string `json:"keyword"`
	Location string   `json:"location"`
}

// parseEHoleRules 将 EHole finger.json 格式转换为本模块统一的 productEntry 格式。
// 优先尝试 EHole 3.x 新格式，失败后回退旧格式。
func parseEHoleRules(data []byte) []productEntry {
	if len(data) == 0 {
		return nil
	}

	// 尝试 EHole 3.x 新格式
	var newFile eholeNewFile
	if err := json.Unmarshal(data, &newFile); err == nil && len(newFile.Fingerprint) > 0 {
		return parseEHoleNew(newFile.Fingerprint)
	}

	// 回退旧格式
	var old []eholeOldEntry
	if err := json.Unmarshal(data, &old); err != nil || len(old) == 0 {
		return nil
	}
	return parseEHoleOld(old)
}

// parseEHoleNew 解析 EHole 3.x 格式：按 cms 名称分组，每条记录变为 OR 规则之一。
func parseEHoleNew(entries []eholeNewEntry) []productEntry {
	// 保持原始顺序，用 slice 去重
	seen := make(map[string]int) // cms → index in out
	var out []productEntry
	for _, e := range entries {
		if e.Method == "faviconhash" || len(e.Keyword) == 0 || e.CMS == "" {
			continue
		}
		loc := e.Location
		switch loc {
		case "body", "title":
			// 直接用
		case "header":
			// EHole header 规则通常是 Set-Cookie 中的会话标识，转为 cookie 匹配
			loc = "cookie"
		default:
			continue
		}
		rule := matchRule{Location: loc, Keywords: e.Keyword}
		if idx, ok := seen[e.CMS]; ok {
			out[idx].Rules = append(out[idx].Rules, rule)
		} else {
			seen[e.CMS] = len(out)
			out = append(out, productEntry{Product: e.CMS, Category: "EHole", Rules: []matchRule{rule}})
		}
	}
	return out
}

// parseEHoleOld 解析 EHole 旧格式（每个条目已包含多条 rule）。
func parseEHoleOld(entries []eholeOldEntry) []productEntry {
	out := make([]productEntry, 0, len(entries))
	for _, e := range entries {
		pe := productEntry{Product: e.Name, Category: "EHole"}
		for _, r := range e.Rule {
			kws := r.Keyword
			if len(kws) == 0 && r.Body != "" {
				kws = []string{r.Body}
			}
			if len(kws) == 0 {
				continue
			}
			loc := r.Location
			switch loc {
			case "body", "title", "cookie":
				pe.Rules = append(pe.Rules, matchRule{Location: loc, Keywords: kws})
			case "header":
				if r.Header != "" {
					pe.Rules = append(pe.Rules, matchRule{Location: "header", Key: r.Header, Keywords: kws})
				}
			}
		}
		if len(pe.Rules) > 0 {
			out = append(out, pe)
		}
	}
	return out
}

// fpResult holds all header-derived fingerprint fields.
type fpResult struct {
	server    string
	os        string
	framework string   // primary framework (X-Powered-By etc.)
	waf       string
	cms       string   // primary CMS/product (first rule match)
	products  []string // ALL matched CMS/product entries (for multi-tech stacks)
}

// runFingerprint inspects HTTP response headers and body to identify
// server, OS, framework, WAF, and CMS/product.
func runFingerprint(headers http.Header, body string, detectCMS, detectWAF bool) fpResult {
	fpLoad()

	f := fpResult{server: "—", os: "—", framework: "—", waf: "无", cms: "—"}

	// ── Server → server string + OS heuristic ──────────────────────────────
	srv := headers.Get("Server")
	if srv != "" {
		f.server = srv
		sl := strings.ToLower(srv)
		switch {
		case strings.Contains(sl, "ubuntu") || strings.Contains(sl, "debian"):
			f.os = "Linux (Debian/Ubuntu)"
		case strings.Contains(sl, "centos") || strings.Contains(sl, "rhel") || strings.Contains(sl, "redhat"):
			f.os = "Linux (RHEL/CentOS)"
		case strings.Contains(sl, "win"):
			f.os = "Windows"
		case strings.Contains(sl, "freebsd"):
			f.os = "FreeBSD"
		case strings.Contains(sl, "linux"):
			f.os = "Linux"
		}
	}

	// ── Framework from well-known headers ──────────────────────────────────
	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		f.framework = xpb
	}
	if headers.Get("X-Application-Context") != "" && f.framework == "—" {
		f.framework = "Spring Boot"
	}
	if aspnet := headers.Get("X-AspNet-Version"); aspnet != "" {
		f.framework = "ASP.NET " + aspnet
		if f.os == "—" {
			f.os = "Windows"
		}
	}
	if mv := headers.Get("X-AspNetMvc-Version"); mv != "" && f.framework == "—" {
		f.framework = "ASP.NET MVC " + mv
	}
	if headers.Get("X-Go-Version") != "" && f.framework == "—" {
		f.framework = "Go"
	}
	if rt := headers.Get("X-Runtime"); rt != "" && f.framework == "—" {
		if strings.Contains(strings.ToLower(rt), "ruby") || strings.Contains(rt, "0.") {
			f.framework = "Ruby on Rails"
		}
	}
	// IIS 版本精确提取（同时设 OS=Windows）
	if srv := headers.Get("Server"); srv != "" {
		sl := strings.ToLower(srv)
		if strings.Contains(sl, "microsoft-iis") {
			if f.os == "—" {
				f.os = "Windows"
			}
			if f.framework == "—" {
				f.framework = srv // e.g. "Microsoft-IIS/10.0"
			}
		}
	}

	// ── Pre-compute lower-case match targets ───────────────────────────────
	bodyLow := strings.ToLower(body)
	title := ""
	if m := titleRe.FindStringSubmatch(body); len(m) > 1 {
		title = strings.ToLower(strings.TrimSpace(m[1]))
	}
	// Join all Set-Cookie values so cookie rules see the full cookie jar.
	var cookieParts []string
	for _, v := range headers.Values("Set-Cookie") {
		cookieParts = append(cookieParts, strings.ToLower(v))
	}
	cookieLow := strings.Join(cookieParts, "\n")

	// ── Cookie-based framework hints ──────────────────────────────────────
	if f.framework == "—" && cookieLow != "" {
		switch {
		case strings.Contains(cookieLow, "laravel_session") || strings.Contains(cookieLow, "xsrf-token"):
			f.framework = "Laravel"
		case strings.Contains(cookieLow, "ci_session"):
			f.framework = "CodeIgniter"
		case strings.Contains(cookieLow, "cfid") && strings.Contains(cookieLow, "cftoken"):
			f.framework = "ColdFusion"
		case strings.Contains(cookieLow, "phpsessid") && f.framework == "—":
			f.framework = "PHP"
		case strings.Contains(cookieLow, "jsessionid") && f.framework == "—":
			f.framework = "Java"
		case strings.Contains(cookieLow, "rack.session"):
			f.framework = "Ruby (Rack)"
		case strings.Contains(cookieLow, "django") || strings.Contains(cookieLow, "csrftoken"):
			f.framework = "Django"
		}
	}

	// ── WAF detection ──────────────────────────────────────────────────────
	if detectWAF {
		for _, e := range fpWAFs {
			if ruleMatchAny(e.Rules, headers, bodyLow, title, cookieLow) {
				f.waf = e.WAF
				break
			}
		}
	}

	// ── CMS / product detection — collect ALL matches (remove break) ───────
	// First match sets cms (primary); subsequent matches append to products only.
	if detectCMS {
		seen := make(map[string]bool)
		for _, p := range fpProducts {
			if ruleMatchAny(p.Rules, headers, bodyLow, title, cookieLow) {
				name := productName(body, p.Product)
				if seen[name] {
					continue
				}
				seen[name] = true
				if f.cms == "—" {
					f.cms = name
				}
				f.products = append(f.products, name)
			}
		}
	}

	return f
}

// productName 返回产品显示名，对已知产品尝试提取版本号（如 "jQuery 3.6.0"）。
func productName(body, product string) string {
	switch product {
	case "WordPress", "Joomla", "Drupal":
		return extractVersionFromMeta(body, product)
	}
	versionReOnce.Do(initVersionRe)
	if pats, ok := versionReMap[product]; ok {
		for _, re := range pats {
			if m := re.FindStringSubmatch(body); len(m) > 1 && len(m[1]) <= 20 {
				return product + " " + m[1]
			}
		}
	}
	return product
}

// initVersionRe 初始化产品版本提取正则表（仅编译一次）。
// 每个产品对应有序正则列表，第一条命中的第一个捕获组即为版本号。
// 匹配目标为原始 body（未 lowercase），部分正则使用 (?i) 忽略大小写。
func initVersionRe() {
	versionReMap = map[string][]*regexp.Regexp{
		// ── JS 框架/库（版本通常嵌在 script URL 或注释里）──────────────────
		"jQuery": {
			regexp.MustCompile(`(?i)jquery[/_-]v?(\d+\.\d+[.\d]*)(?:\.min)?\.js`),
			regexp.MustCompile(`jQuery JavaScript Library v(\d+[.\d]+)`),
			regexp.MustCompile(`jquery@(\d+\.\d+[.\d]*)/`),
		},
		"Bootstrap": {
			regexp.MustCompile(`(?i)bootstrap(?:\.bundle)?\.(?:min\.)?(?:css|js)[?&]v=(\d+\.\d+[.\d]*)`),
			regexp.MustCompile(`bootstrap@(\d+\.\d+[.\d]*)/dist`),
			regexp.MustCompile(`Bootstrap v(\d+\.\d+[.\d]*)`),
		},
		"Vue.js": {
			regexp.MustCompile(`vue@(\d+\.\d+[.\d]*)/`),
			regexp.MustCompile(`(?i)/vue(?:\.min)?\.js[?&]v=(\d+[.\d]+)`),
			regexp.MustCompile(`Vue\.js v(\d+\.\d+[.\d]*)`),
		},
		"React": {
			regexp.MustCompile(`react-dom@(\d+\.\d+[.\d]*)/`),
			regexp.MustCompile(`react@(\d+\.\d+[.\d]*)/`),
		},
		"Angular": {
			regexp.MustCompile(`@angular/core@(\d+\.\d+[.\d]*)/`),
			regexp.MustCompile(`angular@(\d+\.\d+[.\d]*)/`),
			regexp.MustCompile(`AngularJS v(\d+\.\d+[.\d]*)`),
		},
		// ── 服务端产品（版本在页面/响应头中暴露）────────────────────────────
		"phpMyAdmin": {
			regexp.MustCompile(`(?i)phpmyadmin[\s/_-]+v?(\d+\.\d+[.\d]*)`),
		},
		"Grafana": {
			regexp.MustCompile(`"grafana"[^}]{0,80}"version":"(\d+\.\d+[.\d]*)"`),
			regexp.MustCompile(`grafana@(\d+\.\d+[.\d]*)/`),
		},
		"GitLab": {
			regexp.MustCompile(`data-version=(?:"|')(\d+\.\d+[.\d]*)`),
			regexp.MustCompile(`GitLab(?:\s+Community|\s+Enterprise)?\s+Edition\s+(\d+\.\d+[.\d]*)`),
		},
		"Jenkins": {
			regexp.MustCompile(`Jenkins\s+ver\.\s*(\d+\.\d+[.\d]*)`),
			regexp.MustCompile(`<li>Jenkins\s+(\d+\.\d+[.\d]*)</li>`),
		},
		"Nacos": {
			regexp.MustCompile(`(?i)/nacos/v(\d+\.\d+[.\d]*)/`),
		},
		"Apache Shiro": {
			regexp.MustCompile(`(?i)shiro[/_-](\d+\.\d+[.\d]*)(?:\.jar|-all)`),
		},
		"Swagger UI": {
			regexp.MustCompile(`swagger-ui[/_-](\d+\.\d+[.\d]*)`),
			regexp.MustCompile(`swagger-ui@(\d+\.\d+[.\d]*)/`),
		},
		"Kibana": {
			regexp.MustCompile(`kibana@(\d+\.\d+[.\d]*)/`),
			regexp.MustCompile(`"version":"(\d+\.\d+[.\d]*)","buildSha"`),
		},
		"Nexus Repository": {
			regexp.MustCompile(`Nexus Repository Manager\s+(?:OSS\s+)?(\d+\.\d+[.\d]*)`),
		},
		"SonarQube": {
			regexp.MustCompile(`SonarQube\s+v?(\d+\.\d+[.\d]*)`),
		},
		"Confluence": {
			regexp.MustCompile(`<meta name="ajs-version-number" content="(\d+\.\d+[.\d]*)"`),
		},
		"Jira": {
			regexp.MustCompile(`<meta name="ajs-version-number" content="(\d+\.\d+[.\d]*)"`),
		},
		"phpMyAdmin ": { // Wappalyzer 有时用此名称
			regexp.MustCompile(`(?i)phpmyadmin[\s/_-]+v?(\d+\.\d+[.\d]*)`),
		},
	}
}

// ruleMatchAny returns true if ANY rule in the slice matches (OR logic).
func ruleMatchAny(rules []matchRule, headers http.Header, bodyLow, title, cookieLow string) bool {
	for _, rule := range rules {
		if ruleMatchOne(rule, headers, bodyLow, title, cookieLow) {
			return true
		}
	}
	return false
}

// ruleMatchOne evaluates a single rule against pre-lowercased targets.
func ruleMatchOne(rule matchRule, headers http.Header, bodyLow, title, cookieLow string) bool {
	var target string
	switch rule.Location {
	case "body":
		target = bodyLow
	case "header":
		if rule.Key == "" {
			return false
		}
		v := headers.Get(rule.Key) // http.Header.Get canonicalises the key
		if v == "" {
			return false
		}
		if len(rule.Keywords) == 0 {
			return true // header-exists check
		}
		target = strings.ToLower(v)
	case "title":
		target = title
	case "cookie":
		target = cookieLow
	default:
		return false
	}

	// AND logic: every keyword must appear in the target.
	// Empty keywords for non-header locations means no-op rule (never match).
	if len(rule.Keywords) == 0 {
		return false
	}
	for _, kw := range rule.Keywords {
		if !strings.Contains(target, strings.ToLower(kw)) {
			return false
		}
	}
	return true
}

// extractVersionFromMeta tries to append a version string found in the
// <meta name="generator"> tag to the product name (e.g. "WordPress 6.4.2").
func extractVersionFromMeta(body, name string) string {
	bl := strings.ToLower(body)
	nl := strings.ToLower(name)
	idx := strings.Index(bl, `name="generator"`)
	if idx < 0 {
		return name
	}
	end := min(len(body), idx+400)
	chunk := body[idx:end]
	cl := strings.ToLower(chunk)
	if cidx := strings.Index(cl, nl); cidx >= 0 {
		rest := chunk[cidx+len(nl):]
		for i, c := range rest {
			if c >= '0' && c <= '9' {
				j := i
				for j < len(rest) && (rest[j] >= '0' && rest[j] <= '9' || rest[j] == '.') {
					j++
				}
				return name + " " + rest[i:j]
			}
			if i > 30 {
				break
			}
		}
	}
	return name
}
