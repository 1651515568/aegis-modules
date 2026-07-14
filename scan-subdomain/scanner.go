package subdomain

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"redops/core"
)

// SubdomainResult is the output record for a single discovered subdomain.
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IP        []string `json:"ip"`
	CDN       string   `json:"cdn"`
	Status    int      `json:"status"`
	Title     string   `json:"title"`
	Source    string   `json:"source"` // dict | ct | brute
}

// scanOptions mirrors the frontend form parameters.
type scanOptions struct {
	Domain      string `json:"domain"`
	Mode        string `json:"mode"`        // dict | brute | ct | all
	DictPreset  string `json:"dictPreset"`  // small | medium | large | xlarge
	Permutation bool   `json:"permutation"` // generate env/service permutations from discovered prefixes
	Resolver    string `json:"resolver"`
	Threads     int    `json:"threads"`
	TimeoutMs   int    `json:"timeoutMs"`
	HunterKey   string `json:"hunterKey"`
	ZoomEyeKey  string `json:"zoomeyeKey"`
	QuakeKey    string `json:"quakeKey"`
	ZeroZoneKey string `json:"zerozoneKey"`
	FOFAEmail        string `json:"fofaEmail"`        // FOFA 账号邮箱（与 fofaKey 配合）
	FOFAKey          string `json:"fofaKey"`          // FOFA API Key
	ShodanKey        string `json:"shodanKey"`        // Shodan API Key
	SecurityTrailsKey string `json:"securitytrailsKey"` // SecurityTrails API Key
	CensysID         string `json:"censysId"`         // Censys API ID
	CensysSecret     string `json:"censysSecret"`     // Censys API Secret
	VirusTotalKey    string `json:"virusTotalKey"`    // VirusTotal API Key
	ChaosKey         string `json:"chaosKey"`         // Chaos (ProjectDiscovery) API Key
	ThreatBookKey    string `json:"threatbookKey"`    // 微步在线 ThreatBook API Key
}

type scanner struct {
	log core.Logger
}

func newScanner(log core.Logger) *scanner { return &scanner{log: log} }

var subTitleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]{0,256})</title>`)

// resolverPool provides round-robin DNS resolver selection for higher throughput.
type resolverPool struct {
	resolvers []*net.Resolver
	idx       uint64 // accessed via sync/atomic
}

func (p *resolverPool) pick() *net.Resolver {
	i := atomic.AddUint64(&p.idx, 1) % uint64(len(p.resolvers))
	return p.resolvers[i]
}

// makeResolverPool builds a round-robin pool from a comma-separated list of DNS servers.
func makeResolverPool(servers string) *resolverPool {
	var addrs []string
	for _, s := range strings.Split(servers, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		addrs = append(addrs, s)
	}
	if len(addrs) == 0 {
		return &resolverPool{resolvers: []*net.Resolver{net.DefaultResolver}}
	}
	pool := make([]*net.Resolver, len(addrs))
	for i, addr := range addrs {
		a := addr // capture for closure
		pool[i] = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", a)
			},
		}
	}
	return &resolverPool{resolvers: pool}
}

// run executes the subdomain enumeration according to opts.
// progressFn(tried, found) is called after each DNS resolution attempt.
func (s *scanner) run(ctx context.Context, opts scanOptions, progressFn func(tried, found int)) ([]SubdomainResult, error) {
	domain := strings.TrimSpace(strings.ToLower(opts.Domain))
	if domain == "" {
		return nil, fmt.Errorf("domain is empty")
	}
	threads := opts.Threads
	if threads <= 0 {
		threads = 50
	}
	if threads > 500 {
		threads = 500
	}
	timeoutMs := opts.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	mode := opts.Mode
	if mode == "" {
		mode = "all"
	}

	pool := makeResolverPool(opts.Resolver)
	httpClient := makeHTTPClient(timeoutMs)

	// Wildcard detection: resolve a random nonce to see if this domain has a wildcard record.
	wildcardIPs := detectWildcard(ctx, pool.pick(), domain)
	if len(wildcardIPs) > 0 {
		s.log.Warn("wildcard DNS detected — false positives will be filtered",
			"domain", domain, "wildcard_ips", wildcardIPList(wildcardIPs))
	}

	var (
		mu      sync.Mutex
		results []SubdomainResult
		seen    = make(map[string]bool)
		tried   int64
		found   int64
	)

	addResult := func(r SubdomainResult) {
		mu.Lock()
		defer mu.Unlock()
		if seen[r.Subdomain] {
			return
		}
		seen[r.Subdomain] = true
		results = append(results, r)
	}

	// resolveAndEnrich resolves each subdomain, filters wildcards, enriches with CDN+HTTP.
	resolveAndEnrich := func(subs []string, source string) {
		sem := make(chan struct{}, threads)
		var wg sync.WaitGroup
	outer:
		for _, sub := range subs {
			select {
			case <-ctx.Done():
				break outer
			default:
			}
			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				break outer
			}
			go func(subdomain string) {
				defer func() {
					<-sem
					wg.Done()
					cur := int(atomic.AddInt64(&tried, 1))
					if progressFn != nil {
						progressFn(cur, int(atomic.LoadInt64(&found)))
					}
				}()
				// Each goroutine picks a resolver in round-robin for load distribution.
				ips, err := pool.pick().LookupHost(ctx, subdomain)
				if err != nil || len(ips) == 0 {
					return
				}
				// Skip wildcard hits — all IPs are in the wildcard set.
				if isWildcardHit(ips, wildcardIPs) {
					return
				}
				atomic.AddInt64(&found, 1)
				cdn := detectCDN(ctx, subdomain, ips)
				status, title := fetchHTTPInfo(ctx, httpClient, subdomain)
				addResult(SubdomainResult{
					Subdomain: subdomain,
					IP:        ips,
					CDN:       cdn,
					Status:    status,
					Title:     title,
					Source:    source,
				})
			}(sub)
		}
		wg.Wait() // 无论是否取消，等所有 goroutine 完成才返回，防止数据竞争
	}

	if mode == "all" || mode == "dict" {
		words := getWordlist(opts.DictPreset)
		subs := make([]string, 0, len(words))
		for _, w := range words {
			subs = append(subs, w+"."+domain)
		}
		resolveAndEnrich(subs, "dict")
	}

	if mode == "all" || mode == "brute" {
		resolveAndEnrich(generateBruteSubs(domain), "brute")
	}

	if mode == "all" || mode == "ct" {
		// Run crt.sh, hackertarget, and certspotter in parallel for maximum CT coverage.
		var ctSubs, htSubs, csSubs []string
		var ctWg sync.WaitGroup
		ctWg.Add(3)
		go func() {
			defer ctWg.Done()
			subs, err := queryCRT(ctx, domain)
			if err != nil {
				s.log.Warn("crt.sh query failed", "domain", domain, "err", err)
				return
			}
			s.log.Info("crt.sh candidates", "domain", domain, "count", len(subs))
			ctSubs = subs
		}()
		go func() {
			defer ctWg.Done()
			subs, err := queryHackerTarget(ctx, domain)
			if err != nil {
				s.log.Warn("hackertarget query failed", "domain", domain, "err", err)
				return
			}
			s.log.Info("hackertarget candidates", "domain", domain, "count", len(subs))
			htSubs = subs
		}()
		go func() {
			defer ctWg.Done()
			subs, err := queryCertSpotter(ctx, domain)
			if err != nil {
				s.log.Warn("certspotter query failed", "domain", domain, "err", err)
				return
			}
			s.log.Info("certspotter candidates", "domain", domain, "count", len(subs))
			csSubs = subs
		}()
		ctWg.Wait()
		allCT := append(ctSubs, htSubs...) //nolint:gocritic
		allCT = append(allCT, csSubs...)
		resolveAndEnrich(allCT, "ct")
	}

	// ── 威胁情报 API 源（可选，需填写对应 API Key）───────────────────────────
	type apiSource struct {
		name string
		fn   func(context.Context, string, string) ([]string, error)
		key  string
	}
	apiSources := []apiSource{
		{"hunter", queryHunter, opts.HunterKey},
		{"zoomeye", queryZoomEye, opts.ZoomEyeKey},
		{"quake", queryQuake, opts.QuakeKey},
		{"zerozone", queryZeroZone, opts.ZeroZoneKey},
		// FOFA 需要 email+key 两字段，用闭包捕获，以 email 作 key 存在性检查。
		{"fofa", func(ctx context.Context, domain, _ string) ([]string, error) {
			return queryFOFA(ctx, domain, opts.FOFAEmail, opts.FOFAKey)
		}, opts.FOFAEmail},
		{"shodan", queryShodan, opts.ShodanKey},
		{"securitytrails", querySecurityTrails, opts.SecurityTrailsKey},
		// Censys 需要 ID+Secret 两字段，用闭包捕获，以 CensysID 作存在性检查。
		{"censys", func(ctx context.Context, domain, _ string) ([]string, error) {
			return queryCensys(ctx, domain, opts.CensysID, opts.CensysSecret)
		}, opts.CensysID},
		{"virustotal", queryVirusTotal, opts.VirusTotalKey},
		{"chaos", queryChaos, opts.ChaosKey},
		{"threatbook", queryThreatBook, opts.ThreatBookKey},
	}
	// API 情报源并行查询：各源相互独立，串行等待会使总耗时为 N 个源超时之和。
	// resolveAndEnrich 内部线程安全（addResult 持锁），可从多 goroutine 并发调用。
	var apiWg sync.WaitGroup
	for _, src := range apiSources {
		if src.key == "" || ctx.Err() != nil {
			continue
		}
		src := src // 捕获循环变量
		apiWg.Add(1)
		go func() {
			defer apiWg.Done()
			s.log.Info("querying api source", "source", src.name, "domain", domain)
			subs, err := src.fn(ctx, domain, src.key)
			if err != nil {
				s.log.Warn("api source failed", "source", src.name, "err", err)
				return
			}
			s.log.Info("api source result", "source", src.name, "count", len(subs))
			resolveAndEnrich(subs, src.name)
		}()
	}
	apiWg.Wait()

	// ── Permutation pass (optional) ──────────────────────────────────────────
	// Extract prefixes from already-discovered subdomains, cross them with
	// common env/service tokens, and resolve the resulting candidates.
	if opts.Permutation && ctx.Err() == nil {
		mu.Lock()
		knownPrefixes := make([]string, 0, len(results))
		for _, r := range results {
			prefix := strings.TrimSuffix(r.Subdomain, "."+domain)
			if !strings.Contains(prefix, ".") && len(prefix) >= 2 && len(prefix) <= 30 {
				knownPrefixes = append(knownPrefixes, prefix)
			}
		}
		mu.Unlock()
		permSubs := generatePermutations(knownPrefixes, domain, seen)
		if len(permSubs) > 0 {
			s.log.Info("permutation pass", "domain", domain, "candidates", len(permSubs))
			resolveAndEnrich(permSubs, "perm")
		}
	}

	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// permTokens are common environment/service suffixes used in permutation generation.
var permTokens = []string{
	"dev", "prod", "staging", "stg", "test", "qa", "uat",
	"new", "old", "v1", "v2", "v3", "backup", "bak",
	"int", "ext", "2", "3",
}

// generatePermutations builds {prefix}-{token} and {token}-{prefix} candidates
// not already in the seen set.  seen is read after all resolveAndEnrich calls
// have returned, so no mutex is needed here.
func generatePermutations(prefixes []string, domain string, seen map[string]bool) []string {
	if len(prefixes) == 0 {
		return nil
	}
	dedup := make(map[string]bool)
	var out []string
	for _, p := range prefixes {
		for _, tok := range permTokens {
			if p == tok {
				continue
			}
			for _, c := range []string{p + "-" + tok, tok + "-" + p} {
				full := c + "." + domain
				if !seen[full] && !dedup[c] {
					dedup[c] = true
					out = append(out, full)
				}
			}
		}
	}
	return out
}

// detectWildcard resolves a random nonce subdomain to detect DNS wildcards.
func detectWildcard(ctx context.Context, resolver *net.Resolver, domain string) map[string]bool {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	nonce := "wc-" + hex.EncodeToString(b)
	ips, err := resolver.LookupHost(ctx, nonce+"."+domain)
	if err != nil || len(ips) == 0 {
		return nil
	}
	wildcardIPs := make(map[string]bool, len(ips))
	for _, ip := range ips {
		wildcardIPs[ip] = true
	}
	return wildcardIPs
}

// isWildcardHit returns true when every IP in ips appears in wildcardIPs.
func isWildcardHit(ips []string, wildcardIPs map[string]bool) bool {
	if len(wildcardIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if !wildcardIPs[ip] {
			return false
		}
	}
	return true
}

func wildcardIPList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for ip := range m {
		out = append(out, ip)
	}
	return out
}

func makeHTTPClient(timeoutMs int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(timeoutMs/2) * time.Millisecond,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// fetchHTTPInfo tries https first, then falls back to http.
func fetchHTTPInfo(ctx context.Context, client *http.Client, subdomain string) (int, string) {
	type result struct {
		code  int
		title string
	}
	tryScheme := func(scheme string) (result, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+subdomain, nil)
		if err != nil {
			return result{}, false
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AEGIS/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			return result{}, false
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		_ = resp.Body.Close()
		title := ""
		if m := subTitleRe.FindSubmatch(body); len(m) > 1 {
			title = strings.TrimSpace(string(m[1]))
		}
		return result{resp.StatusCode, title}, true
	}
	if r, ok := tryScheme("https"); ok {
		return r.code, r.title
	}
	if r, ok := tryScheme("http"); ok {
		return r.code, r.title
	}
	return 0, ""
}

// detectCDN checks CNAME and IP range patterns to identify CDN/WAF providers.
// ctx 使 CNAME 查询能响应取消，避免在批量任务停止时阻塞工作 goroutine 最多 30s。
func detectCDN(ctx context.Context, host string, ips []string) string {
	resolver := &net.Resolver{PreferGo: true}
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil {
		cname = strings.TrimRight(strings.ToLower(cname), ".")
		switch {
		case strings.Contains(cname, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(cname, "akamai") || strings.Contains(cname, "akamaiedge") || strings.Contains(cname, "edgesuite"):
			return "Akamai"
		case strings.Contains(cname, "fastly"):
			return "Fastly"
		case strings.Contains(cname, "cloudfront"):
			return "AWS CloudFront"
		case strings.Contains(cname, "incapsula") || strings.Contains(cname, "imperva"):
			return "Imperva Incapsula"
		case strings.Contains(cname, "alicdn") || strings.Contains(cname, "aliyuncs") || strings.Contains(cname, "aliyun"):
			return "阿里云 CDN"
		case strings.Contains(cname, "qcloud") || strings.Contains(cname, "tencentcdn") || strings.Contains(cname, "myqcloud"):
			return "腾讯云 CDN"
		case strings.Contains(cname, "hwcdn") || strings.Contains(cname, "huaweicloud"):
			return "华为云 CDN"
		case strings.Contains(cname, "cdn77") || strings.Contains(cname, "keycdn"):
			return "KeyCDN"
		case strings.Contains(cname, "azureedge") || strings.Contains(cname, "azure"):
			return "Azure CDN"
		case strings.Contains(cname, "dualstack") || strings.Contains(cname, "elb.amazonaws"):
			return "AWS ELB"
		case strings.Contains(cname, "netlify"):
			return "Netlify"
		case strings.Contains(cname, "vercel") || strings.Contains(cname, "now.sh"):
			return "Vercel"
		case strings.Contains(cname, "pages.github") || strings.Contains(cname, "github.io"):
			return "GitHub Pages"
		case strings.Contains(cname, "wpengine"):
			return "WP Engine"
		case strings.Contains(cname, "sucuri"):
			return "Sucuri"
		case strings.Contains(cname, "ddos-guard"):
			return "DDoS-Guard"
		case strings.Contains(cname, "wcdn") || strings.Contains(cname, "wangsu"):
			return "网宿 CDN"
		case strings.Contains(cname, "chinanetcenter") || strings.Contains(cname, "lxdns"):
			return "网宿 CDN"
		case strings.Contains(cname, "baidubce") || strings.Contains(cname, "bcebos"):
			return "百度云 CDN"
		case strings.Contains(cname, "ucloud"):
			return "UCloud CDN"
		case strings.Contains(cname, "qiniudns") || strings.Contains(cname, "qnssl"):
			return "七牛云 CDN"
		case strings.Contains(cname, "wswebpic") || strings.Contains(cname, "upai"):
			return "又拍云 CDN"
		}
	}

	// IP-range heuristics for major CDN/cloud providers.
	for _, ip := range ips {
		switch {
		case strings.HasPrefix(ip, "104.16.") || strings.HasPrefix(ip, "104.17.") ||
			strings.HasPrefix(ip, "104.18.") || strings.HasPrefix(ip, "104.19.") ||
			strings.HasPrefix(ip, "172.64.") || strings.HasPrefix(ip, "172.65.") ||
			strings.HasPrefix(ip, "172.66.") || strings.HasPrefix(ip, "172.67."):
			return "Cloudflare"
		}
	}

	return "—"
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// queryCRT queries crt.sh for subdomains discovered in certificate transparency logs.
func queryCRT(ctx context.Context, domain string) ([]string, error) {
	u := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS Security Platform")
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	defer resp.Body.Close()

	// crt.sh 对热门域名可能返回数 MB 的 JSON；限 4MB 防止内存爆炸。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("crt.sh read: %w", err)
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh decode: %w", err)
	}

	seen := make(map[string]bool)
	var subs []string
	suffix := "." + domain
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			line = strings.TrimSpace(strings.ToLower(line))
			line = strings.TrimPrefix(line, "*.")
			if strings.HasSuffix(line, suffix) && !seen[line] {
				seen[line] = true
				subs = append(subs, line)
			}
		}
	}
	return subs, nil
}

// queryHackerTarget queries hackertarget.com for passive subdomain discovery.
// Free tier allows ~10 queries/day without an API key.
func queryHackerTarget(ctx context.Context, domain string) ([]string, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS Security Platform")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}
	// API rate-limit or error responses start with known strings.
	if bytes.Contains(body, []byte("API count exceeded")) ||
		bytes.Contains(body, []byte("error check")) ||
		bytes.Contains(body, []byte("input validation")) {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(string(body)))
	}
	// Response format: "subdomain.example.com,1.2.3.4\n..."
	seen := make(map[string]bool)
	var subs []string
	suffix := "." + domain
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
		host := strings.ToLower(parts[0])
		if strings.HasSuffix(host, suffix) && host != domain && !seen[host] {
			seen[host] = true
			subs = append(subs, host)
		}
	}
	return subs, nil
}

// generateBruteSubs generates single (a-z, 0-9) and two-character (aa-zz, a0-z9) subdomain candidates.
func generateBruteSubs(domain string) []string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	subs := make([]string, 0, len(chars)+len(chars)*len(chars))
	// Single character
	for _, c := range chars {
		subs = append(subs, string(c)+"."+domain)
	}
	// Two characters (letters + digits)
	for _, c1 := range chars {
		for _, c2 := range chars {
			subs = append(subs, string(c1)+string(c2)+"."+domain)
		}
	}
	return subs
}

// ─── CertSpotter (免费 CT 日志，无需 Key) ────────────────────────────────────
//
// API: https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names
// 响应: [{"dns_names": ["sub.example.com", ...]}, ...]

func queryCertSpotter(ctx context.Context, domain string) ([]string, error) {
	u := "https://api.certspotter.com/v1/issuances?domain=" + domain + "&include_subdomains=true&expand=dns_names"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS Security Platform")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter request: %w", err)
	}
	defer resp.Body.Close()

	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&issuances); err != nil {
		return nil, fmt.Errorf("certspotter decode: %w", err)
	}

	suffix := "." + strings.ToLower(domain)
	dom := strings.ToLower(domain)
	seen := make(map[string]bool)
	var subs []string
	for _, iss := range issuances {
		for _, name := range iss.DNSNames {
			name = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(name, "*.")))
			if (strings.HasSuffix(name, suffix) || name == dom) && !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}
