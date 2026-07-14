package probe

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
)

// secondaryPaths are probed in addition to "/" to surface fingerprints that
// only appear at login pages, admin panels, API docs, and monitoring endpoints.
var secondaryPaths = []string{
	"/robots.txt",
	"/login",
	"/admin",
	"/wp-login.php",
	"/wp-admin/",
	"/actuator/health",
	"/actuator",
	"/swagger-ui.html",
	"/swagger-ui/index.html",
	"/v3/api-docs",
	"/api-docs",
	"/console",
	"/manager/html",
	"/phpmyadmin/",
	"/phpMyAdmin/",
	"/druid/login.html",
	"/druid/",
	"/nacos/",
	"/nacos",
	"/jmx-console/",
	"/jenkins/",
	"/grafana/",
	"/kibana/",
	"/app/kibana",
	"/_cat/health",
}

// softNotFoundBody fetches a sentinel non-existent path to detect catch-all
// responses: SPA index.html (status 200), Cloudflare challenge (status 403),
// or other universal error pages. Any secondary path returning the IDENTICAL
// body is a catch-all and carries no product signal.
func softNotFoundBody(ctx context.Context, client *http.Client, baseURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/a3f8b1c2_probe_baseline_nonexistent", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if len(body) == 0 {
		return ""
	}
	return string(body)
}

// multiPathProbe fires GET requests at secondaryPaths concurrently, running
// fingerprinting on each response and merging new products into result.
// Must be called AFTER the root-URL Components block so the seen map starts
// pre-populated and avoids duplicating root-URL findings.
//
// 并发上限：单目标内部最多同时 8 个 goroutine，防止 200 个外层目标 × 23 条路径
// = 4600 goroutine 同时打开，耗尽文件描述符导致 OS 拒绝 TCP 连接。
func multiPathProbe(ctx context.Context, client *http.Client, baseURL string, result *ProbeResult, opts scanOptions) {
	seen := make(map[string]bool)
	for _, c := range result.Components {
		seen[c] = true
	}

	// Detect soft-404 baseline (SPA catch-all / custom error page).
	// Any path that returns the identical body is a catch-all — skip it.
	baseline := softNotFoundBody(ctx, client, baseURL)

	type hit struct {
		fp fpResult
	}
	hitCh := make(chan hit, len(secondaryPaths))
	sem := make(chan struct{}, 8) // per-target goroutine cap

	var wg sync.WaitGroup
	for _, path := range secondaryPaths {
		// 快速响应取消，不再派发新请求
		select {
		case <-ctx.Done():
			break
		default:
		}
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Skip definitive 404/410; probe 200/401/403/302 etc.
			if resp.StatusCode == 404 || resp.StatusCode == 410 {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
			bodyStr := string(body)

			// Skip soft-404: body is same as or very close to the catch-all baseline.
			// Cloudflare and other CDNs embed the requested URL into the challenge
			// page, so different paths yield bodies that differ only in the URL
			// portion — the first 256 bytes (HTML header) are identical.
			if baseline != "" && bodySimilarToBaseline(bodyStr, baseline) {
				return
			}
			hitCh <- hit{fp: runFingerprint(resp.Header, bodyStr, opts.DetectCMS, opts.DetectWAF)}
		}()
	}
	wg.Wait()
	close(hitCh)

	for h := range hitCh {
		fp := h.fp
		if result.CMS == "—" && fp.cms != "—" {
			result.CMS = fp.cms
		}
		if result.Framework == "—" && fp.framework != "—" {
			result.Framework = fp.framework
		}
		if result.WAF == "无" && fp.waf != "无" && fp.waf != "" {
			result.WAF = fp.waf
		}
		for _, product := range fp.products {
			if !seen[product] {
				seen[product] = true
				result.Components = append(result.Components, product)
			}
		}
	}

	// Active probes for technologies that passive fingerprinting can't detect.
	activeDetect(ctx, client, baseURL, baseline, result, seen)
}

// bodySimilarToBaseline returns true when bodyStr is the same as or a minor
// URL-embedding variation of baseline. This catches CDN/WAF challenge pages
// that echo the requested path into an otherwise identical HTML template.
func bodySimilarToBaseline(body, baseline string) bool {
	if body == baseline {
		return true
	}
	if len(baseline) == 0 {
		return false
	}
	// Same-prefix check: first 256 bytes identical AND similar overall length.
	prefixLen := 256
	if len(body) < prefixLen || len(baseline) < prefixLen {
		prefixLen = len(body)
		if len(baseline) < prefixLen {
			prefixLen = len(baseline)
		}
	}
	if prefixLen > 64 && body[:prefixLen] == baseline[:prefixLen] {
		ratio := float64(len(body)) / float64(len(baseline))
		if ratio >= 0.85 && ratio <= 1.15 {
			return true
		}
	}
	return false
}

// activeDetect runs protocol-level probes that passive fingerprinting can't catch,
// such as the Shiro cookie probe and Spring Actuator JSON structure check.
// baseline is the soft-404 reference body; if a probe's response is similar
// to the baseline, it's a catch-all response and should not be trusted.
func activeDetect(ctx context.Context, client *http.Client, baseURL, baseline string, result *ProbeResult, seen map[string]bool) {
	addComponent := func(name string) {
		if !seen[name] {
			seen[name] = true
			result.Components = append(result.Components, name)
			if result.CMS == "—" {
				result.CMS = name
			}
		}
	}

	type check struct {
		name string
		fn   func() bool
	}
	checks := []check{
		{"Apache Shiro", func() bool { return probeShiro(ctx, client, baseURL) }},
		{"Spring Boot Actuator", func() bool { return probeSpringActuator(ctx, client, baseURL, baseline) }},
		{"Nacos", func() bool { return probeNacos(ctx, client, baseURL, baseline) }},
		{"Alibaba Druid", func() bool { return probeDruid(ctx, client, baseURL, baseline) }},
		{"Grafana", func() bool { return probeGrafana(ctx, client, baseURL, baseline) }},
		{"Kibana", func() bool { return probeKibana(ctx, client, baseURL, baseline) }},
		{"Elasticsearch", func() bool { return probeElasticsearch(ctx, client, baseURL, baseline) }},
	}

	type res struct {
		name string
		ok   bool
	}
	resCh := make(chan res, len(checks))
	var wg sync.WaitGroup

	for _, c := range checks {
		select {
		case <-ctx.Done():
			goto activeDone
		default:
		}
		c := c
		if seen[c.name] {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			resCh <- res{c.name, c.fn()}
		}()
	}
activeDone:
	wg.Wait()
	close(resCh)

	for r := range resCh {
		if r.ok {
			addComponent(r.name)
		}
	}
}

// probeShiro injects a fake rememberMe cookie and checks for the "deleteMe"
// characteristic Set-Cookie that Apache Shiro's RememberMeManager emits on
// decryption failure — works even when Shiro is not the login page's host.
func probeShiro(ctx context.Context, client *http.Client, baseURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return false
	}
	// 4AvVhmFLUs0KTA3Kprsdag== 是用 Shiro 默认 AES key 加密的合法 rememberMe 令牌，
	// 能触发 Shiro 尝试解密并在失败时响应 Set-Cookie: rememberMe=deleteMe。
	req.Header.Set("Cookie", "rememberMe=4AvVhmFLUs0KTA3Kprsdag==")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	for _, v := range resp.Header["Set-Cookie"] {
		if strings.Contains(v, "deleteMe") {
			return true
		}
	}
	return false
}

// probeSpringActuator confirms Spring Boot Actuator by checking for a JSON
// response from /actuator/health with a "status" or "components" field.
// Accepts 200, 401, and 403 — a 401 still proves Actuator is present.
func probeSpringActuator(ctx context.Context, client *http.Client, baseURL, baseline string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/actuator/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json,application/vnd.spring-boot.actuator.v3+json")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200, 401, 403:
	default:
		return false
	}
	ct := resp.Header.Get("Content-Type")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := string(body)
	if bodySimilarToBaseline(s, baseline) {
		return false
	}
	return (strings.Contains(ct, "application/json") || strings.Contains(ct, "vnd.spring-boot")) &&
		(strings.Contains(s, `"status"`) || strings.Contains(s, `"components"`) || strings.Contains(s, `"diskSpace"`))
}

// probeNacos detects Nacos service discovery / config center.
// Requires either the nacos-server response header or the specific health API JSON.
func probeNacos(ctx context.Context, client *http.Client, baseURL, baseline string) bool {
	paths := []string{"/nacos/v1/console/health/liveness", "/nacos/", "/nacos/index.html"}
	for _, path := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if bodySimilarToBaseline(string(body), baseline) {
			continue
		}
		// nacos-server header is definitive; body checks require specific structure
		if resp.Header.Get("nacos-server") != "" {
			return true
		}
		ct := resp.Header.Get("Content-Type")
		s := string(body)
		// Health liveness endpoint returns plain "ok" text; login page has a <title>Nacos</title>
		if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/html") {
			if strings.Contains(s, "<title>Nacos") || strings.Contains(s, `"nacos"`) {
				return true
			}
		}
	}
	return false
}

// probeDruid detects Alibaba Druid connection pool monitor page.
func probeDruid(ctx context.Context, client *http.Client, baseURL, baseline string) bool {
	for _, path := range []string{"/druid/login.html", "/druid/index.html", "/druid/"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		s := string(body)
		if bodySimilarToBaseline(s, baseline) {
			continue
		}
		// Use only strings specific to the Druid UI — NOT path fragments like "druid/login.html"
		// which SPA applications echo back in canonical URLs, causing false positives.
		if strings.Contains(s, "Druid Stat Index") || strings.Contains(s, "Druid Monitor") ||
			strings.Contains(s, "com.alibaba.druid") {
			return true
		}
	}
	return false
}

// probeGrafana detects Grafana by the /api/health JSON response structure.
func probeGrafana(ctx context.Context, client *http.Client, baseURL, baseline string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	s := string(body)
	if bodySimilarToBaseline(s, baseline) {
		return false
	}
	// Grafana /api/health returns {"commit":..., "database":..., "version":...}
	// Require application/json to avoid HTML challenge pages
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "application/json") &&
		strings.Contains(s, `"database"`) && strings.Contains(s, `"version"`) && strings.Contains(s, `"commit"`)
}

// probeKibana detects Kibana via the /api/status endpoint or elastic-specific headers.
func probeKibana(ctx context.Context, client *http.Client, baseURL, baseline string) bool {
	for _, path := range []string{"/api/status", "/app/kibana"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json,text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		// Elastic-specific headers are definitive
		if resp.Header.Get("x-elastic-product") != "" || resp.Header.Get("kbn-name") != "" {
			return true
		}
		s := string(body)
		if bodySimilarToBaseline(s, baseline) {
			continue
		}
		ct := resp.Header.Get("Content-Type")
		// Only check body for JSON responses to avoid matching Cloudflare challenge HTML
		if strings.Contains(ct, "application/json") && strings.Contains(s, `"name":"kibana"`) {
			return true
		}
	}
	return false
}

// probeElasticsearch detects Elasticsearch via /_cat/health or /_cluster/health.
// The root "/" is already probed by probeOne; we only check ES-specific paths here.
func probeElasticsearch(ctx context.Context, client *http.Client, baseURL, baseline string) bool {
	for _, path := range []string{"/_cat/health", "/_cluster/health"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.Header.Get("x-elastic-product") == "Elasticsearch" {
			return true
		}
		s := string(body)
		if bodySimilarToBaseline(s, baseline) {
			continue
		}
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "application/json") &&
			(strings.Contains(s, `"cluster_name"`) && strings.Contains(s, `"tagline"`) ||
				strings.Contains(s, `"You Know, for Search"`)) {
			return true
		}
	}
	return false
}
