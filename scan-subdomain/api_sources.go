package subdomain

// api_sources.go — 威胁情报/网络空间搜索引擎子域名查询整合
// 支持：Hunter / ZoomEye / 360 Quake / 零零信安 / FOFA / Shodan / SecurityTrails / Censys / VirusTotal / Chaos / 微步 ThreatBook
//
// 所有 API 请求经 apiDoRetry 包装：遇到 429（限流）后指数退避（1s/2s/4s），最多重试 3 次。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiMaxBodySize = 512 * 1024 // 512 KB

// sharedAPIClient 是所有情报 API 调用共用的 HTTP 客户端，避免每次请求创建新连接池。
var sharedAPIClient = &http.Client{Timeout: 30 * time.Second}

// sanitizeAPIErr 从 net/http 错误中移除 URL（可能含 API Key），仅保留操作和底层错误。
// Go 的 *url.Error 格式为 `Get "https://host/path?key=SECRET": underlying`，直接 log 会泄露密钥。
func sanitizeAPIErr(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

// apiDoRetry 对单次 HTTP 请求做最多 3 次 429 退避重试（延迟：1s / 2s / 4s）。
// 网络错误或非 429 错误不重试，直接返回。
// newReq 每次被调用时构造新请求（POST 需要重建 Body Reader）。
func apiDoRetry(ctx context.Context, newReq func() (*http.Request, error)) (*http.Response, error) {
	backoffs := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	for i := 0; ; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := sharedAPIClient.Do(req)
		if err != nil {
			return nil, sanitizeAPIErr(err)
		}
		if resp.StatusCode != http.StatusTooManyRequests || i >= len(backoffs) {
			return resp, nil
		}
		// 429: 关闭响应体，等待后重试
		resp.Body.Close()
		select {
		case <-time.After(backoffs[i]):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// filterSubdomains keeps only entries that end with "."+domain or equal domain.
func filterSubdomains(candidates []string, domain string) []string {
	suffix := "." + strings.ToLower(domain)
	dom := strings.ToLower(domain)
	seen := make(map[string]bool)
	var out []string
	for _, c := range candidates {
		c = strings.TrimSpace(strings.ToLower(c))
		c = strings.TrimPrefix(c, "*.")
		if (strings.HasSuffix(c, suffix) || c == dom) && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// ─── Hunter (奇安信鹰图) ──────────────────────────────────────────────────────
//
// API: https://hunter.qianxin.com/openApi/search
// 参数: api-key, search (base64), page=1, page_size=100, is_web=3
// 响应: data.arr[].domain

type hunterResp struct {
	Code int `json:"code"`
	Data struct {
		Arr []struct {
			Domain string `json:"domain"`
		} `json:"arr"`
	} `json:"data"`
}

func queryHunter(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	searchQ := base64.StdEncoding.EncodeToString([]byte("domain(" + domain + ")"))
	rawURL := fmt.Sprintf(
		"https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=100&is_web=3",
		apiKey, searchQ,
	)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("hunter request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var hr hunterResp
	if err := json.Unmarshal(body, &hr); err != nil {
		return nil, fmt.Errorf("hunter decode: %w", err)
	}
	var subs []string
	for _, a := range hr.Data.Arr {
		if a.Domain != "" {
			subs = append(subs, a.Domain)
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── ZoomEye (钟馗之眼) ──────────────────────────────────────────────────────
//
// API: https://api.zoomeye.org/domain/search
// 头部: API-KEY: <key>
// 参数: q=<domain>, type=0 (子域名), page=1
// 响应: list[].name

type zoomEyeResp struct {
	List []struct {
		Name string `json:"name"`
	} `json:"list"`
}

func queryZoomEye(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://api.zoomeye.org/domain/search?q=%s&type=0&page=1", domain)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("API-KEY", apiKey)
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("zoomeye request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var zr zoomEyeResp
	if err := json.Unmarshal(body, &zr); err != nil {
		return nil, fmt.Errorf("zoomeye decode: %w", err)
	}
	var subs []string
	for _, item := range zr.List {
		if item.Name != "" {
			subs = append(subs, item.Name)
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── 360 Quake ───────────────────────────────────────────────────────────────
//
// API: https://quake.360.net/api/v3/scroll/quake_service (POST)
// 头部: X-QuakeToken: <key>, Content-Type: application/json
// body: {"query": "domain: \"example.com\"", "start": 0, "size": 100}
// 响应: data[].service.http.host | data[].service.tls.ja3s

type quakeResp struct {
	Data []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
			TLS struct {
				Ja3s string `json:"ja3s"`
			} `json:"tls"`
		} `json:"service"`
	} `json:"data"`
}

func queryQuake(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	bodyMap := map[string]interface{}{
		"query": fmt.Sprintf(`domain: "%s"`, domain),
		"start": 0,
		"size":  100,
	}
	bodyBytes, _ := json.Marshal(bodyMap)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://quake.360.net/api/v3/scroll/quake_service",
			bytes.NewReader(bodyBytes))
		if e != nil {
			return nil, e
		}
		req.Header.Set("X-QuakeToken", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("quake request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var qr quakeResp
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("quake decode: %w", err)
	}
	seen := make(map[string]bool)
	var subs []string
	for _, d := range qr.Data {
		for _, h := range []string{d.Service.HTTP.Host} {
			h = strings.TrimSpace(h)
			if h != "" && !seen[h] {
				seen[h] = true
				subs = append(subs, h)
			}
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── 零零信安 (0.zone) ────────────────────────────────────────────────────────
//
// API: https://0.zone/api/aggs
// 头部: Authorization: <key>
// 参数: q=<domain>, qbase=domain, page=1, pagesize=50
// 响应: data[].domain

type zeroZoneResp struct {
	Data []struct {
		Domain string `json:"domain"`
	} `json:"data"`
}

func queryZeroZone(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://0.zone/api/aggs?q=%s&qbase=domain&page=1&pagesize=50", domain)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("zerozone request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var zr zeroZoneResp
	if err := json.Unmarshal(body, &zr); err != nil {
		return nil, fmt.Errorf("zerozone decode: %w", err)
	}
	var subs []string
	for _, d := range zr.Data {
		if d.Domain != "" {
			subs = append(subs, d.Domain)
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── FOFA ────────────────────────────────────────────────────────────────────
//
// API: https://fofa.info/api/v1/search/all
// 参数: email=<email>&key=<key>&qbase64=BASE64(domain="<domain>")&fields=host&page=1&size=100
// 响应: results[][0] 为 host（可能含端口，需去除）

type fofaResp struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Results [][]string `json:"results"`
}

func queryFOFA(ctx context.Context, domain, email, apiKey string) ([]string, error) {
	if email == "" || apiKey == "" {
		return nil, nil
	}
	query := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`domain="%s"`, domain)))
	rawURL := fmt.Sprintf(
		"https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=host&page=1&size=100",
		email, apiKey, query,
	)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("fofa request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var fr fofaResp
	if err := json.Unmarshal(body, &fr); err != nil {
		return nil, fmt.Errorf("fofa decode: %w", err)
	}
	if fr.Error {
		return nil, fmt.Errorf("fofa api error: %s", fr.ErrMsg)
	}
	var fofaSubs []string
	for _, row := range fr.Results {
		if len(row) == 0 {
			continue
		}
		host := row[0]
		// 去除端口（host:port → host），仅当末段全为数字时才认为是端口
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			maybePort := host[idx+1:]
			allDigit := true
			for _, c := range maybePort {
				if c < '0' || c > '9' {
					allDigit = false
					break
				}
			}
			if allDigit {
				host = host[:idx]
			}
		}
		if host != "" {
			fofaSubs = append(fofaSubs, host)
		}
	}
	return filterSubdomains(fofaSubs, domain), nil
}

// ─── Shodan ──────────────────────────────────────────────────────────────────
//
// API: https://api.shodan.io/dns/domain/<domain>?key=<key>
// 响应: subdomains[] 为前缀数组（不含主域名），需拼接 "." + domain
//
//	data[].subdomain 也可作为来源，两者合并去重

type shodanDNSResp struct {
	Subdomains []string `json:"subdomains"`
	Data       []struct {
		Subdomain string `json:"subdomain"`
	} `json:"data"`
}

func queryShodan(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, apiKey)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("shodan request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var sr shodanDNSResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("shodan decode: %w", err)
	}
	seen := make(map[string]bool)
	var shodanSubs []string
	for _, prefix := range sr.Subdomains {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		fqdn := prefix + "." + domain
		if !seen[fqdn] {
			seen[fqdn] = true
			shodanSubs = append(shodanSubs, fqdn)
		}
	}
	for _, d := range sr.Data {
		prefix := strings.TrimSpace(d.Subdomain)
		if prefix == "" {
			continue
		}
		fqdn := prefix + "." + domain
		if !seen[fqdn] {
			seen[fqdn] = true
			shodanSubs = append(shodanSubs, fqdn)
		}
	}
	return filterSubdomains(shodanSubs, domain), nil
}

// ─── SecurityTrails ───────────────────────────────────────────────────────────
//
// API: https://api.securitytrails.com/v1/domain/<domain>/subdomains
// 头部: APIKEY: <key>
// 响应: {"subdomains": ["www", "mail", ...]} — 返回前缀，需拼接 "." + domain

type securityTrailsResp struct {
	Subdomains []string `json:"subdomains"`
}

func querySecurityTrails(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=true", domain)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("APIKEY", apiKey)
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("securitytrails request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var str securityTrailsResp
	if err := json.Unmarshal(body, &str); err != nil {
		return nil, fmt.Errorf("securitytrails decode: %w", err)
	}
	var subs []string
	for _, prefix := range str.Subdomains {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			subs = append(subs, prefix+"."+domain)
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── Censys ───────────────────────────────────────────────────────────────────
//
// API: https://search.censys.io/api/v2/certificates/search
// 参数: q=parsed.names:<domain>&fields=parsed.names&per_page=100
// 认证: Basic base64(apiID:apiSecret)
// 响应: result.hits[].parsed.names — 证书 SAN 字段，含通配符，需过滤

type censysHit struct {
	Names []string `json:"parsed.names"`
}

type censysCertSearchResp struct {
	Result struct {
		Hits []censysHit `json:"hits"`
	} `json:"result"`
}

func queryCensys(ctx context.Context, domain, apiID, apiSecret string) ([]string, error) {
	if apiID == "" || apiSecret == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf(
		"https://search.censys.io/api/v2/certificates/search?q=parsed.names%%3A+%%22%s%%22&fields=parsed.names&per_page=100",
		domain,
	)
	credentials := base64.StdEncoding.EncodeToString([]byte(apiID + ":" + apiSecret))
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Basic "+credentials)
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("censys request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var cr censysCertSearchResp
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("censys decode: %w", err)
	}
	seen := make(map[string]bool)
	var subs []string
	for _, hit := range cr.Result.Hits {
		for _, name := range hit.Names {
			name = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(name, "*.")))
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────
//
// API: https://www.virustotal.com/api/v3/domains/<domain>/subdomains?limit=40
// 头部: x-apikey: <key>
// 响应: data[].id — 完整 FQDN

type virusTotalResp struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func queryVirusTotal(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("x-apikey", apiKey)
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("virustotal request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var vtr virusTotalResp
	if err := json.Unmarshal(body, &vtr); err != nil {
		return nil, fmt.Errorf("virustotal decode: %w", err)
	}
	var subs []string
	for _, d := range vtr.Data {
		if d.ID != "" {
			subs = append(subs, d.ID)
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── Chaos (ProjectDiscovery) ─────────────────────────────────────────────────
//
// API: https://dns.projectdiscovery.io/dns/<domain>/subdomains
// 头部: Authorization: <key>
// 响应: {"subdomains": ["www", "mail", ...]} — 返回前缀，需拼接 "." + domain

type chaosResp struct {
	Subdomains []string `json:"subdomains"`
}

func queryChaos(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("chaos request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var cr chaosResp
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("chaos decode: %w", err)
	}
	var subs []string
	for _, prefix := range cr.Subdomains {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			subs = append(subs, prefix+"."+domain)
		}
	}
	return filterSubdomains(subs, domain), nil
}

// ─── 微步在线 ThreatBook ──────────────────────────────────────────────────────
//
// API: https://api.threatbook.cn/v1/domain/sub_domains?domain=<domain>&apikey=<key>
// 响应: {"sub_domains": {"data": ["sub.example.com", ...]}}

type threatBookResp struct {
	SubDomains struct {
		Data []string `json:"data"`
	} `json:"sub_domains"`
}

func queryThreatBook(ctx context.Context, domain, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	rawURL := fmt.Sprintf("https://api.threatbook.cn/v1/domain/sub_domains?domain=%s&apikey=%s", domain, apiKey)
	resp, err := apiDoRetry(ctx, func() (*http.Request, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "AEGIS Security Platform")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("threatbook request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBodySize))
	if err != nil {
		return nil, err
	}
	var tbr threatBookResp
	if err := json.Unmarshal(body, &tbr); err != nil {
		return nil, fmt.Errorf("threatbook decode: %w", err)
	}
	return filterSubdomains(tbr.SubDomains.Data, domain), nil
}
