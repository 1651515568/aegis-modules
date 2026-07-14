package assetcollect

// api_net.go — 网络测绘情报源：Hunter / FOFA / ZoomEye / Quake / 零零信安 /
//              Shodan / SecurityTrails / Censys / VirusTotal / Chaos / 微步 ThreatBook
// 每个函数接受已构建好的平台专属 query 字符串，返回 []CollectedAsset。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const netMaxBody = 2 * 1024 * 1024 // 2 MB，crt.sh 大域名响应可达数 MB
const netMaxPages = 5              // 每个情报源最多拉取 5 页，防止 API 配额超支

func netHTTPClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

func netGet(ctx context.Context, u string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS Security Platform")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := netHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, netMaxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		snippet := string(data)
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return data, nil
}

func netPost(ctx context.Context, u string, body []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS Security Platform")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := netHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, netMaxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		snippet := string(data)
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return data, nil
}

func makeAsset(t, value, org, source, meta string) CollectedAsset {
	return CollectedAsset{Type: t, Value: strings.TrimSpace(value), Org: org, Source: source, Meta: meta}
}

// ─── Hunter (奇安信鹰图) ──────────────────────────────────────────────────────

type hunterNetResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Arr   []struct {
			IP     string `json:"ip"`
			Domain string `json:"domain"`
			Port   int    `json:"port"`
			Org    string `json:"company"`
		} `json:"arr"`
	} `json:"data"`
}

func collectFromHunter(ctx context.Context, query, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	// Hunter 要求 URL-safe base64（不带 padding），即 RawURLEncoding
	q := base64.RawURLEncoding.EncodeToString([]byte(query))
	const pageSize = 100

	seen := map[string]bool{}
	var assets []CollectedAsset
	fetched := 0

	for page := 1; page <= netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=3",
			apiKey, q, page, pageSize)
		body, err := netGet(ctx, u, nil)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("hunter: %w", err)
			}
			break
		}
		var r hunterNetResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("hunter decode: %w (raw: %.200s)", err, string(body))
			}
			break
		}
		if r.Code != 200 {
			if page == 1 {
				return nil, fmt.Errorf("hunter api error %d: %s", r.Code, r.Message)
			}
			break
		}
		if len(r.Data.Arr) == 0 {
			break
		}
		fetched += len(r.Data.Arr)
		for _, a := range r.Data.Arr {
			if a.Domain != "" && !seen["d:"+a.Domain] {
				seen["d:"+a.Domain] = true
				assets = append(assets, makeAsset("domain", a.Domain, a.Org, "hunter",
					fmt.Sprintf(`{"port":%d}`, a.Port)))
			}
			if a.IP != "" && !seen["i:"+a.IP] {
				seen["i:"+a.IP] = true
				assets = append(assets, makeAsset("ip", a.IP, a.Org, "hunter",
					fmt.Sprintf(`{"port":%d}`, a.Port)))
			}
		}
		if fetched >= r.Data.Total {
			break
		}
	}
	return assets, nil
}

// ─── FOFA ────────────────────────────────────────────────────────────────────

type fofaNetResp struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Size    int        `json:"size"`    // 总结果数
	Results [][]string `json:"results"` // [host, ip, domain, port]
}

func collectFromFOFA(ctx context.Context, query, email, apiKey string) ([]CollectedAsset, error) {
	if email == "" || apiKey == "" {
		return nil, nil
	}
	q := base64.StdEncoding.EncodeToString([]byte(query)) // FOFA 用标准 base64
	const pageSize = 100

	seen := map[string]bool{}
	var assets []CollectedAsset
	fetched := 0

	for page := 1; page <= netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=host,ip,domain,port&page=%d&size=%d",
			url.QueryEscape(email), url.QueryEscape(apiKey), url.QueryEscape(q), page, pageSize)
		body, err := netGet(ctx, u, nil)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("fofa: %w", err)
			}
			break
		}
		var r fofaNetResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("fofa decode: %w", err)
			}
			break
		}
		if r.Error {
			if page == 1 {
				return nil, fmt.Errorf("fofa api: %s", r.ErrMsg)
			}
			break
		}
		if len(r.Results) == 0 {
			break
		}
		fetched += len(r.Results)
		for _, row := range r.Results {
			if len(row) < 4 {
				continue
			}
			host, ip, domain, port := row[0], row[1], row[2], row[3]
			if domain != "" && !seen["d:"+domain] {
				seen["d:"+domain] = true
				assets = append(assets, makeAsset("domain", domain, "", "fofa", fmt.Sprintf(`{"host":%q,"port":%q}`, host, port)))
			}
			if ip != "" && !seen["i:"+ip] {
				seen["i:"+ip] = true
				assets = append(assets, makeAsset("ip", ip, "", "fofa", fmt.Sprintf(`{"port":%q}`, port)))
			}
		}
		if r.Size > 0 && fetched >= r.Size {
			break
		}
	}
	return assets, nil
}

// ─── ZoomEye (钟馗之眼) ──────────────────────────────────────────────────────

type zoomEyeNetResp struct {
	Total   int `json:"total"`
	Matches []struct {
		IP   string   `json:"ip"`
		Name []string `json:"name"`
	} `json:"matches"`
}

func collectFromZoomEye(ctx context.Context, query, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var assets []CollectedAsset
	fetched := 0

	for page := 1; page <= netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://api.zoomeye.org/host/search?query=%s&page=%d&pagesize=100", url.QueryEscape(query), page)
		body, err := netGet(ctx, u, map[string]string{"API-KEY": apiKey})
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("zoomeye: %w", err)
			}
			break
		}
		var r zoomEyeNetResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("zoomeye decode: %w", err)
			}
			break
		}
		if len(r.Matches) == 0 {
			break
		}
		fetched += len(r.Matches)
		for _, m := range r.Matches {
			if m.IP != "" && !seen["i:"+m.IP] {
				seen["i:"+m.IP] = true
				assets = append(assets, makeAsset("ip", m.IP, "", "zoomeye", ""))
			}
			for _, name := range m.Name {
				if name != "" && !seen["d:"+name] {
					seen["d:"+name] = true
					assets = append(assets, makeAsset("domain", name, "", "zoomeye", ""))
				}
			}
		}
		if r.Total > 0 && fetched >= r.Total {
			break
		}
	}
	return assets, nil
}

// ─── 360 Quake ───────────────────────────────────────────────────────────────

type quakeNetResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		IP      string `json:"ip"`
		Domain  string `json:"domain"`
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		} `json:"service"`
	} `json:"data"`
	Meta struct {
		Total int `json:"total"`
	} `json:"meta"`
}

func collectFromQuake(ctx context.Context, query, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	const pageSize = 100

	seen := map[string]bool{}
	var assets []CollectedAsset
	total := -1

	for page := 0; page < netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		b, _ := json.Marshal(map[string]interface{}{"query": query, "start": page * pageSize, "size": pageSize})
		body, err := netPost(ctx, "https://quake.360.net/api/v3/search/quake_service", b,
			map[string]string{"X-QuakeToken": apiKey})
		if err != nil {
			if page == 0 {
				return nil, fmt.Errorf("quake: %w", err)
			}
			break
		}
		var r quakeNetResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 0 {
				return nil, fmt.Errorf("quake decode: %w", err)
			}
			break
		}
		if r.Code != 0 {
			if page == 0 {
				return nil, fmt.Errorf("quake api error %d: %s", r.Code, r.Message)
			}
			break
		}
		if len(r.Data) == 0 {
			break
		}
		if total < 0 {
			total = r.Meta.Total
		}
		for _, d := range r.Data {
			if d.IP != "" && !seen["i:"+d.IP] {
				seen["i:"+d.IP] = true
				assets = append(assets, makeAsset("ip", d.IP, "", "quake", ""))
			}
			if d.Domain != "" && !seen["d:"+d.Domain] {
				seen["d:"+d.Domain] = true
				assets = append(assets, makeAsset("domain", d.Domain, "", "quake", ""))
			}
		}
		if total > 0 && (page+1)*pageSize >= total {
			break
		}
	}
	return assets, nil
}

// ─── 零零信安 (0.zone) ────────────────────────────────────────────────────────

type zeroZoneNetResp struct {
	Data []struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	} `json:"data"`
}

func collectFromZeroZone(ctx context.Context, query, apiKey, ttype string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	qbase := "domain"
	if ttype == "ip" {
		qbase = "ip"
	}
	const pageSize = 100

	seen := map[string]bool{}
	var assets []CollectedAsset

	for page := 1; page <= netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://0.zone/api/aggs?q=%s&qbase=%s&page=%d&pagesize=%d", url.QueryEscape(query), qbase, page, pageSize)
		body, err := netGet(ctx, u, map[string]string{"Authorization": apiKey})
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("zerozone: %w", err)
			}
			break
		}
		var r zeroZoneNetResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("zerozone decode: %w", err)
			}
			break
		}
		if len(r.Data) == 0 {
			break
		}
		for _, d := range r.Data {
			if d.Domain != "" && !seen["d:"+d.Domain] {
				seen["d:"+d.Domain] = true
				assets = append(assets, makeAsset("domain", d.Domain, "", "zerozone", ""))
			}
			if d.IP != "" && !seen["i:"+d.IP] {
				seen["i:"+d.IP] = true
				assets = append(assets, makeAsset("ip", d.IP, "", "zerozone", ""))
			}
		}
		if len(r.Data) < pageSize {
			break // 不足一页，已到末尾
		}
	}
	return assets, nil
}

// ─── Shodan ──────────────────────────────────────────────────────────────────

type shodanSearchResp struct {
	Total   int `json:"total"`
	Matches []struct {
		IPStr     string   `json:"ip_str"`
		Hostnames []string `json:"hostnames"`
		Org       string   `json:"org"`
		Domains   []string `json:"domains"`
	} `json:"matches"`
}

func collectFromShodan(ctx context.Context, query, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var assets []CollectedAsset
	fetched := 0

	for page := 1; page <= netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d", apiKey, url.QueryEscape(query), page)
		body, err := netGet(ctx, u, nil)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("shodan: %w", err)
			}
			break
		}
		var r shodanSearchResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("shodan decode: %w", err)
			}
			break
		}
		if len(r.Matches) == 0 {
			break
		}
		fetched += len(r.Matches)
		for _, m := range r.Matches {
			if m.IPStr != "" && !seen["i:"+m.IPStr] {
				seen["i:"+m.IPStr] = true
				assets = append(assets, makeAsset("ip", m.IPStr, m.Org, "shodan", ""))
			}
			for _, d := range append(m.Hostnames, m.Domains...) {
				if d != "" && !seen["d:"+d] {
					seen["d:"+d] = true
					assets = append(assets, makeAsset("domain", d, m.Org, "shodan", ""))
				}
			}
		}
		if r.Total > 0 && fetched >= r.Total {
			break
		}
	}
	return assets, nil
}

// ─── SecurityTrails ───────────────────────────────────────────────────────────

type stSearchResp struct {
	Records []struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip_address"`
	} `json:"records"`
	Subdomains  []string `json:"subdomains"`
	Total       int      `json:"total"`
	RecordCount int      `json:"record_count"`
}

func collectFromSecurityTrails(ctx context.Context, target, apiKey, ttype string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var assets []CollectedAsset

	if ttype == "domain" {
		// 子域名模式：单次全量返回，无需分页
		u := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=true", target)
		body, err := netGet(ctx, u, map[string]string{"APIKEY": apiKey})
		if err != nil {
			return nil, fmt.Errorf("securitytrails: %w", err)
		}
		var r stSearchResp
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("securitytrails decode: %w", err)
		}
		for _, sub := range r.Subdomains {
			fqdn := sub + "." + target
			if !seen["d:"+fqdn] {
				seen["d:"+fqdn] = true
				assets = append(assets, makeAsset("domain", fqdn, "", "securitytrails", ""))
			}
		}
	} else {
		// 关键词 / 公司模式：分页
		fetched := 0
		for page := 1; page <= netMaxPages; page++ {
			if ctx.Err() != nil {
				break
			}
			u := fmt.Sprintf("https://api.securitytrails.com/v1/domains/search?keyword=%s&page=%d", url.QueryEscape(target), page)
			body, err := netGet(ctx, u, map[string]string{"APIKEY": apiKey})
			if err != nil {
				if page == 1 {
					return nil, fmt.Errorf("securitytrails: %w", err)
				}
				break
			}
			var r stSearchResp
			if err := json.Unmarshal(body, &r); err != nil {
				if page == 1 {
					return nil, fmt.Errorf("securitytrails decode: %w", err)
				}
				break
			}
			if len(r.Records) == 0 {
				break
			}
			fetched += len(r.Records)
			for _, rec := range r.Records {
				if rec.Hostname != "" && !seen["d:"+rec.Hostname] {
					seen["d:"+rec.Hostname] = true
					assets = append(assets, makeAsset("domain", rec.Hostname, "", "securitytrails", ""))
				}
				if rec.IP != "" && !seen["i:"+rec.IP] {
					seen["i:"+rec.IP] = true
					assets = append(assets, makeAsset("ip", rec.IP, "", "securitytrails", ""))
				}
			}
			if r.Total > 0 && fetched >= r.Total {
				break
			}
		}
	}
	return assets, nil
}

// ─── Censys ───────────────────────────────────────────────────────────────────

type censysHostResp struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Result struct {
		Hits []struct {
			IP string `json:"ip"`
			AS struct {
				Name string `json:"name"`
			} `json:"autonomous_system"`
			DNS struct {
				ReverseNames []string `json:"reverse_dns_names"`
			} `json:"dns"`
		} `json:"hits"`
		Links struct {
			Next string `json:"next"` // cursor token，空串表示已到末页
		} `json:"links"`
	} `json:"result"`
}

func collectFromCensys(ctx context.Context, query, apiID, apiSecret string) ([]CollectedAsset, error) {
	if apiID == "" || apiSecret == "" {
		return nil, nil
	}
	creds := base64.StdEncoding.EncodeToString([]byte(apiID + ":" + apiSecret))
	headers := map[string]string{"Authorization": "Basic " + creds}
	seen := map[string]bool{}
	var assets []CollectedAsset
	cursor := ""

	for page := 1; page <= netMaxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s&per_page=100", url.QueryEscape(query))
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		body, err := netGet(ctx, u, headers)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("censys: %w", err)
			}
			break
		}
		var r censysHostResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("censys decode: %w", err)
			}
			break
		}
		if r.Code != 200 && r.Code != 0 {
			if page == 1 {
				return nil, fmt.Errorf("censys api error %d: %s", r.Code, r.Status)
			}
			break
		}
		if len(r.Result.Hits) == 0 {
			break
		}
		for _, h := range r.Result.Hits {
			if h.IP != "" && !seen["i:"+h.IP] {
				seen["i:"+h.IP] = true
				assets = append(assets, makeAsset("ip", h.IP, h.AS.Name, "censys", ""))
			}
			for _, n := range h.DNS.ReverseNames {
				n = strings.TrimRight(n, ".")
				if n != "" && !seen["d:"+n] {
					seen["d:"+n] = true
					assets = append(assets, makeAsset("domain", n, h.AS.Name, "censys", ""))
				}
			}
		}
		cursor = r.Result.Links.Next
		if cursor == "" {
			break // 已到末页
		}
	}
	return assets, nil
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

type vtNetResp struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"` // cursor 分页：下一页完整 URL
	} `json:"links"`
}

func collectFromVirusTotal(ctx context.Context, target, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	nextURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=100", target)
	var assets []CollectedAsset
	seen := map[string]bool{}

	for page := 1; page <= netMaxPages && nextURL != ""; page++ {
		if ctx.Err() != nil {
			break
		}
		body, err := netGet(ctx, nextURL, map[string]string{"x-apikey": apiKey})
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("virustotal: %w", err)
			}
			break
		}
		var r vtNetResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("virustotal decode: %w", err)
			}
			break
		}
		if len(r.Data) == 0 {
			break
		}
		for _, d := range r.Data {
			if d.ID != "" && !seen["d:"+d.ID] {
				seen["d:"+d.ID] = true
				assets = append(assets, makeAsset("domain", d.ID, "", "virustotal", ""))
			}
		}
		nextURL = r.Links.Next
	}
	return assets, nil
}

// ─── Chaos (ProjectDiscovery) ─────────────────────────────────────────────────

type chaosNetResp struct {
	Subdomains []string `json:"subdomains"`
}

func collectFromChaos(ctx context.Context, domain, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	u := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain)
	body, err := netGet(ctx, u, map[string]string{"Authorization": apiKey})
	if err != nil {
		return nil, fmt.Errorf("chaos: %w", err)
	}
	var r chaosNetResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("chaos decode: %w", err)
	}
	var assets []CollectedAsset
	for _, sub := range r.Subdomains {
		if sub != "" {
			assets = append(assets, makeAsset("domain", sub+"."+domain, "", "chaos", ""))
		}
	}
	return assets, nil
}

// ─── 微步在线 ThreatBook ──────────────────────────────────────────────────────

type tbNetResp struct {
	SubDomains struct {
		Data []string `json:"data"`
	} `json:"sub_domains"`
	RelatedAttackDomains []struct {
		Domain string `json:"domain"`
	} `json:"related_attack_domains"`
}

func collectFromThreatBook(ctx context.Context, target, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	u := fmt.Sprintf("https://api.threatbook.cn/v1/domain/sub_domains?domain=%s&apikey=%s", target, apiKey)
	body, err := netGet(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("threatbook: %w", err)
	}
	var r tbNetResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("threatbook decode: %w", err)
	}
	seen := map[string]bool{}
	var assets []CollectedAsset
	for _, d := range r.SubDomains.Data {
		if d != "" && !seen[d] {
			seen[d] = true
			assets = append(assets, makeAsset("domain", d, "", "threatbook", ""))
		}
	}
	for _, a := range r.RelatedAttackDomains {
		if a.Domain != "" && !seen[a.Domain] {
			seen[a.Domain] = true
			assets = append(assets, makeAsset("domain", a.Domain, "", "threatbook", ""))
		}
	}
	return assets, nil
}

// ─── crt.sh (证书透明度) ──────────────────────────────────────────────────────
//
// crt.sh 是免费的 SSL 证书透明度日志聚合服务，无需 API Key。
// 通过查询证书 SAN/CN 字段，可发现大量未在其他情报源出现的子域名。
// 仅在 domain 模式下调用，company/ip/keyword 模式无意义。

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

func collectFromCRTSH(ctx context.Context, domain string) ([]CollectedAsset, error) {
	u := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", url.QueryEscape(domain))
	body, err := netGet(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: %w", err)
	}
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crtsh decode: %w", err)
	}
	seen := map[string]bool{}
	var assets []CollectedAsset
	for _, e := range entries {
		// name_value 内多条 SAN 用换行分隔
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.TrimPrefix(strings.TrimSpace(raw), "*.")
			if name == "" || !strings.Contains(name, ".") {
				continue
			}
			// 只保留目标域名下的子域（防止无关证书污染结果）
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			assets = append(assets, makeAsset("domain", name, "", "crtsh", ""))
		}
	}
	return assets, nil
}

// ─── Shodan DNS 子域名端点 ──────────────────────────────────────────────────────
//
// /dns/domain/{domain} 返回 Shodan 被动 DNS 数据库中已知的子域名列表，
// 与常规 Shodan 搜索互补（后者偏向开放端口，前者偏向 DNS 历史记录）。
// 仅 domain 模式下调用，复用已有 ShodanKey，不额外占用配额类型。

type shodanDNSResp struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	More       bool     `json:"more"`
}

func collectFromShodanDNS(ctx context.Context, domain, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	u := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", url.QueryEscape(domain), apiKey)
	body, err := netGet(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan-dns: %w", err)
	}
	var r shodanDNSResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("shodan-dns decode: %w", err)
	}
	seen := map[string]bool{}
	var assets []CollectedAsset
	for _, sub := range r.Subdomains {
		if sub == "" {
			continue
		}
		fqdn := sub + "." + domain
		if !seen["d:"+fqdn] {
			seen["d:"+fqdn] = true
			assets = append(assets, makeAsset("domain", fqdn, "", "shodan", ""))
		}
	}
	return assets, nil
}

// ─── AlienVault OTX (被动 DNS) ────────────────────────────────────────────────
//
// OTX 免费公开 API，无需 Key，被动 DNS 数据来自全球威胁情报社区。
// 仅 domain 模式，最多 3 页（每页 500 条），has_next=false 时提前退出。

type otxPassiveDNSResp struct {
	PassiveDNS []struct {
		Address    string `json:"address"`
		Hostname   string `json:"hostname"`
		RecordType string `json:"record_type"`
	} `json:"passive_dns"`
	Count   int  `json:"count"`
	HasNext bool `json:"has_next"`
}

func collectFromOTX(ctx context.Context, domain string) ([]CollectedAsset, error) {
	seen := map[string]bool{}
	var assets []CollectedAsset

	for page := 1; page <= 3; page++ {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns?limit=500&page=%d",
			url.QueryEscape(domain), page)
		body, err := netGet(ctx, u, nil)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("otx: %w", err)
			}
			break
		}
		var r otxPassiveDNSResp
		if err := json.Unmarshal(body, &r); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("otx decode: %w", err)
			}
			break
		}
		if len(r.PassiveDNS) == 0 {
			break
		}
		for _, rec := range r.PassiveDNS {
			if rec.Hostname != "" && !seen["d:"+rec.Hostname] {
				seen["d:"+rec.Hostname] = true
				assets = append(assets, makeAsset("domain", rec.Hostname, "", "otx", ""))
			}
			if rec.Address != "" && rec.RecordType == "A" && !seen["i:"+rec.Address] {
				seen["i:"+rec.Address] = true
				assets = append(assets, makeAsset("ip", rec.Address, "", "otx", ""))
			}
		}
		if !r.HasNext {
			break
		}
	}
	return assets, nil
}

// ─── HackerTarget ─────────────────────────────────────────────────────────────
//
// 免费无需 Key，返回 CSV 格式（hostname,ip）最多 100 条。
// 作为快速补充源，结果有限但无配额消耗。domain 模式下始终调用。

func collectFromHackerTarget(ctx context.Context, domain string) ([]CollectedAsset, error) {
	u := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	body, err := netGet(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	// 免费额度超限时返回 JSON 错误，如 {"error":"API count exceeded"}
	raw := strings.TrimSpace(string(body))
	if strings.HasPrefix(raw, "{") {
		return nil, fmt.Errorf("hackertarget: %s", raw)
	}
	seen := map[string]bool{}
	var assets []CollectedAsset
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 2 {
			continue
		}
		host, ip := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if host != "" && !seen["d:"+host] {
			seen["d:"+host] = true
			assets = append(assets, makeAsset("domain", host, "", "hackertarget", ""))
		}
		if ip != "" && !seen["i:"+ip] {
			seen["i:"+ip] = true
			assets = append(assets, makeAsset("ip", ip, "", "hackertarget", ""))
		}
	}
	return assets, nil
}
