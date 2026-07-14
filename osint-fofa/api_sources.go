package osintfofa

// api_sources.go —— 各空间测绘平台 API 查询实现。
//
// 支持平台：FOFA / Hunter（奇安信鹰图）/ Shodan / ZoomEye / Quake 360
// 统一返回 []Asset，各平台错误独立处理，失败只记录警告不影响其他平台。
// 结果按 ip:port 去重后聚合返回。

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"redops/core"
)

const (
	// apiMaxBody 限制单次 API 响应最大读取字节数（1 MB），防止超大响应占用内存。
	apiMaxBody = 1 * 1024 * 1024

	// fofaAPIURL 使用 fofa.icu 中转站，不消耗 F 点，无需 email，VIP999 免费额度。
	fofaAPIURL     = "http://fofa.icu/api/v1/search/all"
	defaultFOFAKey = "3cf1e8a6dfeb52aff9ab7b49dfa18fc9"
)

// Asset 是空间测绘查询结果中的单条资产记录，多平台共用此结构。
type Asset struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"` // http / https / ssh / ftp 等
	Title    string `json:"title"`
	Banner   string `json:"banner"`
	Country  string `json:"country"`
	City     string `json:"city"`
	OS       string `json:"os"`
	Source   string `json:"source"` // fofa / hunter / shodan / zoomeye
}

// queryOptions 是 "query" 功能的完整参数结构，支持各平台独立查询语句与 key 覆盖。
type queryOptions struct {
	Platform     string `json:"platform"`     // fofa / hunter / shodan / zoomeye / quake / all
	FOFAQuery    string `json:"fofaQuery"`
	HunterQuery  string `json:"hunterQuery"`
	ShodanQuery  string `json:"shodanQuery"`
	ZoomEyeQuery string `json:"zoomeyeQuery"`
	QuakeQuery   string `json:"quakeQuery"`
	PageSize     int    `json:"pageSize"`
	// API Keys 覆盖（优先级高于 settings 表中的配置）
	FOFAEmail  string `json:"fofaEmail"`
	FOFAKey    string `json:"fofaKey"`
	HunterKey  string `json:"hunterKey"`
	ShodanKey  string `json:"shodanKey"`
	ZoomEyeKey string `json:"zoomeyeKey"`
	QuakeKey   string `json:"quakeKey"`
}

// progressFunc 是进度回调签名，pct 为 0~100 的整数百分比，msg 为描述文字。
type progressFunc func(pct int, msg string)

// newAPIClient 返回带超时的 HTTP 客户端，跳过 TLS 证书验证（被测目标环境）。
func newAPIClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 被测目标环境需要跳过证书验证
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// runQuery 是查询总入口，根据 platform 参数分发到单个平台或聚合查询，并去重返回。
func runQuery(ctx context.Context, opts queryOptions, progressFn progressFunc, log core.Logger) ([]Asset, error) {
	var assets []Asset
	var err error

	switch opts.Platform {
	case "fofa":
		progressFn(10, "正在请求 FOFA…")
		fofaKey := opts.FOFAKey
		if fofaKey == "" {
			fofaKey = defaultFOFAKey
		}
		assets, err = queryFOFA(ctx, opts.FOFAQuery, opts.PageSize, opts.FOFAEmail, fofaKey)
		if err != nil {
			log.Warn("FOFA 查询失败", "err", err)
			return nil, fmt.Errorf("FOFA 查询失败")
		}
		progressFn(90, fmt.Sprintf("FOFA 返回 %d 条资产", len(assets)))

	case "hunter":
		progressFn(10, "正在请求 Hunter…")
		assets, err = queryHunter(ctx, opts.HunterQuery, opts.PageSize, opts.HunterKey)
		if err != nil {
			log.Warn("Hunter 查询失败", "err", err)
			return nil, fmt.Errorf("Hunter 查询失败")
		}
		progressFn(90, fmt.Sprintf("Hunter 返回 %d 条资产", len(assets)))

	case "shodan":
		progressFn(10, "正在请求 Shodan…")
		assets, err = queryShodan(ctx, opts.ShodanQuery, opts.PageSize, opts.ShodanKey)
		if err != nil {
			log.Warn("Shodan 查询失败", "err", err)
			return nil, fmt.Errorf("Shodan 查询失败")
		}
		progressFn(90, fmt.Sprintf("Shodan 返回 %d 条资产", len(assets)))

	case "zoomeye":
		progressFn(10, "正在请求 ZoomEye…")
		assets, err = queryZoomEye(ctx, opts.ZoomEyeQuery, opts.PageSize, opts.ZoomEyeKey)
		if err != nil {
			log.Warn("ZoomEye 查询失败", "err", err)
			return nil, fmt.Errorf("ZoomEye 查询失败")
		}
		progressFn(90, fmt.Sprintf("ZoomEye 返回 %d 条资产", len(assets)))

	case "quake":
		progressFn(10, "正在请求 Quake 360…")
		assets, err = queryQuake(ctx, opts.QuakeQuery, opts.PageSize, opts.QuakeKey)
		if err != nil {
			log.Warn("Quake 查询失败", "err", err)
			return nil, fmt.Errorf("Quake 查询失败")
		}
		progressFn(90, fmt.Sprintf("Quake 返回 %d 条资产", len(assets)))

	case "all":
		assets = runAllPlatforms(ctx, opts, progressFn, log)

	default:
		return nil, fmt.Errorf("不支持的平台: %s", opts.Platform)
	}

	// 按 ip:port 去重（多平台聚合时可能出现重复记录）
	deduped := deduplicateAssets(assets)
	progressFn(95, fmt.Sprintf("去重完成，共 %d 条唯一资产", len(deduped)))
	return deduped, nil
}

// runAllPlatforms 并发调用所有已配置平台，汇总结果（任一平台失败仅记录警告）。
func runAllPlatforms(ctx context.Context, opts queryOptions, progressFn progressFunc, log core.Logger) []Asset {
	type result struct {
		assets []Asset
		err    error
		name   string
	}

	// 先计数，再按实际数量创建 channel，避免 goroutine 因 channel 满而永久阻塞
	// FOFA：key 为空时回落到内置默认 key（fofa.icu 中转），email 可选
	resolvedFOFAKey := opts.FOFAKey
	if resolvedFOFAKey == "" {
		resolvedFOFAKey = defaultFOFAKey
	}
	callCount := 0
	if resolvedFOFAKey != "" && opts.FOFAQuery != "" {
		callCount++
	}
	if opts.HunterKey != "" && opts.HunterQuery != "" {
		callCount++
	}
	if opts.ShodanKey != "" && opts.ShodanQuery != "" {
		callCount++
	}
	if opts.ZoomEyeKey != "" && opts.ZoomEyeQuery != "" {
		callCount++
	}
	if opts.QuakeKey != "" && opts.QuakeQuery != "" {
		callCount++
	}

	if callCount == 0 {
		log.Warn("osint-fofa 全平台聚合：未配置任何平台 API Key 或查询语句，请在设置页面填写后重试")
		return nil
	}

	ch := make(chan result, callCount)
	var wg sync.WaitGroup

	// FOFA：使用 resolvedFOFAKey（已在计数时回落到内置默认 key）
	if resolvedFOFAKey != "" && opts.FOFAQuery != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := queryFOFA(ctx, opts.FOFAQuery, opts.PageSize, opts.FOFAEmail, resolvedFOFAKey)
			ch <- result{assets: a, err: e, name: "FOFA"}
		}()
	}

	// Hunter：需要 key 和查询语句
	if opts.HunterKey != "" && opts.HunterQuery != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := queryHunter(ctx, opts.HunterQuery, opts.PageSize, opts.HunterKey)
			ch <- result{assets: a, err: e, name: "Hunter"}
		}()
	}

	// Shodan：需要 key 和查询语句
	if opts.ShodanKey != "" && opts.ShodanQuery != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := queryShodan(ctx, opts.ShodanQuery, opts.PageSize, opts.ShodanKey)
			ch <- result{assets: a, err: e, name: "Shodan"}
		}()
	}

	// ZoomEye：需要 key 和查询语句
	if opts.ZoomEyeKey != "" && opts.ZoomEyeQuery != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := queryZoomEye(ctx, opts.ZoomEyeQuery, opts.PageSize, opts.ZoomEyeKey)
			ch <- result{assets: a, err: e, name: "ZoomEye"}
		}()
	}

	// Quake 360：需要 key 和查询语句
	if opts.QuakeKey != "" && opts.QuakeQuery != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := queryQuake(ctx, opts.QuakeQuery, opts.PageSize, opts.QuakeKey)
			ch <- result{assets: a, err: e, name: "Quake"}
		}()
	}

	// 等待所有 goroutine 结束后关闭 channel
	go func() {
		wg.Wait()
		close(ch)
	}()

	var all []Asset
	done := 0
	for r := range ch {
		done++
		pct := 10 + done*70/callCount
		if r.err != nil {
			log.Warn("osint-fofa 平台查询失败（已忽略）", "platform", r.name, "err", r.err)
			progressFn(pct, fmt.Sprintf("%s 查询失败（已跳过）", r.name))
		} else {
			progressFn(pct, fmt.Sprintf("%s 返回 %d 条资产", r.name, len(r.assets)))
			all = append(all, r.assets...)
		}
		// 检查 context 是否已被取消
		select {
		case <-ctx.Done():
			log.Warn("osint-fofa 全平台查询被取消", "done", done, "total", callCount)
			return all
		default:
		}
	}
	return all
}

// deduplicateAssets 按 ip:port 去重，保留首次出现的记录。
func deduplicateAssets(assets []Asset) []Asset {
	seen := make(map[string]bool, len(assets))
	out := make([]Asset, 0, len(assets))
	for _, a := range assets {
		key := a.IP + ":" + strconv.Itoa(a.Port)
		if !seen[key] {
			seen[key] = true
			out = append(out, a)
		}
	}
	return out
}

// ─── FOFA ───────────────────────────────────────────────────────────────────
//
// API: https://fofa.info/api/v1/search/all
// 认证: email + key（查询参数）
// 查询: qbase64=BASE64(query)，fields 指定返回字段
// 响应: {"results": [["ip","port","domain","protocol","title","country","city"]], "size": N}

type fofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Size    int        `json:"size"`
	Results [][]string `json:"results"`
}

func queryFOFA(ctx context.Context, query string, pageSize int, email, key string) ([]Asset, error) {
	if key == "" {
		key = defaultFOFAKey
	}
	if key == "" {
		return nil, fmt.Errorf("FOFA 未配置 API Key")
	}
	if query == "" {
		return nil, fmt.Errorf("FOFA 查询语句不能为空")
	}
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	// fofa.icu 中转站：不需要 email，不消耗 F 点；email 非空时仍透传（兼容官方接口）
	apiURL := fofaAPIURL
	var url string
	if email != "" {
		url = fmt.Sprintf("%s?email=%s&key=%s&qbase64=%s&fields=ip,port,domain,protocol,title,country,city&page=1&size=%d",
			apiURL, email, key, qb64, pageSize)
	} else {
		url = fmt.Sprintf("%s?key=%s&qbase64=%s&fields=ip,port,domain,protocol,title,country,city&page=1&size=%d",
			apiURL, key, qb64, pageSize)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS-RedOps/1.0")
	resp, err := newAPIClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("FOFA 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBody))
	if err != nil {
		return nil, fmt.Errorf("FOFA 读取响应失败: %w", err)
	}
	var fr fofaResponse
	if err := json.Unmarshal(body, &fr); err != nil {
		return nil, fmt.Errorf("FOFA 响应解析失败: %w", err)
	}
	if fr.Error {
		return nil, fmt.Errorf("FOFA API 返回错误")
	}
	// results 中每行字段顺序与 fields 参数对齐：ip,port,domain,protocol,title,country,city
	assets := make([]Asset, 0, len(fr.Results))
	for _, row := range fr.Results {
		if len(row) < 7 {
			continue
		}
		port, _ := strconv.Atoi(row[1])
		assets = append(assets, Asset{
			IP:       row[0],
			Port:     port,
			Domain:   row[2],
			Protocol: row[3],
			Title:    row[4],
			Country:  row[5],
			City:     row[6],
			Source:   "fofa",
		})
	}
	return assets, nil
}

// ─── Hunter（奇安信鹰图）───────────────────────────────────────────────────────
//
// API: https://hunter.qianxin.com/openApi/search
// 认证: api-key（查询参数）
// 查询: search=BASE64(query)，is_web=3 同时返回 web 与非 web
// 响应: {"code":200,"data":{"arr":[{"ip","port","domain","protocol","web_title","country","province"}]}}

type hunterResponse struct {
	Code int `json:"code"`
	Data struct {
		Arr []struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Domain   string `json:"domain"`
			Protocol string `json:"protocol"`
			Title    string `json:"web_title"`
			Country  string `json:"country"`
			City     string `json:"province"`
		} `json:"arr"`
		Total int `json:"total"`
	} `json:"data"`
	Message string `json:"message"`
}

func queryHunter(ctx context.Context, query string, pageSize int, key string) ([]Asset, error) {
	if key == "" {
		return nil, fmt.Errorf("Hunter 未配置 API Key")
	}
	if query == "" {
		return nil, fmt.Errorf("Hunter 查询语句不能为空")
	}
	searchQ := base64.StdEncoding.EncodeToString([]byte(query))
	url := fmt.Sprintf(
		"https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=%d&is_web=3",
		key, searchQ, pageSize,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS-RedOps/1.0")
	resp, err := newAPIClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("Hunter 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBody))
	if err != nil {
		return nil, fmt.Errorf("Hunter 读取响应失败: %w", err)
	}
	var hr hunterResponse
	if err := json.Unmarshal(body, &hr); err != nil {
		return nil, fmt.Errorf("Hunter 响应解析失败: %w", err)
	}
	if hr.Code != 200 {
		return nil, fmt.Errorf("Hunter API 返回错误（code=%d）", hr.Code)
	}
	assets := make([]Asset, 0, len(hr.Data.Arr))
	for _, item := range hr.Data.Arr {
		assets = append(assets, Asset{
			IP:       item.IP,
			Port:     item.Port,
			Domain:   item.Domain,
			Protocol: item.Protocol,
			Title:    item.Title,
			Country:  item.Country,
			City:     item.City,
			Source:   "hunter",
		})
	}
	return assets, nil
}

// ─── Shodan ──────────────────────────────────────────────────────────────────
//
// API: https://api.shodan.io/shodan/host/search?key=<key>&query=<query>&page=1
// 认证: key（查询参数）
// 响应: {"matches":[{"ip_str","port","hostnames":["..."],"http":{"title"},"location":{"country_name","city"},"data","os"}]}

type shodanResponse struct {
	Matches []struct {
		IPStr     string   `json:"ip_str"`
		Port      int      `json:"port"`
		Hostnames []string `json:"hostnames"`
		HTTP      struct {
			Title string `json:"title"`
		} `json:"http"`
		Location struct {
			CountryName string `json:"country_name"`
			City        string `json:"city"`
		} `json:"location"`
		Data string `json:"data"` // banner 原始数据
		OS   string `json:"os"`
	} `json:"matches"`
	Error string `json:"error"`
}

func queryShodan(ctx context.Context, query string, pageSize int, key string) ([]Asset, error) {
	if key == "" {
		return nil, fmt.Errorf("Shodan 未配置 API Key")
	}
	if query == "" {
		return nil, fmt.Errorf("Shodan 查询语句不能为空")
	}
	// Shodan 免费 key 不支持 minify=true，page 从 1 开始
	url := fmt.Sprintf(
		"https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=1",
		key, query,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AEGIS-RedOps/1.0")
	resp, err := newAPIClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("Shodan 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBody))
	if err != nil {
		return nil, fmt.Errorf("Shodan 读取响应失败: %w", err)
	}
	var sr shodanResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("Shodan 响应解析失败: %w", err)
	}
	if sr.Error != "" {
		return nil, fmt.Errorf("Shodan API 返回错误")
	}
	// 取 hostnames 中第一条作为 domain（若存在）
	assets := make([]Asset, 0, len(sr.Matches))
	for _, m := range sr.Matches {
		domain := ""
		if len(m.Hostnames) > 0 {
			domain = m.Hostnames[0]
		}
		// banner 截断至 512 字符，避免超大响应
		banner := m.Data
		if len(banner) > 512 {
			banner = banner[:512]
		}
		assets = append(assets, Asset{
			IP:      m.IPStr,
			Port:    m.Port,
			Domain:  domain,
			Title:   m.HTTP.Title,
			Banner:  banner,
			Country: m.Location.CountryName,
			City:    m.Location.City,
			OS:      m.OS,
			Source:  "shodan",
		})
	}
	// Shodan 单页默认最多 100 条，此处按 pageSize 截断
	if len(assets) > pageSize {
		assets = assets[:pageSize]
	}
	return assets, nil
}

// ─── Quake 360（奇安信）────────────────────────────────────────────────────────
//
// API: https://quake.360.net/api/v3/search/quake_service
// 认证: X-QuakeToken 请求头
// 请求: POST JSON {"query":"...","start":0,"size":N,"latest":true}
// 响应: {"code":0,"data":[{"ip":"...","port":...,"hostname":"...","service":{"name":"http","http":{"title":"..."},"banner":"..."},"location":{"country_cn":"...","province_cn":"...","city_cn":"..."}}]}

type quakeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Hostname string `json:"hostname"`
		Service  struct {
			Name string `json:"name"`
			HTTP struct {
				Title string `json:"title"`
			} `json:"http"`
			Banner string `json:"banner"`
		} `json:"service"`
		Location struct {
			CountryCN  string `json:"country_cn"`
			ProvinceCN string `json:"province_cn"`
			CityCN     string `json:"city_cn"`
		} `json:"location"`
	} `json:"data"`
}

func queryQuake(ctx context.Context, query string, pageSize int, token string) ([]Asset, error) {
	if token == "" {
		return nil, fmt.Errorf("Quake 未配置 Token")
	}
	if query == "" {
		return nil, fmt.Errorf("Quake 查询语句不能为空")
	}
	if pageSize > 500 {
		pageSize = 500
	}

	reqBody, err := json.Marshal(map[string]any{
		"query":  query,
		"start":  0,
		"size":   pageSize,
		"latest": true,
	})
	if err != nil {
		return nil, fmt.Errorf("Quake 请求构建失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://quake.360.net/api/v3/search/quake_service",
		strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-QuakeToken", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AEGIS-RedOps/1.0")

	resp, err := newAPIClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("Quake 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBody))
	if err != nil {
		return nil, fmt.Errorf("Quake 读取响应失败: %w", err)
	}
	var qr quakeResponse
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("Quake 响应解析失败: %w", err)
	}
	if qr.Code != 0 {
		return nil, fmt.Errorf("Quake API 返回错误（code=%d）: %s", qr.Code, qr.Message)
	}

	assets := make([]Asset, 0, len(qr.Data))
	for _, item := range qr.Data {
		banner := item.Service.Banner
		if len(banner) > 512 {
			banner = banner[:512]
		}
		city := item.Location.CityCN
		if city == "" {
			city = item.Location.ProvinceCN
		}
		assets = append(assets, Asset{
			IP:       item.IP,
			Port:     item.Port,
			Domain:   item.Hostname,
			Protocol: item.Service.Name,
			Title:    item.Service.HTTP.Title,
			Banner:   banner,
			Country:  item.Location.CountryCN,
			City:     city,
			Source:   "quake",
		})
	}
	return assets, nil
}

// ─── ZoomEye（钟馗之眼）─────────────────────────────────────────────────────────
//
// API: https://api.zoomeye.org/host/search?query=<query>&page=1
// 认证: API-KEY 请求头
// 响应: {"matches":[{"ip","portinfo":{"port","service","banner"},"rdns":["..."],"geoinfo":{"country":{"names":{"zh-CN":"..."}},"city":{"names":{"zh-CN":"..."}}}}]}

type zoomEyeResponse struct {
	Matches []struct {
		IP       string   `json:"ip"`
		PortInfo struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
			Banner  string `json:"banner"`
		} `json:"portinfo"`
		RDNS    []string `json:"rdns"`
		GeoInfo struct {
			Country struct {
				Names map[string]string `json:"names"`
			} `json:"country"`
			City struct {
				Names map[string]string `json:"names"`
			} `json:"city"`
		} `json:"geoinfo"`
	} `json:"matches"`
	Error string `json:"error"`
}

func queryZoomEye(ctx context.Context, query string, pageSize int, key string) ([]Asset, error) {
	if key == "" {
		return nil, fmt.Errorf("ZoomEye 未配置 API Key")
	}
	if query == "" {
		return nil, fmt.Errorf("ZoomEye 查询语句不能为空")
	}
	url := fmt.Sprintf("https://api.zoomeye.org/host/search?query=%s&page=1", query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-KEY", key)
	req.Header.Set("User-Agent", "AEGIS-RedOps/1.0")
	resp, err := newAPIClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ZoomEye 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBody))
	if err != nil {
		return nil, fmt.Errorf("ZoomEye 读取响应失败: %w", err)
	}
	var zr zoomEyeResponse
	if err := json.Unmarshal(body, &zr); err != nil {
		return nil, fmt.Errorf("ZoomEye 响应解析失败: %w", err)
	}
	if zr.Error != "" {
		return nil, fmt.Errorf("ZoomEye API 返回错误")
	}
	assets := make([]Asset, 0, len(zr.Matches))
	for _, m := range zr.Matches {
		domain := ""
		if len(m.RDNS) > 0 {
			domain = m.RDNS[0]
		}
		// 优先读取中文地名，回退到英文
		country := m.GeoInfo.Country.Names["zh-CN"]
		if country == "" {
			country = m.GeoInfo.Country.Names["en"]
		}
		city := m.GeoInfo.City.Names["zh-CN"]
		if city == "" {
			city = m.GeoInfo.City.Names["en"]
		}
		banner := m.PortInfo.Banner
		if len(banner) > 512 {
			banner = banner[:512]
		}
		assets = append(assets, Asset{
			IP:       m.IP,
			Port:     m.PortInfo.Port,
			Domain:   domain,
			Protocol: m.PortInfo.Service,
			Banner:   banner,
			Country:  country,
			City:     city,
			Source:   "zoomeye",
		})
	}
	if len(assets) > pageSize {
		assets = assets[:pageSize]
	}
	return assets, nil
}
