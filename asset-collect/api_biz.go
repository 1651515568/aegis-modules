package assetcollect

// api_biz.go — 企业情报源：天眼查 / 企查查 / 爱企查 / 小蓝本 / 七麦数据 / 风鸟
// 每个函数接受公司名或关键词，返回 []CollectedAsset（domain / app / icp / company 类型）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ─── 天眼查 ───────────────────────────────────────────────────────────────────
//
// 文档: https://open.tianyancha.com/open
// 认证: Authorization: <token>（Bearer 格式）
// 流程: 搜索公司 → 取第一条 ID → 并行查 ICP 域名 + App

type tycSearchResp struct {
	State string `json:"state"`
	Data  struct {
		Items []struct {
			ID   json.Number `json:"id"`
			Name string      `json:"name"`
		} `json:"items"`
	} `json:"data"`
}

type tycICPResp struct {
	State string `json:"state"`
	Data  struct {
		Items []struct {
			Domain  string `json:"domain"`
			IcpNo   string `json:"icpNo"`
			WebName string `json:"webName"`
		} `json:"items"`
	} `json:"data"`
}

type tycAppResp struct {
	State string `json:"state"`
	Data  struct {
		Items []struct {
			Name     string `json:"name"`
			Platform string `json:"platform"` // android | ios
			BundleID string `json:"bundleId"`
		} `json:"items"`
	} `json:"data"`
}

func collectFromTianYanCha(ctx context.Context, companyName, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"Authorization": apiKey}

	// 1. 搜索公司
	searchURL := fmt.Sprintf("https://api.tianyancha.com/services/v4/open/companyFuzzySearch?word=%s&pageNum=1&pageSize=5", url.QueryEscape(companyName))
	body, err := netGet(ctx, searchURL, hdr)
	if err != nil {
		return nil, fmt.Errorf("tianyancha search: %w", err)
	}
	var sr tycSearchResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("tianyancha decode: %w", err)
	}
	if sr.State != "ok" {
		return nil, fmt.Errorf("tianyancha api error: state=%s", sr.State)
	}
	if len(sr.Data.Items) == 0 {
		return nil, nil
	}
	companyID := sr.Data.Items[0].ID.String()
	orgName := sr.Data.Items[0].Name

	var assets []CollectedAsset

	// 2. 查 ICP 备案域名
	icpURL := fmt.Sprintf("https://api.tianyancha.com/services/v4/open/companyIcpInfo?id=%s&pageNum=1&pageSize=100", companyID)
	if icpBody, err := netGet(ctx, icpURL, hdr); err == nil {
		var ir tycICPResp
		if err := json.Unmarshal(icpBody, &ir); err == nil && ir.State == "ok" {
			for _, item := range ir.Data.Items {
				if item.Domain != "" {
					assets = append(assets, makeAsset("domain", item.Domain, orgName, "tianyancha",
						fmt.Sprintf(`{"icpNo":%q,"webName":%q}`, item.IcpNo, item.WebName)))
					assets = append(assets, CollectedAsset{
						Type: "icp", Value: item.IcpNo, Org: orgName, Source: "tianyancha",
						Meta: fmt.Sprintf(`{"domain":%q,"webName":%q}`, item.Domain, item.WebName),
					})
				}
			}
		}
	}

	// 3. 查移动 App
	appURL := fmt.Sprintf("https://api.tianyancha.com/services/v4/open/companyApp?id=%s&pageNum=1&pageSize=50", companyID)
	if appBody, err := netGet(ctx, appURL, hdr); err == nil {
		var ar tycAppResp
		if err := json.Unmarshal(appBody, &ar); err == nil && ar.State == "ok" {
			for _, item := range ar.Data.Items {
				if item.Name != "" {
					assets = append(assets, makeAsset("app", item.Name, orgName, "tianyancha",
						fmt.Sprintf(`{"platform":%q,"bundleId":%q}`, item.Platform, item.BundleID)))
				}
			}
		}
	}

	return assets, nil
}

// ─── 企查查 ───────────────────────────────────────────────────────────────────
//
// 文档: https://openapi.qcc.com/
// 认证: Token: <key>（请求头）
// 流程: 搜索公司 → 取 KeyNo → 查 ICP 信息

type qccSearchResp struct {
	Status string `json:"Status"`
	Result struct {
		Result []struct {
			KeyNo string `json:"KeyNo"`
			Name  string `json:"Name"`
		} `json:"Result"`
	} `json:"Result"`
}

type qccICPResp struct {
	Status string `json:"Status"`
	Result []struct {
		Domain string `json:"Domain"`
		IcpNo  string `json:"IcpNo"`
		SiteName string `json:"SiteName"`
	} `json:"Result"`
}

type qccAppResp struct {
	Status string `json:"Status"`
	Result []struct {
		AppName  string `json:"AppName"`
		Platform string `json:"Platform"`
		BundleID string `json:"BundleID"`
	} `json:"Result"`
}

func collectFromQCC(ctx context.Context, companyName, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"Token": apiKey}

	searchURL := fmt.Sprintf("https://api.qichacha.com/ECIV4GetBasicDetailsByName?key=%s&keyword=%s&pageIndex=1&pageSize=5", apiKey, url.QueryEscape(companyName))
	body, err := netGet(ctx, searchURL, hdr)
	if err != nil {
		return nil, fmt.Errorf("qcc search: %w", err)
	}
	var sr qccSearchResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("qcc decode: %w", err)
	}
	if sr.Status != "200" {
		return nil, fmt.Errorf("qcc api error: status=%s", sr.Status)
	}
	if len(sr.Result.Result) == 0 {
		return nil, nil
	}
	keyNo := sr.Result.Result[0].KeyNo
	orgName := sr.Result.Result[0].Name

	var assets []CollectedAsset

	// ICP 备案
	icpURL := fmt.Sprintf("https://api.qichacha.com/EciIcpInfo?key=%s&id=%s&pageIndex=1", apiKey, keyNo)
	if icpBody, err := netGet(ctx, icpURL, hdr); err == nil {
		var ir qccICPResp
		if err := json.Unmarshal(icpBody, &ir); err == nil && ir.Status == "200" {
			for _, item := range ir.Result {
				if item.Domain != "" {
					assets = append(assets, makeAsset("domain", item.Domain, orgName, "qcc",
						fmt.Sprintf(`{"icpNo":%q,"siteName":%q}`, item.IcpNo, item.SiteName)))
				}
			}
		}
	}

	// App
	appURL := fmt.Sprintf("https://api.qichacha.com/ECICompanyApp?key=%s&id=%s&pageIndex=1&pageSize=50", apiKey, keyNo)
	if appBody, err := netGet(ctx, appURL, hdr); err == nil {
		var ar qccAppResp
		if err := json.Unmarshal(appBody, &ar); err == nil && ar.Status == "200" {
			for _, item := range ar.Result {
				if item.AppName != "" {
					assets = append(assets, makeAsset("app", item.AppName, orgName, "qcc",
						fmt.Sprintf(`{"platform":%q,"bundleId":%q}`, item.Platform, item.BundleID)))
				}
			}
		}
	}

	return assets, nil
}

// ─── 爱企查 (百度) ───────────────────────────────────────────────────────────
//
// 认证: X-API-KEY: <key>
// 接口: https://api.aiqicha.com/v1/

type aiqichaSearchResp struct {
	Errno  int    `json:"errno"`
	ErrMsg string `json:"errmsg"`
	Data   struct {
		List []struct {
			PID      string `json:"pid"`
			Name     string `json:"name"`
			WebSite  string `json:"webSite"`
		} `json:"list"`
	} `json:"data"`
}

type aiqichaICPResp struct {
	Errno int    `json:"errno"`
	Data  struct {
		List []struct {
			Domain  string `json:"domain"`
			IcpNo   string `json:"icpNum"`
			SiteName string `json:"siteName"`
		} `json:"list"`
	} `json:"data"`
}

func collectFromAiQiCha(ctx context.Context, companyName, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"X-API-KEY": apiKey}

	searchURL := fmt.Sprintf("https://api.aiqicha.com/v1/company/search?keyword=%s&pageIndex=1&pageSize=5", url.QueryEscape(companyName))
	body, err := netGet(ctx, searchURL, hdr)
	if err != nil {
		return nil, fmt.Errorf("aiqicha search: %w", err)
	}
	var sr aiqichaSearchResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("aiqicha decode: %w", err)
	}
	if sr.Errno != 0 {
		return nil, fmt.Errorf("aiqicha api error %d: %s", sr.Errno, sr.ErrMsg)
	}
	if len(sr.Data.List) == 0 {
		return nil, nil
	}
	pid := sr.Data.List[0].PID
	orgName := sr.Data.List[0].Name

	var assets []CollectedAsset
	// 主网站
	if ws := sr.Data.List[0].WebSite; ws != "" {
		ws = strings.TrimPrefix(strings.TrimPrefix(ws, "https://"), "http://")
		ws = strings.TrimRight(ws, "/")
		assets = append(assets, makeAsset("domain", ws, orgName, "aiqicha", ""))
	}

	// ICP 备案
	icpURL := fmt.Sprintf("https://api.aiqicha.com/v1/company/icp?pid=%s&pageIndex=1&pageSize=100", pid)
	if icpBody, err := netGet(ctx, icpURL, hdr); err == nil {
		var ir aiqichaICPResp
		if err := json.Unmarshal(icpBody, &ir); err == nil && ir.Errno == 0 {
			for _, item := range ir.Data.List {
				if item.Domain != "" {
					assets = append(assets, makeAsset("domain", item.Domain, orgName, "aiqicha",
						fmt.Sprintf(`{"icpNo":%q,"siteName":%q}`, item.IcpNo, item.SiteName)))
				}
			}
		}
	}

	return assets, nil
}

// ─── 小蓝本 ───────────────────────────────────────────────────────────────────
//
// 小蓝本（xiaolanben.com）企业数据平台
// 认证: Authorization: Bearer <key>

type xlbSearchResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		List []struct {
			CompID  string `json:"compId"`
			Name    string `json:"name"`
			Website string `json:"website"`
			IcpNo   string `json:"icpNo"`
		} `json:"list"`
	} `json:"data"`
}

func collectFromXiaoLanBen(ctx context.Context, companyName, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"Authorization": "Bearer " + apiKey}

	searchURL := fmt.Sprintf("https://api.xiaolanben.com/openapi/v2/company/search?keyword=%s&pageIndex=1&pageSize=10", url.QueryEscape(companyName))
	body, err := netGet(ctx, searchURL, hdr)
	if err != nil {
		return nil, fmt.Errorf("xiaolanben: %w", err)
	}
	var r xlbSearchResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("xiaolanben decode: %w", err)
	}
	if r.Code != 0 {
		return nil, fmt.Errorf("xiaolanben api error %d: %s", r.Code, r.Msg)
	}
	var assets []CollectedAsset
	for _, item := range r.Data.List {
		orgName := item.Name
		if item.Website != "" {
			ws := strings.TrimPrefix(strings.TrimPrefix(item.Website, "https://"), "http://")
			ws = strings.TrimRight(ws, "/")
			assets = append(assets, makeAsset("domain", ws, orgName, "xiaolanben",
				fmt.Sprintf(`{"icpNo":%q}`, item.IcpNo)))
		}
	}
	return assets, nil
}

// ─── 七麦数据 ─────────────────────────────────────────────────────────────────
//
// 七麦数据（qimai.cn）App Store 情报
// 认证: X-Token: <key>
// 返回: iOS / Android App 列表

type qimaiSearchResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		List []struct {
			AppID     string `json:"appId"`
			Name      string `json:"name"`
			Developer string `json:"developer"`
			Platform  string `json:"platform"`
			Icon      string `json:"icon"`
		} `json:"list"`
	} `json:"data"`
}

func collectFromQiMai(ctx context.Context, keyword, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"X-Token": apiKey}

	// iOS + Android 各查一次
	var assets []CollectedAsset
	for _, device := range []string{"iphone", "android"} {
		b, _ := json.Marshal(map[string]interface{}{
			"keyword": keyword, "country": "cn", "page": 1, "device": device,
		})
		body, err := netPost(ctx, "https://api.qimai.cn/search/app", b, hdr)
		if err != nil {
			continue
		}
		var r qimaiSearchResp
		if err := json.Unmarshal(body, &r); err != nil {
			continue
		}
		for _, item := range r.Data.List {
			if item.Name != "" {
				platform := item.Platform
				if platform == "" {
					platform = device
				}
				assets = append(assets, makeAsset("app", item.Name, item.Developer, "qimai",
					fmt.Sprintf(`{"appId":%q,"platform":%q,"icon":%q}`, item.AppID, platform, item.Icon)))
			}
		}
	}
	return assets, nil
}

// ─── 风鸟情报 ─────────────────────────────────────────────────────────────────
//
// 风鸟（fengniao）企业数字资产情报平台
// 认证: X-Api-Key: <key>

type fengniaResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Domains []struct {
			Domain string `json:"domain"`
			Org    string `json:"org"`
		} `json:"domains"`
		IPs []struct {
			IP  string `json:"ip"`
			Org string `json:"org"`
		} `json:"ips"`
		Apps []struct {
			Name     string `json:"name"`
			Platform string `json:"platform"`
		} `json:"apps"`
	} `json:"data"`
}

func collectFromFengNiao(ctx context.Context, keyword, apiKey string) ([]CollectedAsset, error) {
	if apiKey == "" {
		return nil, nil
	}
	u := fmt.Sprintf("https://api.fengniao.io/v1/asset/search?keyword=%s&page=1&size=100", url.QueryEscape(keyword))
	body, err := netGet(ctx, u, map[string]string{"X-Api-Key": apiKey})
	if err != nil {
		return nil, fmt.Errorf("fengniao: %w", err)
	}
	var r fengniaResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("fengniao decode: %w", err)
	}
	if r.Code != 0 {
		return nil, fmt.Errorf("fengniao api error %d: %s", r.Code, r.Msg)
	}
	var assets []CollectedAsset
	for _, d := range r.Data.Domains {
		if d.Domain != "" {
			assets = append(assets, makeAsset("domain", d.Domain, d.Org, "fengniao", ""))
		}
	}
	for _, ip := range r.Data.IPs {
		if ip.IP != "" {
			assets = append(assets, makeAsset("ip", ip.IP, ip.Org, "fengniao", ""))
		}
	}
	for _, app := range r.Data.Apps {
		if app.Name != "" {
			assets = append(assets, makeAsset("app", app.Name, "", "fengniao",
				fmt.Sprintf(`{"platform":%q}`, app.Platform)))
		}
	}
	return assets, nil
}

// ─── 子公司发现 ───────────────────────────────────────────────────────────────
//
// 通过天眼查/企查查查询目标公司持股 ≥51% 的子公司，扩展红队资产边界。
// 返回的 SubsidiaryInfo 由 scanner.go 的 collectSubsidiaries() 统一使用。

// SubsidiaryInfo 记录一条持股关系。
type SubsidiaryInfo struct {
	Name       string  // 子公司名称
	Ownership  float64 // 持股比例 0-100
	ParentName string  // 母公司名称
}

// parsePercent 把 "75.68%" / "75.68" 解析为 float64。
func parsePercent(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// ── 天眼查子公司发现 ──────────────────────────────────────────────────────────

type tycInvestResp struct {
	State string `json:"state"`
	Data  struct {
		Total int `json:"total"`
		Items []struct {
			ID      json.Number `json:"id"`
			Name    string      `json:"name"`
			Percent string      `json:"percent"` // 例 "71.68%"
		} `json:"items"`
	} `json:"data"`
}

// discoverSubsidiariesFromTYC 先用天眼查搜索公司，再查其对外投资列表，
// 返回持股比例 ≥51% 的子公司。
func discoverSubsidiariesFromTYC(ctx context.Context, companyName, apiKey string) ([]SubsidiaryInfo, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"Authorization": apiKey}

	// Step 1: 模糊搜索公司，取第一条 ID
	body, err := netGet(ctx,
		fmt.Sprintf("https://api.tianyancha.com/services/v4/open/companyFuzzySearch?word=%s&pageNum=1&pageSize=5",
			url.QueryEscape(companyName)), hdr)
	if err != nil {
		return nil, fmt.Errorf("tianyancha subsidiary search: %w", err)
	}
	var sr tycSearchResp
	if err := json.Unmarshal(body, &sr); err != nil || sr.State != "ok" || len(sr.Data.Items) == 0 {
		return nil, nil
	}
	companyID := sr.Data.Items[0].ID.String()

	// Step 2: 查对外投资/持股列表
	body, err = netGet(ctx,
		fmt.Sprintf("https://api.tianyancha.com/services/v4/open/companyInvestment?id=%s&pageNum=1&pageSize=100",
			companyID), hdr)
	if err != nil {
		return nil, fmt.Errorf("tianyancha investment: %w", err)
	}
	var ir tycInvestResp
	if err := json.Unmarshal(body, &ir); err != nil || ir.State != "ok" {
		return nil, nil
	}

	var result []SubsidiaryInfo
	for _, item := range ir.Data.Items {
		if pct := parsePercent(item.Percent); pct >= 51 {
			result = append(result, SubsidiaryInfo{Name: item.Name, Ownership: pct, ParentName: companyName})
		}
	}
	return result, nil
}

// ── 企查查子公司发现 ──────────────────────────────────────────────────────────

type qccInvestResp struct {
	Status string `json:"Status"`
	Result []struct {
		InvestCompany string `json:"InvestCompany"`
		Ratio         string `json:"Ratio"` // 例 "75%"
		KeyNo         string `json:"KeyNo"`
	} `json:"Result"`
}

// discoverSubsidiariesFromQCC 先用企查查搜索公司，再查对外投资列表，
// 返回持股比例 ≥51% 的子公司。
func discoverSubsidiariesFromQCC(ctx context.Context, companyName, apiKey string) ([]SubsidiaryInfo, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"Token": apiKey}

	// Step 1: 按名称搜索，取第一条 KeyNo
	body, err := netGet(ctx,
		fmt.Sprintf("https://api.qichacha.com/ECIV4GetBasicDetailsByName?key=%s&keyword=%s&pageIndex=1&pageSize=5",
			apiKey, url.QueryEscape(companyName)), hdr)
	if err != nil {
		return nil, fmt.Errorf("qcc subsidiary search: %w", err)
	}
	var sr qccSearchResp
	if err := json.Unmarshal(body, &sr); err != nil || sr.Status != "200" || len(sr.Result.Result) == 0 {
		return nil, nil
	}
	keyNo := sr.Result.Result[0].KeyNo

	// Step 2: 查对外投资列表
	body, err = netGet(ctx,
		fmt.Sprintf("https://api.qichacha.com/ECIEquityInvestOutInfo?key=%s&id=%s&pageIndex=1&pageSize=100",
			apiKey, keyNo), hdr)
	if err != nil {
		return nil, fmt.Errorf("qcc investment: %w", err)
	}
	var ir qccInvestResp
	if err := json.Unmarshal(body, &ir); err != nil || ir.Status != "200" {
		return nil, nil
	}

	var result []SubsidiaryInfo
	for _, item := range ir.Result {
		if pct := parsePercent(item.Ratio); pct >= 51 {
			result = append(result, SubsidiaryInfo{Name: item.InvestCompany, Ownership: pct, ParentName: companyName})
		}
	}
	return result, nil
}

// ── 爱企查子公司发现 ──────────────────────────────────────────────────────────

type aqcInvestResp struct {
	Errno int    `json:"errno"`
	ErrMsg string `json:"errmsg"`
	Data  struct {
		List []struct {
			Name     string `json:"name"`
			RegRatio string `json:"regRatio"` // 例 "75.00%"
			Ratio    string `json:"ratio"`    // 部分接口用此字段
		} `json:"list"`
	} `json:"data"`
}

// discoverSubsidiariesFromAQC 先用爱企查搜索公司取 pid，再查对外投资列表，
// 返回持股比例 ≥51% 的子公司。
func discoverSubsidiariesFromAQC(ctx context.Context, companyName, apiKey string) ([]SubsidiaryInfo, error) {
	if apiKey == "" {
		return nil, nil
	}
	hdr := map[string]string{"X-API-KEY": apiKey}

	// Step 1: 搜索公司，取第一条 pid
	body, err := netGet(ctx,
		fmt.Sprintf("https://api.aiqicha.com/v1/company/search?keyword=%s&pageIndex=1&pageSize=5",
			url.QueryEscape(companyName)), hdr)
	if err != nil {
		return nil, fmt.Errorf("aiqicha subsidiary search: %w", err)
	}
	var sr aiqichaSearchResp
	if err := json.Unmarshal(body, &sr); err != nil || sr.Errno != 0 || len(sr.Data.List) == 0 {
		return nil, nil
	}
	pid := sr.Data.List[0].PID

	// Step 2: 查对外投资列表
	body, err = netGet(ctx,
		fmt.Sprintf("https://api.aiqicha.com/v1/company/invest?pid=%s&pageIndex=1&pageSize=100", pid), hdr)
	if err != nil {
		return nil, fmt.Errorf("aiqicha investment: %w", err)
	}
	var ir aqcInvestResp
	if err := json.Unmarshal(body, &ir); err != nil || ir.Errno != 0 {
		return nil, nil
	}

	var result []SubsidiaryInfo
	for _, item := range ir.Data.List {
		// regRatio 优先，fallback 到 ratio
		raw := item.RegRatio
		if raw == "" {
			raw = item.Ratio
		}
		if pct := parsePercent(raw); pct >= 51 {
			result = append(result, SubsidiaryInfo{Name: item.Name, Ownership: pct, ParentName: companyName})
		}
	}
	return result, nil
}
