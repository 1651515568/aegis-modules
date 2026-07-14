package assetcollect

// scanner.go — 核心资产收集逻辑：并行调用所有配置的情报源，合并去重后返回结果。

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"redops/core"
)

// CollectedAsset 是单条收集结果，统一描述域名/IP/App/ICP/公司等各类资产。
type CollectedAsset struct {
	Type    string `json:"type"`    // domain | ip | app | icp | company
	Value   string `json:"value"`   // 资产主值（域名/IP/App包名等）
	Org     string `json:"org"`     // 归属组织
	Source  string `json:"source"`  // 来源情报平台
	Meta    string `json:"meta"`    // 附加信息（JSON 字符串）
	FoundAt string `json:"foundAt"` // 发现时间
}

// collectOptions 是资产收集任务参数。
type collectOptions struct {
	Target     string `json:"target"`     // 目标（公司名、域名、IP、关键词）
	TargetType string `json:"targetType"` // company | domain | ip | keyword

	// ── 网络测绘情报源 ───────────────────────────────────────────────
	HunterKey         string `json:"hunterKey"`
	ZoomEyeKey        string `json:"zoomeyeKey"`
	QuakeKey          string `json:"quakeKey"`
	ZeroZoneKey       string `json:"zerozoneKey"`
	FOFAEmail         string `json:"fofaEmail"`
	FOFAKey           string `json:"fofaKey"`
	ShodanKey         string `json:"shodanKey"`
	SecurityTrailsKey string `json:"securitytrailsKey"`
	CensysID          string `json:"censysId"`
	CensysSecret      string `json:"censysSecret"`
	VirusTotalKey     string `json:"virusTotalKey"`
	ChaosKey          string `json:"chaosKey"`
	ThreatBookKey     string `json:"threatbookKey"`

	// ── 企业情报源 ───────────────────────────────────────────────────
	TianYanChaKey string `json:"tianyanchaKey"`
	QCCKey        string `json:"qccKey"`
	AiQiChaKey    string `json:"aiqichaKey"`
	XiaoLanBenKey string `json:"xiaolanbenKey"`
	QiMaiKey      string `json:"qimaiKey"`
	FengNiaoKey   string `json:"fengniaKey"`
}

type assetCollector struct {
	log core.Logger
}

func newAssetCollector(log core.Logger) *assetCollector {
	return &assetCollector{log: log}
}

// countActiveSources 统计本次将实际启动的情报源 goroutine 数量，用于进度百分比计算。
func countActiveSources(opts collectOptions, ttype string) int {
	n := 0
	if ttype == "company" || ttype == "keyword" {
		for _, k := range []string{
			opts.TianYanChaKey, opts.QCCKey, opts.AiQiChaKey,
			opts.XiaoLanBenKey, opts.QiMaiKey, opts.FengNiaoKey,
		} {
			if k != "" {
				n++
			}
		}
	}
	if opts.CensysID != "" && opts.CensysSecret != "" {
		n++
	}
	for _, k := range []string{
		opts.HunterKey, opts.ZoomEyeKey, opts.QuakeKey, opts.ZeroZoneKey,
		opts.ShodanKey, opts.SecurityTrailsKey,
		opts.VirusTotalKey, opts.ThreatBookKey,
	} {
		if k != "" {
			n++
		}
	}
	// FOFA 需要 email + key 两个字段都非空才会实际运行
	if opts.FOFAEmail != "" && opts.FOFAKey != "" {
		n++
	}
	if opts.ChaosKey != "" && ttype == "domain" {
		n++
	}
	// domain 模式下始终启用的免费源：crt.sh + AlienVault OTX + HackerTarget
	if ttype == "domain" {
		n += 3
	}
	// Shodan DNS 子域名端点（domain 模式，复用已有 ShodanKey）
	if ttype == "domain" && opts.ShodanKey != "" {
		n++
	}
	return n
}

func (c *assetCollector) run(ctx context.Context, opts collectOptions, progress func(int, string)) ([]CollectedAsset, error) {
	var mu sync.Mutex
	seen := make(map[string]bool)
	var results []CollectedAsset

	addAll := func(assets []CollectedAsset) {
		mu.Lock()
		defer mu.Unlock()
		for _, a := range assets {
			k := a.Type + ":" + strings.ToLower(a.Value)
			if !seen[k] && a.Value != "" {
				seen[k] = true
				results = append(results, a)
			}
		}
	}

	var wg sync.WaitGroup
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		return nil, nil
	}
	ttype := opts.TargetType
	if ttype == "" {
		ttype = "domain"
	}

	total := countActiveSources(opts, ttype)
	var doneMu sync.Mutex
	doneCount := 0
	onDone := func(name string, count int, err error) {
		doneMu.Lock()
		doneCount++
		n := doneCount
		doneMu.Unlock()
		pct := 5
		if total > 0 {
			pct = 5 + n*85/total
		}
		if err != nil {
			progress(pct, fmt.Sprintf("[%d/%d] %s 失败: %v", n, total, name, err))
		} else {
			progress(pct, fmt.Sprintf("[%d/%d] %s 返回 %d 条", n, total, name, count))
		}
	}

	progress(5, fmt.Sprintf("分发 %d 个情报源…", total))

	// ── 企业情报源（仅公司/关键词模式）─────────────────────────────
	if ttype == "company" || ttype == "keyword" {
		type bizSrc struct {
			name string
			key  string
			fn   func(context.Context, string, string) ([]CollectedAsset, error)
		}
		bizSrcs := []bizSrc{
			{"tianyancha", opts.TianYanChaKey, collectFromTianYanCha},
			{"qcc", opts.QCCKey, collectFromQCC},
			{"aiqicha", opts.AiQiChaKey, collectFromAiQiCha},
			{"xiaolanben", opts.XiaoLanBenKey, collectFromXiaoLanBen},
			{"qimai", opts.QiMaiKey, collectFromQiMai},
			{"fengniao", opts.FengNiaoKey, collectFromFengNiao},
		}
		for _, src := range bizSrcs {
			if src.key == "" || ctx.Err() != nil {
				continue
			}
			wg.Add(1)
			go func(s bizSrc) {
				defer wg.Done()
				assets, err := s.fn(ctx, target, s.key)
				if err != nil {
					c.log.Warn("biz source failed", "source", s.name, "err", err)
					onDone(s.name, 0, err)
					return
				}
				c.log.Info("biz source result", "source", s.name, "count", len(assets))
				addAll(assets)
				onDone(s.name, len(assets), nil)
			}(src)
		}
	}

	// ── 网络测绘情报源 ───────────────────────────────────────────────
	type netSrc struct {
		name    string
		key     string
		queryFn func(string, string) string // (target, targetType) → query string
		fn      func(context.Context, string, string) ([]CollectedAsset, error)
	}
	netSrcs := []netSrc{
		{"hunter", opts.HunterKey, buildHunterQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromHunter(ctx, q, k)
			}},
		{"zoomeye", opts.ZoomEyeKey, buildZoomEyeQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromZoomEye(ctx, q, k)
			}},
		{"quake", opts.QuakeKey, buildQuakeQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromQuake(ctx, q, k)
			}},
		{"zerozone", opts.ZeroZoneKey, buildZeroZoneQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromZeroZone(ctx, q, k, ttype)
			}},
		{"fofa", opts.FOFAEmail, buildFOFAQuery,
			func(ctx context.Context, q, _ string) ([]CollectedAsset, error) {
				return collectFromFOFA(ctx, q, opts.FOFAEmail, opts.FOFAKey)
			}},
		{"shodan", opts.ShodanKey, buildShodanQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromShodan(ctx, q, k)
			}},
		{"securitytrails", opts.SecurityTrailsKey, buildSTQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromSecurityTrails(ctx, q, k, ttype)
			}},
		{"virustotal", opts.VirusTotalKey, buildVTQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromVirusTotal(ctx, q, k)
			}},
		{"threatbook", opts.ThreatBookKey, buildThreatBookQuery,
			func(ctx context.Context, q, k string) ([]CollectedAsset, error) {
				return collectFromThreatBook(ctx, q, k)
			}},
	}
	// Censys 双字段
	if opts.CensysID != "" && opts.CensysSecret != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := buildCensysQuery(target, ttype)
			assets, err := collectFromCensys(ctx, q, opts.CensysID, opts.CensysSecret)
			if err != nil {
				c.log.Warn("net source failed", "source", "censys", "err", err)
				onDone("censys", 0, err)
				return
			}
			c.log.Info("net source result", "source", "censys", "count", len(assets))
			addAll(assets)
			onDone("censys", len(assets), nil)
		}()
	}

	for _, src := range netSrcs {
		if src.key == "" || ctx.Err() != nil {
			continue
		}
		wg.Add(1)
		go func(s netSrc) {
			defer wg.Done()
			q := s.queryFn(target, ttype)
			assets, err := s.fn(ctx, q, s.key)
			if err != nil {
				c.log.Warn("net source failed", "source", s.name, "err", err)
				onDone(s.name, 0, err)
				return
			}
			c.log.Info("net source result", "source", s.name, "count", len(assets))
			addAll(assets)
			onDone(s.name, len(assets), nil)
		}(src)
	}

	// Chaos 只支持域名模式
	if opts.ChaosKey != "" && (ttype == "domain") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := collectFromChaos(ctx, target, opts.ChaosKey)
			if err != nil {
				c.log.Warn("chaos failed", "err", err)
				onDone("chaos", 0, err)
				return
			}
			addAll(assets)
			onDone("chaos", len(assets), nil)
		}()
	}

	// crt.sh — 免费无需 Key，domain 模式下始终运行
	if ttype == "domain" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := collectFromCRTSH(ctx, target)
			if err != nil {
				c.log.Warn("crtsh failed", "err", err)
				onDone("crtsh", 0, err)
				return
			}
			c.log.Info("crtsh result", "count", len(assets))
			addAll(assets)
			onDone("crtsh", len(assets), nil)
		}()
	}

	// AlienVault OTX — 免费被动 DNS，domain 模式下始终运行
	if ttype == "domain" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := collectFromOTX(ctx, target)
			if err != nil {
				c.log.Warn("otx failed", "err", err)
				onDone("otx", 0, err)
				return
			}
			c.log.Info("otx result", "count", len(assets))
			addAll(assets)
			onDone("otx", len(assets), nil)
		}()
	}

	// HackerTarget — 免费主机搜索，domain 模式下始终运行
	if ttype == "domain" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := collectFromHackerTarget(ctx, target)
			if err != nil {
				c.log.Warn("hackertarget failed", "err", err)
				onDone("hackertarget", 0, err)
				return
			}
			c.log.Info("hackertarget result", "count", len(assets))
			addAll(assets)
			onDone("hackertarget", len(assets), nil)
		}()
	}

	// Shodan DNS 子域名端点（domain 模式，复用 ShodanKey，与常规 Shodan 搜索互补）
	if ttype == "domain" && opts.ShodanKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, err := collectFromShodanDNS(ctx, target, opts.ShodanKey)
			if err != nil {
				c.log.Warn("shodan-dns failed", "err", err)
				onDone("shodan-dns", 0, err)
				return
			}
			c.log.Info("shodan-dns result", "count", len(assets))
			addAll(assets)
			onDone("shodan-dns", len(assets), nil)
		}()
	}

	wg.Wait()

	// ── 子公司资产延伸（company 模式，持股≥51%，深度 1）────────────────────────
	if ttype == "company" && (opts.TianYanChaKey != "" || opts.QCCKey != "" || opts.AiQiChaKey != "") {
		progress(96, "查询持股≥51% 子公司…")
		subsidiaries := collectSubsidiaries(ctx, target, opts)
		if len(subsidiaries) > 0 {
			progress(97, fmt.Sprintf("发现 %d 家受控子公司，收集其资产…", len(subsidiaries)))
			// 子公司名称本身作为 company 类型资产归档
			for _, sub := range subsidiaries {
				addAll([]CollectedAsset{makeAsset("company", sub.Name, sub.ParentName, "subsidiary",
					fmt.Sprintf(`{"parentCompany":%q,"ownershipPct":%.1f}`, sub.ParentName, sub.Ownership))})
			}
			// 并行收集各子公司的 ICP 备案域名 + App（优先天眼查，天眼查无结果再用企查查）
			var subWg sync.WaitGroup
			for _, sub := range subsidiaries {
				subWg.Add(1)
				go func(s SubsidiaryInfo) {
					defer subWg.Done()
					var assets []CollectedAsset
					if opts.TianYanChaKey != "" {
						a, _ := collectFromTianYanCha(ctx, s.Name, opts.TianYanChaKey)
						assets = append(assets, a...)
					}
					if opts.QCCKey != "" && len(assets) == 0 {
						a, _ := collectFromQCC(ctx, s.Name, opts.QCCKey)
						assets = append(assets, a...)
					}
					if opts.AiQiChaKey != "" && len(assets) == 0 {
						a, _ := collectFromAiQiCha(ctx, s.Name, opts.AiQiChaKey)
						assets = append(assets, a...)
					}
					addAll(assets)
				}(sub)
			}
			subWg.Wait()
		}
	}

	progress(99, "整理去重结果…")
	return results, ctx.Err()
}

// collectSubsidiaries 并行调用天眼查/企查查/爱企查的对外投资接口，
// 返回持股比例 ≥51% 的子公司列表（已去重，最多 30 条）。
func collectSubsidiaries(ctx context.Context, companyName string, opts collectOptions) []SubsidiaryInfo {
	const maxSubs = 30

	var all []SubsidiaryInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	if opts.TianYanChaKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := discoverSubsidiariesFromTYC(ctx, companyName, opts.TianYanChaKey)
			if err != nil || len(subs) == 0 {
				return
			}
			mu.Lock()
			all = append(all, subs...)
			mu.Unlock()
		}()
	}
	if opts.QCCKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := discoverSubsidiariesFromQCC(ctx, companyName, opts.QCCKey)
			if err != nil || len(subs) == 0 {
				return
			}
			mu.Lock()
			all = append(all, subs...)
			mu.Unlock()
		}()
	}
	if opts.AiQiChaKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := discoverSubsidiariesFromAQC(ctx, companyName, opts.AiQiChaKey)
			if err != nil || len(subs) == 0 {
				return
			}
			mu.Lock()
			all = append(all, subs...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 去重（跳过母公司自身），取持股比例最高的前 maxSubs 条
	seen := map[string]bool{strings.ToLower(companyName): true}
	var result []SubsidiaryInfo
	for _, s := range all {
		key := strings.ToLower(s.Name)
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}
	if len(result) > maxSubs {
		result = result[:maxSubs]
	}
	return result
}

// ── 查询语句构建 ─────────────────────────────────────────────────────────────

func buildHunterQuery(target, ttype string) string {
	switch ttype {
	case "company":
		// icp.name 精准匹配 ICP 备案主体名称
		return `icp.name="` + target + `"`
	case "keyword":
		// 复合查询：网页标题 OR ICP 备案名称，提高命中率
		return `web.title="` + target + `" || icp.name="` + target + `"`
	case "ip":
		// CIDR 段用 ip.src，单 IP 用 ip
		if strings.Contains(target, "/") {
			return `ip.src="` + target + `"`
		}
		return `ip="` + target + `"`
	default: // domain
		return `domain.suffix="` + target + `"`
	}
}

func buildFOFAQuery(target, ttype string) string {
	switch ttype {
	case "company", "keyword":
		return `org="` + target + `"`
	case "ip":
		return `ip="` + target + `"`
	default:
		return `domain="` + target + `"`
	}
}

func buildZoomEyeQuery(target, ttype string) string {
	switch ttype {
	case "company", "keyword":
		return `org:"` + target + `"`
	case "ip":
		return `ip:"` + target + `"`
	default:
		return `hostname:"` + target + `"`
	}
}

func buildQuakeQuery(target, ttype string) string {
	switch ttype {
	case "company", "keyword":
		return `org: "` + target + `"`
	case "ip":
		return `ip: "` + target + `"`
	default:
		return `domain: "` + target + `"`
	}
}

func buildZeroZoneQuery(target, ttype string) string {
	switch ttype {
	case "company", "keyword":
		return target
	case "ip":
		return target
	default:
		return target
	}
}

func buildShodanQuery(target, ttype string) string {
	switch ttype {
	case "company", "keyword":
		return `org:"` + target + `"`
	case "ip":
		return `net:` + target
	default:
		return `hostname:` + target
	}
}

func buildSTQuery(target, ttype string) string {
	// SecurityTrails 用于域名发现，公司模式下当关键词
	return target
}

func buildVTQuery(target, ttype string) string {
	return target
}

func buildThreatBookQuery(target, ttype string) string {
	return target
}

func buildCensysQuery(target, ttype string) string {
	switch ttype {
	case "company", "keyword":
		return `autonomous_system.organization: "` + target + `"`
	case "ip":
		return `ip: "` + target + `"`
	default:
		return `parsed.names: "` + target + `"`
	}
}
