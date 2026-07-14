package assetcollect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"time"

	"redops/core"
)

// ── 函数列表 ──────────────────────────────────────────────────────────────────

func assetCollectFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "collect",
			Name:        "资产收集",
			Description: "多情报源并行资产收集：网络测绘（11个平台）+ 企业情报（6个平台）",
			Params: []core.ParamSpec{
				{Name: "target", Label: "目标", Type: core.ParamString, Required: true,
					Placeholder: "example.com 或 示例科技有限公司",
					Help:        "公司名称 / 域名 / IP 地址 / 关键词"},
				{Name: "targetType", Label: "目标类型", Type: core.ParamSelect, Required: true,
					Default: "company",
					Help:    "company=企业，domain=域名，ip=IP段，keyword=关键词",
					Options: []core.ParamOption{
						{Value: "company", Label: "企业 (company)"},
						{Value: "domain", Label: "域名 (domain)"},
						{Value: "ip", Label: "IP / CIDR (ip)"},
						{Value: "keyword", Label: "关键词 (keyword)"},
					}},
				// ── 网络测绘 ──────────────────────────────────────
				{Name: "hunterKey", Label: "Hunter API Key", Type: core.ParamString,
					Placeholder: "奇安信鹰图 API Key（可选）",
					Help:        "填写后启用 Hunter 网络测绘情报源"},
				{Name: "zoomeyeKey", Label: "ZoomEye API Key", Type: core.ParamString,
					Placeholder: "钟馗之眼 API Key（可选）",
					Help:        "填写后启用 ZoomEye 网络测绘情报源"},
				{Name: "quakeKey", Label: "360 Quake Token", Type: core.ParamString,
					Placeholder: "360 Quake API Token（可选）",
					Help:        "填写后启用 360 Quake 网络测绘情报源"},
				{Name: "zerozoneKey", Label: "零零信安 Key", Type: core.ParamString,
					Placeholder: "0.zone API Key（可选）",
					Help:        "填写后启用零零信安网络测绘情报源"},
				{Name: "fofaEmail", Label: "FOFA 账号邮箱", Type: core.ParamString,
					Placeholder: "FOFA 注册邮箱（与 fofaKey 配合使用）",
					Help:        "FOFA 认证需要邮箱+Key 两个字段，两者均填写才启用"},
				{Name: "fofaKey", Label: "FOFA API Key", Type: core.ParamString,
					Placeholder: "fofa.info API Key（可选）",
					Help:        "填写后（配合邮箱）启用 FOFA 网络空间测绘情报源"},
				{Name: "shodanKey", Label: "Shodan API Key", Type: core.ParamString,
					Placeholder: "shodan.io API Key（可选）",
					Help:        "填写后启用 Shodan 国际互联网资产情报源"},
				{Name: "securitytrailsKey", Label: "SecurityTrails API Key", Type: core.ParamString,
					Placeholder: "SecurityTrails API Key（可选）",
					Help:        "填写后启用 SecurityTrails DNS 历史情报源"},
				{Name: "censysId", Label: "Censys API ID", Type: core.ParamString,
					Placeholder: "Censys API ID（与 censysSecret 配合使用）",
					Help:        "Censys 认证需要 API ID + Secret 两个字段"},
				{Name: "censysSecret", Label: "Censys API Secret", Type: core.ParamString,
					Placeholder: "Censys API Secret（与 censysId 配合使用）",
					Help:        "填写后（配合 ID）启用 Censys 证书透明度与测绘情报源"},
				{Name: "virusTotalKey", Label: "VirusTotal API Key", Type: core.ParamString,
					Placeholder: "VirusTotal API Key（可选）",
					Help:        "填写后启用 VirusTotal 被动 DNS 情报源"},
				{Name: "chaosKey", Label: "Chaos API Key", Type: core.ParamString,
					Placeholder: "ProjectDiscovery Chaos API Key（可选）",
					Help:        "仅域名模式下生效，启用 Chaos 公开子域名数据集"},
				{Name: "threatbookKey", Label: "微步 ThreatBook API Key", Type: core.ParamString,
					Placeholder: "微步在线 ThreatBook API Key（可选）",
					Help:        "填写后启用微步在线威胁情报资产发现"},
				// ── 企业情报（仅 company/keyword 模式生效）────────
				{Name: "tianyanchaKey", Label: "天眼查 API Token", Type: core.ParamString,
					Placeholder: "天眼查开放平台 Token（可选）",
					Help:        "company/keyword 模式：查询 ICP 备案域名与移动 App"},
				{Name: "qccKey", Label: "企查查 API Token", Type: core.ParamString,
					Placeholder: "企查查 API Token（可选）",
					Help:        "company/keyword 模式：查询 ICP 备案域名与移动 App"},
				{Name: "aiqichaKey", Label: "爱企查 API Key", Type: core.ParamString,
					Placeholder: "爱企查（百度）API Key（可选）",
					Help:        "company/keyword 模式：查询企业官网与 ICP 备案"},
				{Name: "xiaolanbenKey", Label: "小蓝本 API Key", Type: core.ParamString,
					Placeholder: "小蓝本开放平台 Key（可选）",
					Help:        "company/keyword 模式：查询企业官网资产"},
				{Name: "qimaiKey", Label: "七麦数据 API Token", Type: core.ParamString,
					Placeholder: "七麦数据 Token（可选）",
					Help:        "company/keyword 模式：查询 iOS/Android App 情报"},
				{Name: "fengniaKey", Label: "风鸟情报 API Key", Type: core.ParamString,
					Placeholder: "风鸟情报平台 Key（可选）",
					Help:        "company/keyword 模式：查询企业数字资产"},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": assetCollectFunctions()})
}

// ── 任务调用 ──────────────────────────────────────────────────────────────────

type collectInvokeRequest struct {
	TaskID    string          `json:"taskId"`
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"`
}

func fallbackCollectTaskID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "eng-" + hex.EncodeToString(b)
}

func (m *Module) invokeFunction(w http.ResponseWriter, r *http.Request) {
	var req collectInvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	switch req.Function {
	case "collect":
		m.invokeCollect(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

func (m *Module) invokeCollect(w http.ResponseWriter, req collectInvokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}

	// 同一时间只允许一个收集任务
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有收集任务在运行，请先停止"})
		return
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Minute)
	m.cancel = cancelFn
	m.mu.Unlock()

	var opts collectOptions
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &opts); err != nil {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
			cancelFn()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}
	if opts.Target == "" {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target 不能为空"})
		return
	}
	if opts.TargetType == "" {
		opts.TargetType = "company"
	}

	// 从数据库补全未传入的 key（fallback）
	if m.db != nil {
		tbl := m.db.Table("settings")
		m.loadSettingFallback(tbl, "hunterKey", &opts.HunterKey)
		m.loadSettingFallback(tbl, "zoomeyeKey", &opts.ZoomEyeKey)
		m.loadSettingFallback(tbl, "quakeKey", &opts.QuakeKey)
		m.loadSettingFallback(tbl, "zerozoneKey", &opts.ZeroZoneKey)
		m.loadSettingFallback(tbl, "fofaEmail", &opts.FOFAEmail)
		m.loadSettingFallback(tbl, "fofaKey", &opts.FOFAKey)
		m.loadSettingFallback(tbl, "shodanKey", &opts.ShodanKey)
		m.loadSettingFallback(tbl, "securitytrailsKey", &opts.SecurityTrailsKey)
		m.loadSettingFallback(tbl, "censysId", &opts.CensysID)
		m.loadSettingFallback(tbl, "censysSecret", &opts.CensysSecret)
		m.loadSettingFallback(tbl, "virusTotalKey", &opts.VirusTotalKey)
		m.loadSettingFallback(tbl, "chaosKey", &opts.ChaosKey)
		m.loadSettingFallback(tbl, "threatbookKey", &opts.ThreatBookKey)
		m.loadSettingFallback(tbl, "tianyanchaKey", &opts.TianYanChaKey)
		m.loadSettingFallback(tbl, "qccKey", &opts.QCCKey)
		m.loadSettingFallback(tbl, "aiqichaKey", &opts.AiQiChaKey)
		m.loadSettingFallback(tbl, "xiaolanbenKey", &opts.XiaoLanBenKey)
		m.loadSettingFallback(tbl, "qimaiKey", &opts.QiMaiKey)
		m.loadSettingFallback(tbl, "fengniaKey", &opts.FengNiaoKey)
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackCollectTaskID()
	}
	if err := m.runs.Start(taskID, "collect"); err != nil {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	go func() {
		defer func() {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		_ = m.runs.Progress(taskID, 2, fmt.Sprintf("开始收集 %s（类型: %s），分发情报源…", opts.Target, opts.TargetType))

		collector := newAssetCollector(m.log)
		assets, err := collector.run(ctx, opts, func(pct int, msg string) {
			_ = m.runs.Progress(taskID, pct, msg)
		})

		if err != nil {
			if ctx.Err() != nil {
				m.saveFindings(taskID, assets)
				_ = m.runs.Cancel(taskID, fmt.Sprintf("用户手动停止，已保存资产 %d 条", len(assets)))
			} else {
				_ = m.runs.Fail(taskID, err.Error())
			}
			return
		}

		// 归档资产到模块自有表（覆盖式，同 scan-backup saveFindings 模式）。
		m.saveFindings(taskID, assets)

		_ = m.runs.Succeed(taskID, map[string]any{
			"count":      len(assets),
			"target":     opts.Target,
			"targetType": opts.TargetType,
		})
	}()

	m.log.Info("asset collect invoked", "task", taskID, "target", opts.Target, "type", opts.TargetType)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

func (m *Module) stopCollect(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stopped": false, "msg": "无运行中的收集任务"})
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
}

func (m *Module) getTask(w http.ResponseWriter, r *http.Request) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	id := path.Base(r.URL.Path)
	t, ok, err := m.runs.Get(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}
