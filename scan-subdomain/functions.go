package subdomain

// functions.go — 模块「可调用功能」自描述 + 通用 invoke/task 入口。
//
// 对外契约（经 AEGIS 后端 /api/v1/engine/m/scan-subdomain/* 代理）：
//   GET  /functions        列出可调用功能及参数 schema
//   POST /invoke           {taskId, function, params}：发起调用
//   POST /stop             停止当前运行中的枚举
//   GET  /tasks/<taskId>   轮询任务进度/结果（读自 task_runs 表）

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"redops/core"
)

func fptr(f float64) *float64 { return &f }

func subdomainFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "enumerate",
			Name:        "子域名枚举",
			Description: "对目标主域名进行子域名枚举，支持字典爆破、DNS 递归与证书透明度日志。",
			Params: []core.ParamSpec{
				{
					Name:        "domain",
					Label:       "目标主域名",
					Type:        core.ParamString,
					Required:    true,
					Placeholder: "example.com",
					Help:        "不含 http://，只填主域名",
				},
				{
					Name:    "mode",
					Label:   "枚举模式",
					Type:    core.ParamSelect,
					Default: "all",
					Options: []core.ParamOption{
						{Value: "all", Label: "全部模式（字典+暴破+CT）"},
						{Value: "dict", Label: "字典爆破"},
						{Value: "brute", Label: "DNS 递归（a-z/aa-zz）"},
						{Value: "ct", Label: "证书透明度（crt.sh）"},
					},
					Help: "全部模式会合并三种方式的结果，去重后输出",
				},
				{
					Name:    "dictPreset",
					Label:   "字典规模",
					Type:    core.ParamSelect,
					Default: "medium",
					Options: []core.ParamOption{
						{Value: "small", Label: "小字典（~250 条）"},
						{Value: "medium", Label: "中字典（~1800 条）"},
						{Value: "large", Label: "大字典（~2300 条）"},
						{Value: "xlarge", Label: "超大字典（~61500 条）"},
					},
				},
				{
					Name:    "permutation",
					Label:   "排列组合增强",
					Type:    core.ParamBool,
					Default: true,
					Help:    "从已发现子域名前缀生成 {prefix}-{dev/prod/test...} 组合，二次解析发现更多资产",
				},
				{
					Name:        "resolver",
					Label:       "DNS 服务器",
					Type:        core.ParamString,
					Default:     "8.8.8.8,1.1.1.1",
					Placeholder: "8.8.8.8,1.1.1.1",
					Help:        "逗号分隔，支持多个，端口可选（默认 53）",
				},
				{
					Name:    "threads",
					Label:   "并发线程",
					Type:    core.ParamInt,
					Default: 100,
					Min:     fptr(10),
					Max:     fptr(500),
					Help:    "并发 DNS 解析线程数，默认 100",
				},
				{
					Name:    "timeoutMs",
					Label:   "超时(ms)",
					Type:    core.ParamInt,
					Default: 3000,
					Min:     fptr(500),
					Max:     fptr(10000),
					Help:    "单个 DNS 解析超时，默认 3000ms",
				},
				{
					Name:        "hunterKey",
					Label:       "Hunter API Key",
					Type:        core.ParamString,
					Placeholder: "奇安信鹰图 API Key（可选）",
					Help:        "填写后启用 Hunter 情报源查询子域名",
				},
				{
					Name:        "zoomeyeKey",
					Label:       "ZoomEye API Key",
					Type:        core.ParamString,
					Placeholder: "钟馗之眼 API Key（可选）",
					Help:        "填写后启用 ZoomEye 情报源查询子域名",
				},
				{
					Name:        "quakeKey",
					Label:       "360 Quake Token",
					Type:        core.ParamString,
					Placeholder: "360 Quake API Token（可选）",
					Help:        "填写后启用 360 Quake 情报源查询子域名",
				},
				{
					Name:        "zerozoneKey",
					Label:       "零零信安 Key",
					Type:        core.ParamString,
					Placeholder: "0.zone API Key（可选）",
					Help:        "填写后启用零零信安情报源查询子域名",
				},
				{
					Name:        "fofaEmail",
					Label:       "FOFA 账号邮箱",
					Type:        core.ParamString,
					Placeholder: "FOFA 注册邮箱（与 fofaKey 配合使用）",
					Help:        "FOFA 认证需要邮箱+Key 两个字段，两者均填写才启用",
				},
				{
					Name:        "fofaKey",
					Label:       "FOFA API Key",
					Type:        core.ParamString,
					Placeholder: "fofa.info API Key（可选）",
					Help:        "填写后（配合邮箱）启用 FOFA 网络空间测绘情报查询",
				},
				{
					Name:        "shodanKey",
					Label:       "Shodan API Key",
					Type:        core.ParamString,
					Placeholder: "shodan.io API Key（可选）",
					Help:        "填写后启用 Shodan 国际互联网资产情报查询",
				},
				{
					Name:        "securitytrailsKey",
					Label:       "SecurityTrails API Key",
					Type:        core.ParamString,
					Placeholder: "SecurityTrails API Key（可选）",
					Help:        "填写后启用 SecurityTrails DNS 历史与子域名查询",
				},
				{
					Name:        "censysId",
					Label:       "Censys API ID",
					Type:        core.ParamString,
					Placeholder: "Censys API ID（与 censysSecret 配合使用）",
					Help:        "Censys 证书搜索认证需要 API ID + Secret 两个字段",
				},
				{
					Name:        "censysSecret",
					Label:       "Censys API Secret",
					Type:        core.ParamString,
					Placeholder: "Censys API Secret（与 censysId 配合使用）",
					Help:        "填写后（配合 ID）启用 Censys 证书透明度与网络测绘查询",
				},
				{
					Name:        "virusTotalKey",
					Label:       "VirusTotal API Key",
					Type:        core.ParamString,
					Placeholder: "VirusTotal API Key（可选）",
					Help:        "填写后启用 VirusTotal 子域名情报查询",
				},
				{
					Name:        "chaosKey",
					Label:       "Chaos API Key",
					Type:        core.ParamString,
					Placeholder: "ProjectDiscovery Chaos API Key（可选）",
					Help:        "填写后启用 ProjectDiscovery Chaos 公开子域名数据集查询",
				},
				{
					Name:        "threatbookKey",
					Label:       "微步 ThreatBook API Key",
					Type:        core.ParamString,
					Placeholder: "微步在线 ThreatBook API Key（可选）",
					Help:        "填写后启用微步在线子域名情报查询",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": subdomainFunctions()})
}

type invokeRequest struct {
	TaskID    string          `json:"taskId"`
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"`
}

func fallbackTaskID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "eng-" + hex.EncodeToString(b)
}

func (m *Module) invokeFunction(w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	switch req.Function {
	case "enumerate":
		m.invokeEnumerate(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

func (m *Module) invokeEnumerate(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}

	// Reject if a scan is already running.
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有枚举任务在运行，请先停止"})
		return
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	m.cancel = cancelFn
	m.mu.Unlock()

	var opts scanOptions
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
	if opts.Domain == "" {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain 不能为空"})
		return
	}

	// 若调用方未传入 API Key，从持久化 settings 表中 fallback 读取。
	if m.db != nil {
		stbl := m.db.Table("settings")
		m.loadSettingFallback(stbl, "hunterKey", &opts.HunterKey)
		m.loadSettingFallback(stbl, "zoomeyeKey", &opts.ZoomEyeKey)
		m.loadSettingFallback(stbl, "quakeKey", &opts.QuakeKey)
		m.loadSettingFallback(stbl, "zerozoneKey", &opts.ZeroZoneKey)
		m.loadSettingFallback(stbl, "fofaEmail", &opts.FOFAEmail)
		m.loadSettingFallback(stbl, "fofaKey", &opts.FOFAKey)
		m.loadSettingFallback(stbl, "shodanKey", &opts.ShodanKey)
		m.loadSettingFallback(stbl, "securitytrailsKey", &opts.SecurityTrailsKey)
		m.loadSettingFallback(stbl, "censysId", &opts.CensysID)
		m.loadSettingFallback(stbl, "censysSecret", &opts.CensysSecret)
		m.loadSettingFallback(stbl, "virusTotalKey", &opts.VirusTotalKey)
		m.loadSettingFallback(stbl, "chaosKey", &opts.ChaosKey)
		m.loadSettingFallback(stbl, "threatbookKey", &opts.ThreatBookKey)
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	if err := m.runs.Start(taskID, "enumerate"); err != nil {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	// Estimate total probes for progress calculation (CT count is unknown, skip it).
	totalExpected := 0
	if opts.Mode == "all" || opts.Mode == "dict" {
		totalExpected += len(getWordlist(opts.DictPreset))
	}
	if opts.Mode == "all" || opts.Mode == "brute" {
		totalExpected += 1332 // 36 (a-z+0-9) + 36*36 two-char
	}
	if totalExpected == 0 {
		totalExpected = 100 // ct-only mode: rough estimate
	}

	go func() {
		defer cancelFn() // 枚举结束时释放 ctx 资源，防止 context goroutine 泄漏
		defer func() {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		_ = m.runs.Progress(taskID, 2, fmt.Sprintf("开始枚举 %s (模式: %s)，检测通配符中…", opts.Domain, opts.Mode))

		results, err := m.sc.run(ctx, opts, func(tried, found int) {
			pct := tried * 90 / totalExpected
			if pct < 3 {
				pct = 3
			}
			if pct > 90 {
				pct = 90
			}
			_ = m.runs.Progress(taskID, pct, fmt.Sprintf("已解析 %d 条，发现 %d 个子域名", tried, found))
		})
		if err != nil {
			if ctx.Err() != nil {
				if m.db != nil {
					m.saveFindings(taskID, results)
				}
				_ = m.runs.Cancel(taskID, fmt.Sprintf("用户手动停止，已保存 %d 条子域名", len(results)))
			} else {
				_ = m.runs.Fail(taskID, err.Error())
			}
			return
		}

		if m.db != nil {
			m.saveFindings(taskID, results)
		}
		if results == nil {
			results = []SubdomainResult{}
		}
		_ = m.runs.Progress(taskID, 100, fmt.Sprintf("枚举完成，发现 %d 个子域名", len(results)))
		_ = m.runs.Succeed(taskID, map[string]any{
			"total":   len(results),
			"domain":  opts.Domain,
			"results": results,
		})
	}()

	m.log.Info("subdomain enumerate invoked", "task", taskID, "domain", opts.Domain, "mode", opts.Mode)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

func (m *Module) stopScan(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stopped": false, "msg": "无运行中的枚举任务"})
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
