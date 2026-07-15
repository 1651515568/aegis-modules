package osintfofa

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes 声明业务 HTTP 路由，框架自动挂载到 /api/m/osint-fofa/...
// 路由约定（框架已剥掉 /api/m/osint-fofa 前缀）：
//
//	GET  /functions        功能 schema 自描述，前端据此渲染表单
//	GET  /settings         读取各平台 API Key 配置
//	POST /settings         保存各平台 API Key 配置
//	POST /invoke           发起空间测绘查询任务
//	GET  /tasks/*          按 task_id 轮询任务进度/结果
//	GET  /findings         按 task_id 取归档资产（见 findings.go）
//	POST /findings/clear   清除指定 task_id 的归档
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET", Path: "/functions", Handler: m.listFunctions, Permission: "osint:view"},
		{Method: "GET", Path: "/settings", Handler: m.getSettings, Permission: "osint:view"},
		{Method: "POST", Path: "/settings", Handler: m.saveSettings, Permission: "osint:query"},
		{Method: "POST", Path: "/invoke", Handler: m.invokeFunction, Permission: "osint:query"},
		{Method: "POST", Path: "/stop", Handler: m.stopQuery, Permission: "osint:query"},
		{Method: "GET", Path: "/tasks/*", Handler: m.getTask, Permission: "osint:view"},
		{Method: "GET", Path: "/findings", Handler: m.listFindings, Permission: "osint:view"},
		{Method: "POST", Path: "/findings/clear", Handler: m.clearFindings, Permission: "osint:query"},
	}
}

// settingKeys 枚举本模块管理的所有配置键。
var settingKeys = []string{
	"fofaEmail",
	"fofaKey",
	"hunterKey",
	"shodanKey",
	"zoomeyeKey",
	"quakeKey",
}

// getSettings 读取 API Key 配置，未设置的键返回空字符串。
func (m *Module) getSettings(w http.ResponseWriter, _ *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	tbl := m.db.Table("settings")
	result := make(map[string]string, len(settingKeys))
	for _, k := range settingKeys {
		var v string
		if row := m.db.QueryRow(`SELECT value FROM `+tbl+` WHERE key=?`, k); row.Scan(&v) == nil {
			result[k] = v
		} else {
			result[k] = ""
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// settingsRequest 是保存配置的请求体结构。
type settingsRequest struct {
	FOFAEmail  string `json:"fofaEmail"`
	FOFAKey    string `json:"fofaKey"`
	HunterKey  string `json:"hunterKey"`
	ShodanKey  string `json:"shodanKey"`
	ZoomEyeKey string `json:"zoomeyeKey"`
	QuakeKey   string `json:"quakeKey"`
}

// saveSettings 把 API Key 配置持久化到 settings 表（upsert）。
func (m *Module) saveSettings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	var req settingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	tbl := m.db.Table("settings")
	kvs := map[string]string{
		"fofaEmail":  req.FOFAEmail,
		"fofaKey":    req.FOFAKey,
		"hunterKey":  req.HunterKey,
		"shodanKey":  req.ShodanKey,
		"zoomeyeKey": req.ZoomEyeKey,
		"quakeKey":   req.QuakeKey,
	}
	for k, v := range kvs {
		if _, err := m.db.Exec(
			`INSERT OR REPLACE INTO `+tbl+` (key, value, updated_at) VALUES (?, ?, datetime('now'))`, k, v,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// loadSettingFallback 从 settings 表读取指定 key 的值，若 *ptr 已有值则跳过（fallback 模式）。
// 适用于调用时传入的参数可覆盖全局配置的场景（params 中有值优先，否则读 DB 填充）。
func (m *Module) loadSettingFallback(tbl, key string, ptr *string) {
	if *ptr != "" || m.db == nil {
		return
	}
	var v string
	if row := m.db.QueryRow(`SELECT value FROM `+tbl+` WHERE key=?`, key); row.Scan(&v) == nil && v != "" {
		*ptr = v
	}
}

// writeJSON 统一响应帮助函数，设置 Content-Type 并写入 JSON 编码结果。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// stopQuery 取消当前运行中的查询任务（若有），供前端「停止」按钮调用。
// 触发 invokeQuery 里 ctx 的取消，goroutine 会走取消分支落 Cancel 终态并归档已得资产。
func (m *Module) stopQuery(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	c := m.cancel
	m.mu.Unlock()
	if c != nil {
		c()
	}
	writeJSON(w, http.StatusOK, map[string]any{"stopped": c != nil})
}
