package bruteforce

// handler.go —— HTTP 路由注册与非 findings 的请求处理。
//
// 路由约定（框架剥掉 /api/m/brute-force 前缀）：
//   GET  /functions         功能 schema 自描述
//   GET  /status            当前是否有任务运行
//   GET  /findings          按 task_id 取归档凭据（见 findings.go）
//   POST /findings/clear    清除指定 task_id 的归档（见 findings.go）
//   GET  /export            导出归档凭据（JSON/CSV，见 findings.go）
//   GET  /settings          读取模块设置
//   POST /settings          保存模块设置
//   POST /invoke            发起爆破（见 functions.go）
//   POST /stop              停止当前爆破
//   GET  /tasks/*           按 task_id 查进度（见 functions.go）

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes declares the HTTP routes for the brute-force module.
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",  Path: "/functions",      Handler: m.listFunctions,  Permission: "brute:view"},
		{Method: "GET",  Path: "/status",         Handler: m.bruteStatus,    Permission: "brute:view"},
		{Method: "GET",  Path: "/findings",       Handler: m.listFindings,   Permission: "brute:view"},
		{Method: "POST", Path: "/findings/clear", Handler: m.clearFindings,  Permission: "brute:run"},
		{Method: "GET",  Path: "/export",         Handler: m.exportFindings, Permission: "brute:view"},
		{Method: "GET",  Path: "/settings",       Handler: m.getSettings,    Permission: "brute:view"},
		{Method: "POST", Path: "/settings",       Handler: m.saveSettings,   Permission: "brute:run"},
		{Method: "POST", Path: "/invoke",         Handler: m.invokeFunction, Permission: "brute:run"},
		{Method: "POST", Path: "/stop",           Handler: m.stopBrute,      Permission: "brute:run"},
		{Method: "GET",  Path: "/tasks/*",        Handler: m.getTask,        Permission: "brute:view"},
	}
}

// settingKeys 列出本模块在 settings 表中持久化的键。
var settingKeys = []string{
	"httpFormURL",
	"httpFormUserField",
	"httpFormPassField",
	"httpFormFailText",
}

// bruteStatus 返回当前是否有爆破任务在运行。
func (m *Module) bruteStatus(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	running := m.cancel != nil
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"running": running})
}

// getSettings 读取持久化的模块设置。
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

type settingsRequest struct {
	HTTPFormURL       string `json:"httpFormURL"`
	HTTPFormUserField string `json:"httpFormUserField"`
	HTTPFormPassField string `json:"httpFormPassField"`
	HTTPFormFailText  string `json:"httpFormFailText"`
}

// saveSettings 把模块设置写入引擎 SQLite。
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
		"httpFormURL":       req.HTTPFormURL,
		"httpFormUserField": req.HTTPFormUserField,
		"httpFormPassField": req.HTTPFormPassField,
		"httpFormFailText":  req.HTTPFormFailText,
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

// loadSettingFallback 若 ptr 为空则从 DB 读取兜底值。
func (m *Module) loadSettingFallback(tbl, key string, ptr *string) {
	if *ptr != "" || m.db == nil {
		return
	}
	var v string
	if row := m.db.QueryRow(`SELECT value FROM `+tbl+` WHERE key=?`, key); row.Scan(&v) == nil && v != "" {
		*ptr = v
	}
}

// writeJSON 是内部 HTTP 响应辅助函数。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
