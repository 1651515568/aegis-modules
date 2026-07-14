package subdomain

import (
	"encoding/json"
	"net/http"
	"strings"

	"redops/core"
)

// Routes 声明业务 HTTP 路由，框架挂载到 /api/m/scan-subdomain/...
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET", Path: "/functions", Handler: m.listFunctions, Permission: "subdomain:view"},
		{Method: "GET", Path: "/status", Handler: m.scanStatus, Permission: "subdomain:view"},
		{Method: "GET",  Path: "/findings",       Handler: m.listFindings,  Permission: "subdomain:view"},
		{Method: "POST", Path: "/findings/clear", Handler: m.clearFindings, Permission: "subdomain:scan"},
		{Method: "GET", Path: "/settings", Handler: m.getSettings, Permission: "subdomain:view"},
		{Method: "POST", Path: "/settings", Handler: m.saveSettings, Permission: "subdomain:scan"},
		{Method: "DELETE", Path: "/settings/*", Handler: m.deleteSettingKey, Permission: "subdomain:scan"},
		{Method: "POST", Path: "/invoke", Handler: m.invokeFunction, Permission: "subdomain:scan"},
		{Method: "POST", Path: "/stop", Handler: m.stopScan, Permission: "subdomain:scan"},
		{Method: "GET", Path: "/tasks/*", Handler: m.getTask, Permission: "subdomain:view"},
	}
}

// settingKeys 是受管的情报源 API Key 名称列表，与 scanOptions 字段对应。
var settingKeys = []string{
	"hunterKey", "zoomeyeKey", "quakeKey", "zerozoneKey",
	"fofaEmail", "fofaKey", "shodanKey",
	"securitytrailsKey", "censysId", "censysSecret",
	"virusTotalKey", "chaosKey", "threatbookKey",
}

// scanStatus 返回当前是否有枚举任务在运行，供前端挂载时检测。
func (m *Module) scanStatus(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	running := m.cancel != nil
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"running": running})
}

// getSettings 返回已持久化的情报源 API Key 配置状态，已配置的 Key 脱敏为 "****"，避免明文泄露。
func (m *Module) getSettings(w http.ResponseWriter, _ *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	tbl := m.db.Table("settings")
	result := make(map[string]string, len(settingKeys))
	for _, k := range settingKeys {
		var v string
		if row := m.db.QueryRow(`SELECT value FROM `+tbl+` WHERE key=?`, k); row.Scan(&v) == nil && v != "" {
			result[k] = "****" // 脱敏：仅告知"已配置"，不返回实际 Key
		} else {
			result[k] = ""
		}
	}
	writeJSON(w, http.StatusOK, result)
}

type settingsRequest struct {
	HunterKey         string `json:"hunterKey"`
	ZoomeyeKey        string `json:"zoomeyeKey"`
	QuakeKey          string `json:"quakeKey"`
	ZerozoneKey       string `json:"zerozoneKey"`
	FOFAEmail         string `json:"fofaEmail"`
	FOFAKey           string `json:"fofaKey"`
	ShodanKey         string `json:"shodanKey"`
	SecurityTrailsKey string `json:"securitytrailsKey"`
	CensysID          string `json:"censysId"`
	CensysSecret      string `json:"censysSecret"`
	VirusTotalKey     string `json:"virusTotalKey"`
	ChaosKey          string `json:"chaosKey"`
	ThreatBookKey     string `json:"threatbookKey"`
}

// saveSettings 持久化情报源 API Key 到引擎 SQLite。
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
		"hunterKey":         req.HunterKey,
		"zoomeyeKey":        req.ZoomeyeKey,
		"quakeKey":          req.QuakeKey,
		"zerozoneKey":       req.ZerozoneKey,
		"fofaEmail":         req.FOFAEmail,
		"fofaKey":           req.FOFAKey,
		"shodanKey":         req.ShodanKey,
		"securitytrailsKey": req.SecurityTrailsKey,
		"censysId":          req.CensysID,
		"censysSecret":      req.CensysSecret,
		"virusTotalKey":     req.VirusTotalKey,
		"chaosKey":          req.ChaosKey,
		"threatbookKey":     req.ThreatBookKey,
	}
	for k, v := range kvs {
		if v == "" {
			// 空字符串跳过写入，防止"只想更新一个 Key"时意外清空其他已保存的 Key。
			continue
		}
		if _, err := m.db.Exec(
			`INSERT OR REPLACE INTO `+tbl+` (key, value, updated_at) VALUES (?, ?, datetime('now'))`, k, v,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存失败: " + err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// deleteSettingKey 删除单个情报源 API Key：DELETE /settings/:key
// 解决 saveSettings 跳过空字符串后用户无法主动清除某个已保存 Key 的问题。
func (m *Module) deleteSettingKey(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	// 取路径末段作为 key 名称（路由模式 /settings/*）
	key := strings.TrimPrefix(r.URL.Path, "/settings/")
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key 不能为空"})
		return
	}
	// 白名单校验：仅允许删除已声明的配置 key，防止任意路径注入
	allowed := false
	for _, k := range settingKeys {
		if k == key {
			allowed = true
			break
		}
	}
	if !allowed {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "未知 key: " + key})
		return
	}
	tbl := m.db.Table("settings")
	if _, err := m.db.Exec(`DELETE FROM `+tbl+` WHERE key=?`, key); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "删除失败: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "key": key})
}

// loadSettingFallback 若 *ptr 为空，从 settings 表中读取已存的值填入。
func (m *Module) loadSettingFallback(tbl, key string, ptr *string) {
	if *ptr != "" || m.db == nil {
		return
	}
	var v string
	if row := m.db.QueryRow(`SELECT value FROM `+tbl+` WHERE key=?`, key); row.Scan(&v) == nil && v != "" {
		*ptr = v
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
