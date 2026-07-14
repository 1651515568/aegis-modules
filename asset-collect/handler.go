package assetcollect

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes declares the HTTP routes for the asset-collect module.
// 路由约定（框架剥掉 /api/m/asset-collect 前缀）：
//   GET  /functions         功能 schema 自描述
//   GET  /status            当前是否有任务运行
//   GET  /findings          按 task_id 取归档资产（见 findings.go）
//   POST /findings/clear    清除指定 task_id 的归档（见 findings.go）
//   GET  /settings          读取情报源 API Key 配置
//   POST /settings          保存情报源 API Key 配置
//   POST /invoke            发起资产收集（见 functions.go）
//   POST /stop              停止当前收集
//   GET  /tasks/*           按 task_id 查进度（见 functions.go）
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",  Path: "/functions",      Handler: m.listFunctions,  Permission: "asset:view"},
		{Method: "GET",  Path: "/status",         Handler: m.collectStatus,  Permission: "asset:view"},
		{Method: "GET",  Path: "/findings",       Handler: m.listFindings,   Permission: "asset:view"},
		{Method: "POST", Path: "/findings/clear", Handler: m.clearFindings,  Permission: "asset:collect"},
		{Method: "GET",  Path: "/settings",       Handler: m.getSettings,    Permission: "asset:view"},
		{Method: "POST", Path: "/settings",       Handler: m.saveSettings,   Permission: "asset:collect"},
		{Method: "POST", Path: "/invoke",         Handler: m.invokeFunction, Permission: "asset:collect"},
		{Method: "POST", Path: "/stop",           Handler: m.stopCollect,    Permission: "asset:collect"},
		{Method: "GET",  Path: "/tasks/*",        Handler: m.getTask,        Permission: "asset:view"},
	}
}

var settingKeys = []string{
	"hunterKey", "zoomeyeKey", "quakeKey", "zerozoneKey",
	"fofaEmail", "fofaKey", "shodanKey",
	"securitytrailsKey", "censysId", "censysSecret",
	"virusTotalKey", "chaosKey", "threatbookKey",
	"tianyanchaKey", "qccKey", "aiqichaKey",
	"xiaolanbenKey", "qimaiKey", "fengniaKey",
}

func (m *Module) collectStatus(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	running := m.cancel != nil
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"running": running})
}

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
	TianYanChaKey     string `json:"tianyanchaKey"`
	QCCKey            string `json:"qccKey"`
	AiQiChaKey        string `json:"aiqichaKey"`
	XiaoLanBenKey     string `json:"xiaolanbenKey"`
	QiMaiKey          string `json:"qimaiKey"`
	FengNiaoKey       string `json:"fengniaKey"`
}

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
		"hunterKey": req.HunterKey, "zoomeyeKey": req.ZoomeyeKey,
		"quakeKey": req.QuakeKey, "zerozoneKey": req.ZerozoneKey,
		"fofaEmail": req.FOFAEmail, "fofaKey": req.FOFAKey,
		"shodanKey": req.ShodanKey, "securitytrailsKey": req.SecurityTrailsKey,
		"censysId": req.CensysID, "censysSecret": req.CensysSecret,
		"virusTotalKey": req.VirusTotalKey, "chaosKey": req.ChaosKey,
		"threatbookKey": req.ThreatBookKey,
		"tianyanchaKey": req.TianYanChaKey, "qccKey": req.QCCKey,
		"aiqichaKey": req.AiQiChaKey, "xiaolanbenKey": req.XiaoLanBenKey,
		"qimaiKey": req.QiMaiKey, "fengniaKey": req.FengNiaoKey,
	}
	for k, v := range kvs {
		if v == "" {
			continue // 空字段 = 保留已有值，不覆盖
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
