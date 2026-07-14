package sslaudit

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes 声明业务 HTTP 路由，框架自动挂载到 /api/m/ssl-audit/...
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",  Path: "/functions", Handler: m.listFunctions, Permission: "ssl:view"},
		{Method: "POST", Path: "/invoke",    Handler: m.invokeFunction, Permission: "ssl:scan"},
		{Method: "POST", Path: "/stop",      Handler: m.stopScan,       Permission: "ssl:scan"},
		{Method: "GET",  Path: "/tasks/*",   Handler: m.getTask,        Permission: "ssl:view"},
		{Method: "GET",  Path: "/status",    Handler: m.getStatus,      Permission: "ssl:view"},
		{Method: "GET",  Path: "/results",   Handler: m.getResults,     Permission: "ssl:view"},
		{Method: "GET",  Path: "/findings",  Handler: m.listFindings,   Permission: "ssl:view"},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
