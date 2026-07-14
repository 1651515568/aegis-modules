package jsextract

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes 声明业务 HTTP 路由，框架挂载到 /api/m/js-extract/...
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",  Path: "/functions",      Handler: m.listFunctions,  Permission: "jsextract:view"},
		{Method: "GET",  Path: "/findings",       Handler: m.listFindings,   Permission: "jsextract:view"},
		{Method: "POST", Path: "/findings/clear", Handler: m.clearFindings,  Permission: "jsextract:scan"},
		{Method: "GET",  Path: "/tasks/*",        Handler: m.getTask,        Permission: "jsextract:view"},
		{Method: "GET",  Path: "/files/*",        Handler: m.serveFiles,     Permission: "jsextract:view"},
		{Method: "POST", Path: "/invoke",         Handler: m.invokeFunction, Permission: "jsextract:scan"},
		{Method: "POST", Path: "/stop",           Handler: m.stopScan,       Permission: "jsextract:scan"},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
