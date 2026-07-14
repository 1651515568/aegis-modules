package probe

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes 声明业务 HTTP 路由，框架挂载到 /api/m/scan-probe/...
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET", Path: "/functions", Handler: m.listFunctions, Permission: "probe:view"},
		{Method: "GET",  Path: "/findings",       Handler: m.listFindings,  Permission: "probe:view"},
		{Method: "POST", Path: "/findings/clear", Handler: m.clearFindings, Permission: "probe:scan"},
		{Method: "GET",  Path: "/results",        Handler: m.listResults,   Permission: "probe:view"},
		{Method: "GET", Path: "/tasks/*", Handler: m.getTask, Permission: "probe:view"},
		{Method: "POST", Path: "/invoke", Handler: m.invokeFunction, Permission: "probe:scan"},
		{Method: "POST", Path: "/stop", Handler: m.stopProbe, Permission: "probe:scan"},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
