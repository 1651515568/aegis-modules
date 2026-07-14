package webshell

import (
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes 返回 webshell 模块的 HTTP 路由表（含 Permission 字段）。
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",    Path: "/shells",          Handler: m.listShells,     Permission: "webshell:view"},
		{Method: "POST",   Path: "/shells",          Handler: m.addShell,       Permission: "webshell:manage"},
		{Method: "GET",    Path: "/shells/generate", Handler: m.genCode,        Permission: "webshell:manage"},
		{Method: "GET",    Path: "/shells/*",        Handler: m.shellGetOps,    Permission: "webshell:view"},
		{Method: "POST",   Path: "/shells/*",        Handler: m.shellPostOps,   Permission: "webshell:manage"},
		{Method: "PUT",    Path: "/shells/*",        Handler: m.shellPutOps,    Permission: "webshell:manage"},
		{Method: "DELETE", Path: "/shells/*",        Handler: m.shellDeleteOps, Permission: "webshell:manage"},
		{Method: "GET",    Path: "/functions",       Handler: m.listFunctions,  Permission: "webshell:view"},
		{Method: "POST",   Path: "/invoke",          Handler: m.invokeFunction, Permission: "webshell:manage"},
		{Method: "GET",    Path: "/tasks/*",         Handler: m.getTask,        Permission: "webshell:view"},
	}
}

// listFunctions 返回可调用功能目录（webshell 所有操作均为交互式同步接口，无异步任务）。
func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": []core.FunctionSpec{}})
}

// invokeFunction webshell 无长耗时异步功能，交互操作通过 /shells/* 系列接口直接调用。
func (m *Module) invokeFunction(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "webshell 操作均为交互式同步调用，无异步任务；请使用 /shells/<id>/<action> 系列接口",
	})
}

// getTask webshell 模块无 TaskRuns 持久化，始终返回 503。
func (m *Module) getTask(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "webshell 模块无异步任务"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
