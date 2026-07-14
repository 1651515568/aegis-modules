package vulnpoc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"strconv"

	"redops/core"
)

func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",    Path: "/entries",         Handler: m.handleList,           Permission: "vuln:view"},
		{Method: "POST",   Path: "/entries",         Handler: m.handleCreate,         Permission: "vuln:scan"},
		{Method: "GET",    Path: "/entry",           Handler: m.handleGet,            Permission: "vuln:view"},
		{Method: "PUT",    Path: "/entry",           Handler: m.handleUpdate,         Permission: "vuln:scan"},
		{Method: "DELETE", Path: "/entry",           Handler: m.handleDelete,         Permission: "vuln:scan"},
		{Method: "POST",   Path: "/entry/run",       Handler: m.handleRun,            Permission: "vuln:scan"},
		{Method: "POST",   Path: "/entry/stop",      Handler: m.handleStop,           Permission: "vuln:scan"},
		{Method: "POST",   Path: "/entry/status",    Handler: m.handleSetStatus,      Permission: "vuln:scan"},
		{Method: "POST",   Path: "/import",          Handler: m.handleImport,         Permission: "vuln:scan"},
		{Method: "GET",    Path: "/search/template", Handler: m.handleTemplateSearch, Permission: "vuln:view"},
		// 漏洞库
		{Method: "GET",    Path: "/library",         Handler: m.handleLibrary,        Permission: "vuln:view"},
		{Method: "GET",    Path: "/library/stats",   Handler: m.handleLibraryStats,   Permission: "vuln:view"},
		{Method: "POST",   Path: "/library/rebuild", Handler: m.handleLibraryRebuild, Permission: "vuln:scan"},
		{Method: "POST",   Path: "/library/run",     Handler: m.handleLibraryRun,     Permission: "vuln:scan"},
	}
}

// GET /entries?status=confirmed&severity=high&search=xxx
func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	statusF := q.Get("status")
	sevF := q.Get("severity")
	search := strings.ToLower(q.Get("search"))

	all := m.store.list()
	var filtered []*Entry
	for _, e := range all {
		if statusF != "" && string(e.Status) != statusF {
			continue
		}
		if sevF != "" && !strings.EqualFold(e.Severity, sevF) {
			continue
		}
		if search != "" {
			hay := strings.ToLower(e.Name + " " + e.Target + " " + e.Template)
			if !strings.Contains(hay, search) {
				continue
			}
		}
		filtered = append(filtered, e)
	}

	// 统计各状态数量
	stats := map[string]int{
		"unconfirmed": 0, "confirmed": 0, "fixing": 0, "fixed": 0,
	}
	for _, e := range all {
		if _, ok := stats[string(e.Status)]; ok {
			stats[string(e.Status)]++
		}
	}

	var runningIDs []string
	for _, e := range all {
		if m.store.isRunning(e.ID) {
			runningIDs = append(runningIDs, e.ID)
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"entries":    filtered,
		"total":      len(filtered),
		"stats":      stats,
		"runningIds": runningIDs,
	})
}

// GET /entry?id=xxx
func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	e := m.store.get(id)
	if e == nil {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"entry": e, "running": m.store.isRunning(id)})
}

// POST /entries — 创建新条目
func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	var e Entry
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	if strings.TrimSpace(e.Target) == "" || strings.TrimSpace(e.Template) == "" {
		writeJSON(w, 400, map[string]string{"error": "target 和 template 不能为空"})
		return
	}
	m.store.create(&e)
	m.store.save()
	writeJSON(w, 200, map[string]interface{}{"entry": &e})
}

// PUT /entry?id=xxx — 更新名称/备注/标签等
func (m *Module) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var patch struct {
		Name     *string  `json:"name"`
		Note     *string  `json:"note"`
		Severity *string  `json:"severity"`
		Tags     []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ok := m.store.update(id, func(e *Entry) {
		if patch.Name != nil {
			e.Name = *patch.Name
		}
		if patch.Note != nil {
			e.Note = *patch.Note
		}
		if patch.Severity != nil {
			e.Severity = *patch.Severity
		}
		if patch.Tags != nil {
			e.Tags = patch.Tags
		}
	})
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
		return
	}
	m.store.save()
	writeJSON(w, 200, map[string]string{"message": "已更新"})
}

// DELETE /entry?id=xxx
func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	m.store.stopRun(id)
	if !m.store.delete(id) {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
		return
	}
	m.store.save()
	writeJSON(w, 200, map[string]string{"message": "已删除"})
}

// POST /entry/run?id=xxx — 执行 PoC 验证
func (m *Module) handleRun(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if m.store.get(id) == nil {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
		return
	}
	if m.store.isRunning(id) {
		writeJSON(w, 409, map[string]string{"error": "该条目正在验证中"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	if !m.store.beginRun(id, cancel) {
		cancel()
		writeJSON(w, 409, map[string]string{"error": "已在运行"})
		return
	}
	go m.runner.Run(ctx, id)
	writeJSON(w, 200, map[string]string{"message": "验证已启动"})
}

// POST /entry/stop?id=xxx
func (m *Module) handleStop(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if m.store.stopRun(id) {
		writeJSON(w, 200, map[string]string{"message": "已发送停止信号"})
	} else {
		writeJSON(w, 409, map[string]string{"error": "该条目未在运行"})
	}
}

// POST /entry/status?id=xxx — 手动切换生命周期状态
func (m *Module) handleSetStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	validStatus := map[string]bool{
		"unconfirmed": true, "confirmed": true, "fixing": true, "fixed": true,
	}
	if !validStatus[body.Status] {
		writeJSON(w, 400, map[string]string{"error": "无效状态"})
		return
	}
	ok := m.store.update(id, func(e *Entry) {
		e.Status = Status(body.Status)
	})
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
		return
	}
	m.store.save()
	writeJSON(w, 200, map[string]string{"message": "状态已更新"})
}

// POST /import — 从 vuln-scan 结果批量导入
// Body: [{ name, target, template, severity, tags, sourceScan, sourceHit }]
func (m *Module) handleImport(w http.ResponseWriter, r *http.Request) {
	var items []Entry
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	created := 0
	for i := range items {
		if items[i].Target == "" || items[i].Template == "" {
			continue
		}
		m.store.create(&items[i])
		created++
	}
	m.store.save()
	writeJSON(w, 200, map[string]interface{}{"created": created})
}

// GET /search/template?q=xxx&limit=20 — 模板关键词搜索
func (m *Module) handleTemplateSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}
	results := TemplateSearch(q, limit)
	writeJSON(w, 200, map[string]interface{}{"templates": results})
}

// ─── 漏洞库处理函数 ──────────────────────────────────────────────────────────

// GET /library?search=&severity=&category=&source=&page=&pageSize=
func (m *Module) handleLibrary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("pageSize"))
	result := m.lib.Query(LibraryQuery{
		Search:   q.Get("search"),
		Severity: q.Get("severity"),
		Category: q.Get("category"),
		Source:   q.Get("source"),
		Page:     page,
		PageSize: pageSize,
	})
	writeJSON(w, 200, result)
}

// GET /library/stats
func (m *Module) handleLibraryStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, m.lib.Stats())
}

// POST /library/rebuild — 强制重建索引
func (m *Module) handleLibraryRebuild(w http.ResponseWriter, r *http.Request) {
	m.lib.Rebuild()
	writeJSON(w, 200, map[string]string{"message": "重建索引已启动"})
}

// POST /library/run — 对指定目标运行一条库中的模板
// Body: { target: string, filePath: string, name: string, severity: string }
func (m *Module) handleLibraryRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target   string `json:"target"`
		FilePath string `json:"filePath"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Target == "" || body.FilePath == "" {
		writeJSON(w, 400, map[string]string{"error": "target 和 filePath 不能为空"})
		return
	}
	// 若为绝对路径，校验必须位于允许的模板目录内，防止任意文件路径穿越
	if filepath.IsAbs(body.FilePath) {
		home, _ := os.UserHomeDir()
		allowedRoots := []string{
			filepath.Join(home, "nuclei-templates"),
			filepath.Join(home, "custom-templates"),
		}
		allowed := false
		for _, root := range allowedRoots {
			rel, err := filepath.Rel(root, body.FilePath)
			if err == nil && !strings.HasPrefix(rel, "..") {
				allowed = true
				break
			}
		}
		if !allowed {
			writeJSON(w, 400, map[string]string{"error": "模板路径超出允许的目录范围"})
			return
		}
	}
	e := &Entry{
		Name:     body.Name,
		Target:   body.Target,
		Template: body.FilePath,
		Severity: body.Severity,
	}
	m.store.create(e)
	m.store.save()

	ctx, cancel := context.WithCancel(context.Background())
	m.store.beginRun(e.ID, cancel)
	go m.runner.Run(ctx, e.ID)

	writeJSON(w, 200, map[string]interface{}{"entryId": e.ID, "message": "已创建条目并启动验证"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
