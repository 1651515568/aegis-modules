package backup

import (
	"context"
	"encoding/json"
	"net/http"

	"redops/core"
)

// Routes 声明业务 HTTP 路由。框架自动挂载到 /api/m/backup/...
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET", Path: "/hits", Handler: m.listHits, Permission: "backup:view"},
		{Method: "GET", Path: "/stats", Handler: m.stats, Permission: "backup:view"},
		{Method: "GET", Path: "/dict", Handler: m.dict, Permission: "backup:view"},
		{Method: "GET", Path: "/export", Handler: m.export, Permission: "backup:view"},
		{Method: "GET", Path: "/scan/status", Handler: m.scanStatus, Permission: "backup:view"},
		{Method: "GET", Path: "/functions", Handler: m.listFunctions, Permission: "backup:view"},
		{Method: "GET", Path: "/findings", Handler: m.listFindings, Permission: "backup:view"},
		{Method: "POST", Path: "/invoke", Handler: m.invokeFunction, Permission: "backup:scan"},
		{Method: "GET", Path: "/tasks/*", Handler: m.getTask, Permission: "backup:view"},
		{Method: "POST", Path: "/scan/stop", Handler: m.stopScan, Permission: "backup:scan"},
		{Method: "POST", Path: "/scan/resume", Handler: m.resumeScan, Permission: "backup:scan"},
		{Method: "POST", Path: "/scan", Handler: m.startScan, Permission: "backup:scan"},
		{Method: "POST", Path: "/hits/clear", Handler: m.clearScanHits, Permission: "backup:scan"},
		{Method: "POST", Path: "/hits/delete", Handler: m.deleteScanHit, Permission: "backup:scan"},
	}
}

func (m *Module) listHits(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": m.store.list()})
}

func (m *Module) stats(w http.ResponseWriter, _ *http.Request) {
	out := m.store.summary()
	out["module"] = m.manifest.ID
	out["version"] = m.manifest.Version
	writeJSON(w, http.StatusOK, out)
}

// dict 暴露字典规模与来源,供前端展示「字典覆盖面」。
func (m *Module) dict(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, dictInfo())
}

// scanStatus 返回当前扫描任务的实时进度(前端轮询用)。
func (m *Module) scanStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, m.store.status())
}

// export 导出命中结果。?format=json|csv|html(默认 json),以附件形式下载。
func (m *Module) export(w http.ResponseWriter, r *http.Request) {
	hits := m.store.list()
	st := m.store.status()
	var body []byte
	var ctype, fname string
	switch r.URL.Query().Get("format") {
	case "csv":
		body, ctype, fname = exportCSV(hits), "text/csv; charset=utf-8", "backup-hits.csv"
	case "html":
		body, ctype, fname = exportHTML(hits, st.Target, st.EndedAt), "text/html; charset=utf-8", "backup-report.html"
	default:
		body, ctype, fname = exportJSON(hits, st.Target, st.EndedAt), "application/json; charset=utf-8", "backup-hits.json"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// clearScanHits 清空全部命中并删除落盘文件。
func (m *Module) clearScanHits(w http.ResponseWriter, _ *http.Request) {
	if m.store.status().Running {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "扫描运行中,无法清空"})
		return
	}
	m.store.clearHits()
	m.log.Info("backup hits cleared")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": m.store.status()})
}

// deleteScanHit 按 id 删除单条命中(请求体 {"id":"..."})。
func (m *Module) deleteScanHit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 id"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": m.store.deleteHit(body.ID)})
}

// startScan 发起一次真实存在性探测。同一时刻只允许一个扫描在跑。
func (m *Module) startScan(w http.ResponseWriter, r *http.Request) {
	var opt scanOptions
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	if len(opt.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空(需为 http(s) URL 或域名)"})
		return
	}

	taskID := fallbackTaskID() // /scan 路径无系统 task_id，生成兜底 id 用于 findings 落库
	ctx, cancel := context.WithCancel(context.Background())
	// 原子地设置 Running=true 和 cancel，防止 stop() 在窗口期到达时因 cancel==nil 失效。
	if !m.store.tryBeginScanWithCancel("(解析中…)", false, cancel) {
		cancel()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描在运行,请先停止或等待完成"})
		return
	}
	m.store.setJob(&scanJob{Opts: opt, Status: "running", StartedAt: nowStamp()})
	go func() {
		m.sc.run(ctx, opt)
		m.saveFindings(taskID) // 扫描结束后持久化命中，与 /invoke 路径保持一致
	}()

	m.log.Info("backup scan requested", "targets", len(opt.Targets))
	writeJSON(w, http.StatusAccepted, m.store.status())
}

// resumeScan 续扫上次未完成的任务(跳过已完成目标,在原结果上追加)。
func (m *Module) resumeScan(w http.ResponseWriter, _ *http.Request) {
	job, done, ok := m.store.tryBeginResume()
	if !ok {
		if m.store.status().Running {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描在运行"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无可续扫的未完成任务"})
		}
		return
	}
	taskID := fallbackTaskID()
	ctx, cancel := context.WithCancel(context.Background())
	m.store.setCancel(cancel)
	m.store.setJobStatus("running")
	go func() {
		m.sc.runScan(ctx, job.Opts, done)
		m.saveFindings(taskID)
	}()

	m.log.Info("backup scan resumed", "remaining", job.remaining())
	writeJSON(w, http.StatusAccepted, m.store.status())
}

// stopScan 取消正在运行的扫描。
func (m *Module) stopScan(w http.ResponseWriter, _ *http.Request) {
	stopped := m.store.stop()
	writeJSON(w, http.StatusOK, map[string]any{"stopped": stopped, "status": m.store.status()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
