package scandir

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"redops/core"
)

// Routes 声明业务 HTTP 路由。框架自动挂载到 /api/m/scan-dir/...
//
// 契约分两类:
//   - 统一异步契约(AEGIS 必需):/functions、/invoke、/tasks/<id>、/findings
//   - 实时/辅助视图(可选,§5.6):/hits、/dict、/export、/scan*、/history*
//
// 权威、可审计、可固化的任务台账只走 /invoke + /tasks/<id>;/scan 等为引擎本地实时视图,
// 便于直连引擎调试与界面轮询展示当前扫描细节。
func (m *Module) Routes() []core.Route {
	return []core.Route{
		// 统一异步契约
		{Method: "GET", Path: "/functions", Handler: m.listFunctions, Permission: "dirscan:view"},
		{Method: "GET", Path: "/findings", Handler: m.listFindings, Permission: "dirscan:view"},
		{Method: "GET", Path: "/tasks/*", Handler: m.getTask, Permission: "dirscan:view"},
		{Method: "POST", Path: "/invoke", Handler: m.invokeFunction, Permission: "dirscan:scan"},

		// 实时/辅助视图
		{Method: "GET", Path: "/hits", Handler: m.listHits, Permission: "dirscan:view"},
		{Method: "GET", Path: "/dict", Handler: m.dict, Permission: "dirscan:view"},
		{Method: "GET", Path: "/export", Handler: m.export, Permission: "dirscan:view"},
		{Method: "GET", Path: "/scan/status", Handler: m.scanStatus, Permission: "dirscan:view"},
		{Method: "GET", Path: "/history", Handler: m.listHistory, Permission: "dirscan:view"},
		{Method: "GET", Path: "/history/get", Handler: m.getHistory, Permission: "dirscan:view"},
		{Method: "POST", Path: "/history/delete", Handler: m.deleteHistory, Permission: "dirscan:scan"},
		{Method: "POST", Path: "/scan/stop", Handler: m.stopScan, Permission: "dirscan:scan"},
		{Method: "POST", Path: "/scan/resume", Handler: m.resumeScan, Permission: "dirscan:scan"},
		{Method: "POST", Path: "/scan", Handler: m.startScan, Permission: "dirscan:scan"},
	}
}

func (m *Module) listHits(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": m.store.list()})
}

// dict 暴露内置字典规模与预设,供前端展示与选择。
func (m *Module) dict(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, dictInfo())
}

// scanStatus 返回当前扫描任务的实时进度(前端轮询用)。
func (m *Module) scanStatus(w http.ResponseWriter, _ *http.Request) {
	st := m.store.status()
	writeJSON(w, http.StatusOK, map[string]any{"status": st, "id": m.store.currentID()})
}

// listHistory 返回引擎本地的最近扫描摘要(非权威台账)。
func (m *Module) listHistory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": m.store.listTasks()})
}

// getHistory 按 id 返回某次本地扫描的完整结果(/history/get?id=...)。
func (m *Module) getHistory(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	t, ok := m.store.taskByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// deleteHistory 删除一条本地扫描记录(请求体 {"id":"..."})。
func (m *Module) deleteHistory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 id"})
		return
	}
	ok := m.store.deleteTask(body.ID)
	if ok {
		m.store.persist()
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": ok})
}

// startScan 发起一次「引擎本地」扫描(不登记 AEGIS 台账,供直连调试/实时视图)。
// 经 AEGIS 用界面发起扫描应走 POST /invoke,以获得统一 task_id 与可固化进度。
func (m *Module) startScan(w http.ResponseWriter, r *http.Request) {
	var opt scanOptions
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	if len(opt.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}
	name := opt.Name
	if name == "" {
		name = "目录扫描任务"
	}
	id := genTaskID()

	ctx, cancel := context.WithCancel(context.Background())
	if !m.store.tryBeginScan(id, name, opt.Targets, opt) {
		cancel()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描在运行,请先停止或等待完成"})
		return
	}
	m.store.setCancel(cancel)
	sc := newScanner(m.log, m.store)
	go func() {
		defer cancel() // 确保扫描正常结束时也释放 ctx 资源，防止 context 泄漏
		sc.run(ctx, opt)
	}()

	m.log.Info("dirscan requested", "id", id, "targets", len(opt.Targets), "wordlist", opt.Wordlist)
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": m.store.status()})
}

// stopScan 取消正在运行的扫描。
func (m *Module) stopScan(w http.ResponseWriter, _ *http.Request) {
	stopped := m.store.stop()
	writeJSON(w, http.StatusOK, map[string]any{"stopped": stopped, "status": m.store.status()})
}

// resumeScan 续扫上次被中断的扫描(从检查点恢复待扫基目录队列,保留已有命中)。
// beginResume 内部原子地检查+设置 Running，无需外部预检。
func (m *Module) resumeScan(w http.ResponseWriter, _ *http.Request) {
	opt, ok := m.store.beginResume()
	if !ok {
		if m.store.status().Running {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描在运行"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无可续扫的任务"})
		}
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.store.setCancel(cancel)
	sc := newScanner(m.log, m.store)
	go sc.runResumable(ctx, opt, true)

	m.log.Info("dirscan resumed")
	writeJSON(w, http.StatusAccepted, map[string]any{"id": m.store.currentID(), "status": m.store.status()})
}

var taskSeq int64

func genTaskID() string {
	return fmt.Sprintf("t%d-%d", time.Now().UnixNano(), atomic.AddInt64(&taskSeq, 1))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
