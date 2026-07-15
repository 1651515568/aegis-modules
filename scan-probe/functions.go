package probe

// functions.go — 模块「可调用功能」自描述 + 通用 invoke/task 入口。
//
// 对外契约（经 AEGIS 后端 /api/v1/engine/m/scan-probe/* 代理）：
//   GET  /functions        列出可调用功能及参数 schema
//   POST /invoke           {taskId, function, params}：发起调用
//   POST /stop             停止当前运行中的探测
//   GET  /tasks/<taskId>   轮询任务进度/结果（读自 task_runs 表）

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"redops/core"
)

func fptr(f float64) *float64 { return &f }

func probeFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "probe",
			Name:        "Web 指纹识别",
			Description: "对目标进行 HTTP 指纹探测，识别 CMS、WAF、服务器、框架等信息。",
			Params: []core.ParamSpec{
				{
					Name:        "targets",
					Label:       "目标列表",
					Type:        core.ParamStringList,
					Required:    true,
					Placeholder: "每行一个目标，如 http://192.168.1.1\nhttps://example.com",
					Help:        "支持 http:// 或 https://；无协议头默认尝试 http，失败时回退 https",
				},
				{
					Name:    "threads",
					Label:   "并发数",
					Type:    core.ParamInt,
					Default: 20,
					Min:     fptr(1),
					Max:     fptr(200),
					Help:    "并发探测线程数，默认 20，上限 200",
				},
				{
					Name:    "timeoutMs",
					Label:   "超时(ms)",
					Type:    core.ParamInt,
					Default: 5000,
					Min:     fptr(500),
					Max:     fptr(30000),
					Help:    "单目标请求超时，默认 5000ms",
				},
				{
					Name:    "detectWaf",
					Label:   "WAF 识别",
					Type:    core.ParamBool,
					Default: true,
					Help:    "启用 WAF/CDN 特征识别",
				},
				{
					Name:    "detectCms",
					Label:   "CMS 指纹",
					Type:    core.ParamBool,
					Default: true,
					Help:    "启用 CMS 指纹识别（WordPress、Drupal、帆软等）及 favicon hash 匹配",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": probeFunctions()})
}

type invokeRequest struct {
	TaskID    string          `json:"taskId"`
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"`
}

func fallbackTaskID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "eng-" + hex.EncodeToString(b)
}

func (m *Module) invokeFunction(w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	switch req.Function {
	case "probe":
		m.invokeProbe(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

func (m *Module) invokeProbe(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	if m.sc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "指纹识别引擎未就绪"})
		return
	}

	// Reject concurrent invocations.
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有探测任务在运行，请先停止"})
		return
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	m.cancel = cancelFn
	m.mu.Unlock()

	var opts scanOptions
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &opts); err != nil {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
			cancelFn()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}
	if len(opts.Targets) == 0 {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	if err := m.runs.Start(taskID, "probe"); err != nil {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	go func() {
		defer m.runs.GuardPanic(taskID, m.log)
		defer cancelFn() // 扫描结束时释放 ctx 资源，防止 context goroutine 泄漏
		defer func() {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		total := len(opts.Targets)
		results, err := m.sc.run(ctx, opts, func(done, _ int) {
			p := 0
			if total > 0 {
				p = done * 100 / total
			}
			_ = m.runs.Progress(taskID, p, fmt.Sprintf("已探测 %d/%d", done, total))
		})
		// 过滤所有方案均失败（StatusCode=0）的空白结果，不写入持久化以保持结果表干净。
		valid := make([]ProbeResult, 0, len(results))
		for _, r := range results {
			if r.StatusCode > 0 {
				valid = append(valid, r)
			}
		}
		results = valid
		if err != nil {
			if ctx.Err() != nil {
				m.saveFindings(taskID, results)
				_ = m.runs.Cancel(taskID, fmt.Sprintf("用户手动停止，已保存 %d 条结果", len(results)))
			} else {
				_ = m.runs.Fail(taskID, err.Error())
			}
			return
		}
		m.saveFindings(taskID, results)
		_ = m.runs.Progress(taskID, 100, fmt.Sprintf("探测完成，有效结果 %d 条", len(results)))
		_ = m.runs.Succeed(taskID, map[string]any{
			"total":   len(results),
			"results": results,
		})
	}()

	m.log.Info("probe invoked", "task", taskID, "targets", len(opts.Targets), "project", req.ProjectID)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

func (m *Module) stopProbe(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stopped": false, "msg": "无运行中的探测任务"})
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
}

// listResults retrieves the latest archived probe results across all tasks: GET /results
// Returns the most recent 500 rows (newest first). Used by the frontend to restore state on mount.
func (m *Module) listResults(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
		return
	}
	table := m.db.Table("results")
	rows, err := m.db.Query(
		"SELECT host,port,protocol,cms,framework,waf,server,title,status_code,os,favicon_hash,components,found_at"+
			" FROM "+table+" ORDER BY rowid DESC LIMIT 500",
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type findingRow struct {
		Host        string   `json:"host"`
		Port        int      `json:"port"`
		Protocol    string   `json:"protocol"`
		CMS         string   `json:"cms"`
		Framework   string   `json:"framework"`
		WAF         string   `json:"waf"`
		Server      string   `json:"server"`
		Title       string   `json:"title"`
		StatusCode  int      `json:"statusCode"`
		OS          string   `json:"os"`
		FaviconHash int32    `json:"faviconHash,omitempty"`
		Components  []string `json:"components,omitempty"`
		FoundAt     string   `json:"foundAt"`
	}
	items := make([]findingRow, 0)
	for rows.Next() {
		var fr findingRow
		var compsJSON string
		if err := rows.Scan(&fr.Host, &fr.Port, &fr.Protocol, &fr.CMS, &fr.Framework,
			&fr.WAF, &fr.Server, &fr.Title, &fr.StatusCode, &fr.OS, &fr.FaviconHash,
			&compsJSON, &fr.FoundAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal([]byte(compsJSON), &fr.Components)
		items = append(items, fr)
	}
	// SQL 已使用 ORDER BY rowid DESC，items 已是最新在前，无需再次反转。
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (m *Module) getTask(w http.ResponseWriter, r *http.Request) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	id := path.Base(r.URL.Path)
	t, ok, err := m.runs.Get(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}
