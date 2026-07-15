package sslaudit

// functions.go —— 模块可调用功能自描述 + invoke/task/status/results 入口。
//
// 对外契约（经 AEGIS 后端 /api/v1/engine/m/ssl-audit/* 代理）：
//   GET  /functions         列出本模块可调用功能及参数 schema
//   POST /invoke            {taskId, function, params}：用系统签发的 taskId 发起调用
//   POST /stop              取消当前正在运行的扫描
//   GET  /tasks/<taskId>    轮询任务进度/结果
//   GET  /status            当前扫描实时状态（前端轮询用）
//   GET  /results           当前扫描实时结果（前端轮询用）
//   GET  /findings?taskId=  历史 task 的归档发现

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"redops/core"
)


func fptr(f float64) *float64 { return &f }

// sslFunctions 声明本模块对外可调用的功能目录（前端据此渲染表单）。
func sslFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{{
		ID:          "scan",
		Name:        "SSL/TLS 安全审计",
		Description: "对目标批量检测 SSL/TLS 配置缺陷：证书有效性、弱协议版本（TLS 1.0/1.1）、弱密码套件（RC4/3DES）、HSTS 缺失。",
		Params: []core.ParamSpec{
			{
				Name: "targets", Label: "目标列表", Type: core.ParamStringList, Required: true,
				Placeholder: "每行一个地址：\nexample.com\nexample.com:8443\nhttps://app.example.com",
				Help:        "支持域名、IP 或带端口的地址，默认端口 443，https:// 前缀会自动剥离。",
			},
			{
				Name: "concurrency", Label: "并发数", Type: core.ParamInt,
				Default: 10, Min: fptr(1), Max: fptr(20),
				Help: "同时扫描的主机数，建议 5–15。",
			},
			{
				Name: "timeoutMs", Label: "单主机超时 (ms)", Type: core.ParamInt,
				Default: 10000, Min: fptr(3000), Max: fptr(30000),
				Help: "每台主机 TLS 探测的最大等待时间（毫秒），包含协议探测与 HSTS 请求。",
			},
		},
	}}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": sslFunctions()})
}

// ── /invoke ───────────────────────────────────────────────────────────────────

type invokeRequest struct {
	TaskID    string          `json:"taskId"`
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"`
}

func (m *Module) invokeFunction(w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	switch req.Function {
	case "scan":
		m.invokeScan(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

type scanParams struct {
	Targets     []string `json:"targets"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeoutMs"`
}

func (m *Module) invokeScan(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil || m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪，无法登记任务"})
		return
	}

	// 原子性检查+占位：在同一把锁内完成「空闲检查」与「cancel 赋值」，消除 TOCTOU 竞态。
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描正在运行，请先停止或等待完成"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel // 立即占位，后续参数解析失败时需回退
	m.mu.Unlock()

	// 参数解析失败时释放占位
	releasSlot := func() {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancel()
	}

	// 解析参数
	var p scanParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			releasSlot()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}

	// 支持混合格式：targets 元素内可含换行（前端 stringList 有时整段传）
	var rawLines []string
	for _, t := range p.Targets {
		for _, line := range strings.Split(t, "\n") {
			rawLines = append(rawLines, strings.TrimSpace(line))
		}
	}

	var targets []ScanTarget
	for _, line := range rawLines {
		if t, ok := parseTarget(line); ok {
			targets = append(targets, t)
		}
	}
	targets = dedupTargets(targets)
	if len(targets) == 0 {
		releasSlot()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空，请提供有效的主机地址"})
		return
	}
	if len(targets) > 200 {
		targets = targets[:200]
	}

	concurrency := p.Concurrency
	if concurrency <= 0 || concurrency > 20 {
		concurrency = 10
	}
	timeoutMs := p.TimeoutMs
	if timeoutMs <= 0 || timeoutMs > 60000 {
		timeoutMs = 10000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	taskID := req.TaskID
	if taskID == "" {
		taskID = "eng-" + randHex(6)
	}

	// 登记任务
	if err := m.runs.Start(taskID, "scan"); err != nil {
		releasSlot()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	st := &scanState{
		total:   len(targets),
		startAt: time.Now(),
	}
	m.mu.Lock()
	m.st = st
	m.mu.Unlock()

	go func() {
		// done channel 须在 defer 之前声明，确保 panic recover 路径也能关闭它。
		done := make(chan struct{})
		var closeOnce sync.Once
		closeDone := func() { closeOnce.Do(func() { close(done) }) }

		defer func() {
			closeDone() // 无论正常返回还是 panic，都保证进度 goroutine 能退出
			if rv := recover(); rv != nil {
				m.log.Warn("ssl-audit scan goroutine panicked", "task", taskID, "err", fmt.Sprintf("%v", rv))
				_ = m.runs.Fail(taskID, fmt.Sprintf("panic: %v", rv))
				m.mu.Lock()
				m.cancel = nil
				m.mu.Unlock()
			}
		}()

		// 进度上报 goroutine（600ms 间隔，不阻塞主扫描）
		go func() {
			t := time.NewTicker(600 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					total, probed, found, _, _, _, _ := st.snapshot()
					pct := 0
					if total > 0 {
						pct = probed * 100 / total
					}
					_ = m.runs.Progress(taskID, pct,
						fmt.Sprintf("已扫描 %d/%d，发现 %d 项问题", probed, total, found))
				}
			}
		}()

		// 并发扫描
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, tgt := range targets {
			select {
			case <-ctx.Done():
				goto scanDone // 停止派发新任务，但已启动的 goroutine 须等待
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(t ScanTarget) {
				defer wg.Done()
				defer func() { <-sem }()
				r := scanHost(ctx, t, timeout) // scanHost 内有 per-host ctx timeout，可快速响应取消
				st.addResult(r)
			}(tgt)
		}

	scanDone:
		wg.Wait() // 始终等待飞行中的 goroutine 完成（cancel 后 scanHost 可快速返回）

		// 先更新终态，再关闭 done，确保进度 goroutine 最后读到 done=true
		st.mu.Lock()
		st.done = true
		st.endAt = time.Now()
		if ctx.Err() != nil && st.err == "" {
			st.err = "扫描已停止"
		}
		st.mu.Unlock()

		// 正常完成时推送最终 100% 进度
		if ctx.Err() == nil {
			_, _, found, _, _, _, _ := st.snapshot()
			_ = m.runs.Progress(taskID, 100,
				fmt.Sprintf("扫描完成，已检测 %d 台主机，发现 %d 项问题", len(targets), found))
		}
		closeDone()

		// 落库
		results := st.allResults()
		m.saveFindings(taskID, results)

		_, _, found, _, _, _, _ := st.snapshot()
		if ctx.Err() != nil {
			_ = m.runs.Cancel(taskID, "用户已取消扫描，已保存发现")
		} else {
			_ = m.runs.Succeed(taskID, map[string]any{
				"found":  found,
				"probed": len(results),
				"total":  len(targets),
			})
		}

		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancel()
		m.log.Info("ssl-audit scan complete", "task", taskID,
			"hosts", strconv.Itoa(len(results)), "findings", strconv.Itoa(found))
	}()

	m.log.Info("ssl-audit scan invoked", "task", taskID, "targets", len(targets), "project", req.ProjectID)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

// ── /stop ─────────────────────────────────────────────────────────────────────

func (m *Module) stopScan(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()

	if cancel == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no scan running"})
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

// ── /tasks/* ──────────────────────────────────────────────────────────────────

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

// ── /status ───────────────────────────────────────────────────────────────────

func (m *Module) getStatus(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	running := m.cancel != nil
	st := m.st
	m.mu.Unlock()

	if st == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"running": false, "total": 0, "probed": 0, "found": 0,
		})
		return
	}
	total, probed, found, done, errStr, startAt, endAt := st.snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"running":   running,
		"total":     total,
		"probed":    probed,
		"found":     found,
		"done":      done,
		"error":     errStr,
		"startedAt": startAt,
		"endedAt":   endAt,
	})
}

// ── /results ──────────────────────────────────────────────────────────────────

func (m *Module) getResults(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	st := m.st
	m.mu.Unlock()

	if st == nil {
		writeJSON(w, http.StatusOK, map[string]any{"hosts": []any{}, "stats": map[string]int{}})
		return
	}
	results := st.allResults()
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts": results,
		"stats": calcStats(results),
	})
}

func calcStats(results []*HostResult) map[string]int {
	s := map[string]int{
		"total": len(results), "withIssues": 0,
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, r := range results {
		if len(r.Findings) > 0 {
			s["withIssues"]++
		}
		for _, f := range r.Findings {
			if _, ok := s[f.Severity]; ok {
				s[f.Severity]++
			}
		}
	}
	return s
}
