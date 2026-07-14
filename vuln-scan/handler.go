package vulnscan

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"redops/core"
)

func (m *Module) Routes() []core.Route {
	return []core.Route{
		// 扫描控制
		{Method: "GET", Path: "/status", Handler: m.handleStatus, Permission: "vuln:view"},
		{Method: "POST", Path: "/start", Handler: m.handleStart, Permission: "vuln:scan"},
		{Method: "POST", Path: "/stop", Handler: m.handleStop, Permission: "vuln:scan"},
		// 结果管理
		{Method: "GET", Path: "/results", Handler: m.handleListResults, Permission: "vuln:view"},
		{Method: "DELETE", Path: "/results", Handler: m.handleClearResults, Permission: "vuln:scan"},
		{Method: "DELETE", Path: "/result", Handler: m.handleDeleteResult, Permission: "vuln:scan"},
		{Method: "PATCH", Path: "/result", Handler: m.handleUpdateResult, Permission: "vuln:scan"},
		{Method: "POST", Path: "/results/batch", Handler: m.handleBatchUpdate, Permission: "vuln:scan"},
		// 模板 & 导出
		{Method: "GET", Path: "/templates", Handler: m.handleTemplates, Permission: "vuln:view"},
		{Method: "GET", Path: "/export", Handler: m.handleExport, Permission: "vuln:view"},
		// 任务历史
		{Method: "GET", Path: "/tasks", Handler: m.handleListTasks, Permission: "vuln:view"},
		{Method: "DELETE", Path: "/task", Handler: m.handleDeleteTask, Permission: "vuln:scan"},
		// 断点续扫
		{Method: "POST", Path: "/resume", Handler: m.handleResume, Permission: "vuln:scan"},
		// 资产规范化预览
		{Method: "POST", Path: "/normalize", Handler: m.handleNormalize, Permission: "vuln:view"},
		// 目标列表
		{Method: "GET", Path: "/target-lists", Handler: m.handleListTargetLists, Permission: "vuln:view"},
		{Method: "POST", Path: "/target-lists", Handler: m.handleCreateTargetList, Permission: "vuln:scan"},
		{Method: "DELETE", Path: "/target-list", Handler: m.handleDeleteTargetList, Permission: "vuln:scan"},
		// 扫描队列
		{Method: "GET", Path: "/queue", Handler: m.handleListQueue, Permission: "vuln:view"},
		{Method: "POST", Path: "/queue", Handler: m.handleEnqueue, Permission: "vuln:scan"},
		{Method: "DELETE", Path: "/queue", Handler: m.handleQueueOp, Permission: "vuln:scan"},
		// Scope（授权扫描范围）
		{Method: "GET", Path: "/scope", Handler: m.handleGetScope, Permission: "vuln:view"},
		{Method: "PUT", Path: "/scope", Handler: m.handleSetScope, Permission: "vuln:scan"},
		// 排除列表
		{Method: "GET", Path: "/exclusions", Handler: m.handleListExclusions, Permission: "vuln:view"},
		{Method: "POST", Path: "/exclusions", Handler: m.handleAddExclusion, Permission: "vuln:scan"},
		{Method: "DELETE", Path: "/exclusion", Handler: m.handleDeleteExclusion, Permission: "vuln:scan"},
		// HTML 报告
		{Method: "GET", Path: "/report", Handler: m.handleReport, Permission: "vuln:view"},
		// SSE 实时推送
		{Method: "GET", Path: "/events", Handler: m.handleEvents, Permission: "vuln:view"},
		// Prometheus 风格 metrics
		{Method: "GET", Path: "/metrics", Handler: m.handleMetrics, Permission: "vuln:view"},
		// 模板库更新
		{Method: "POST", Path: "/templates/update", Handler: m.handleUpdateTemplates, Permission: "vuln:scan"},
		// 指纹库浏览
	}
}

// GET /status
func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, m.store.getStatus())
}

// POST /start
func (m *Module) handleStart(w http.ResponseWriter, r *http.Request) {
	if m.store.getStatus().Running {
		writeJSON(w, 409, map[string]string{"error": "扫描任务正在运行，请先停止或将任务加入队列"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 限制 10 MiB
	var opt scanOptions
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	if len(opt.Targets) == 0 {
		writeJSON(w, 400, map[string]string{"error": "targets 不能为空"})
		return
	}

	// 规范化
	raw := strings.Join(opt.Targets, "\n")
	normalized, normStats := NormalizeTargets(raw)
	if len(normalized) == 0 {
		writeJSON(w, 400, map[string]string{
			"error": fmt.Sprintf("没有有效目标（输入 %d 条均无法识别）", normStats.InputTokens),
		})
		return
	}

	// Scope + 排除列表过滤
	filterResult := m.store.FilterTargets(normalized)
	allowed := filterResult.Allowed
	if len(allowed) == 0 {
		writeJSON(w, 400, map[string]string{
			"error": fmt.Sprintf("所有目标均被过滤（排除列表拦截 %d 个，超范围阻断 %d 个）",
				filterResult.Excluded, filterResult.OutOfScope),
		})
		return
	}
	opt.Targets = allowed

	taskName := "扫描-" + time.Now().Format("20060102-150405")
	taskID, err := m.startTask(taskName, opt)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, map[string]interface{}{
		"taskId":      taskID,
		"taskName":    taskName,
		"targets":     len(allowed),
		"normStats":   normStats,
		"filterStats": filterResult,
		"message":     "扫描已启动",
	})
}

// POST /stop
func (m *Module) handleStop(w http.ResponseWriter, r *http.Request) {
	if m.store.stop() {
		writeJSON(w, 200, map[string]string{"message": "停止信号已发送"})
	} else {
		writeJSON(w, 409, map[string]string{"error": "当前没有正在运行的扫描"})
	}
}

// startTask 原子地检查是否有任务在运行、创建 Task、持久化并启动扫描 goroutine。
// 返回 (taskID, nil) 表示成功；若已有任务运行则返回 ("", error)。
func (m *Module) startTask(name string, opt scanOptions) (string, error) {
	taskID := newTaskID()
	task := &Task{
		ID:          taskID,
		Name:        name,
		Targets:     opt.Targets,
		TargetCount: len(opt.Targets),
		Templates:   opt.Templates,
		Severity:    opt.Severity,
		ScanMode:    opt.ScanMode,
		RateLimit:   opt.RateLimit,
		TimeoutSec:  opt.Timeout,
		Tags:        opt.Tags,
		Proxy:       opt.Proxy,
		StartedAt:   time.Now(),
		Running:     true,
	}
	if !m.store.tryBeginScan(task) {
		return "", fmt.Errorf("扫描任务正在运行，请先停止或将任务加入队列")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.store.setCancel(cancel)
	go m.sc.Run(ctx, opt)
	return taskID, nil
}

// POST /resume?taskId=xxx&mode=all|unscanned  — 将历史任务的目标重新入队/直接启动
// mode=unscanned 表示仅扫描该任务中尚未出现结果的目标（断点续扫）
func (m *Module) handleResume(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 taskId 参数"})
		return
	}
	task := m.store.getTask(taskID)
	if task == nil {
		writeJSON(w, 404, map[string]string{"error": "任务不存在"})
		return
	}
	if task.Running {
		writeJSON(w, 409, map[string]string{"error": "该任务仍在运行"})
		return
	}

	targets := task.Targets
	// mode=unscanned：过滤掉该任务中已有扫描结果的目标
	if r.URL.Query().Get("mode") == "unscanned" {
		scannedHosts := map[string]bool{}
		for _, res := range m.store.list() {
			if res.TaskID == taskID {
				scannedHosts[res.Host] = true
			}
		}
		var unscanned []string
		for _, t := range targets {
			if !scannedHosts[t] {
				unscanned = append(unscanned, t)
			}
		}
		if len(unscanned) == 0 {
			writeJSON(w, 200, map[string]interface{}{
				"message":   "所有目标均已扫描，无需续扫",
				"skipped":   len(targets),
				"remaining": 0,
			})
			return
		}
		targets = unscanned
	}

	opt := scanOptions{
		Targets:   targets,
		Templates: task.Templates,
		Severity:  task.Severity,
		RateLimit: task.RateLimit,
		Timeout:   task.TimeoutSec,
		Tags:      task.Tags,
		Proxy:     task.Proxy,
	}

	now := time.Now()
	if m.store.getStatus().Running {
		// 当前有扫描在运行：加入队列
		qi := &QueueItem{
			ID:          newTaskID(),
			Name:        "续扫-" + task.Name,
			Opt:         opt,
			TargetCount: len(targets),
			Status:      "pending",
			CreatedAt:   now,
		}
		if err := m.store.enqueue(qi); err != nil {
			writeJSON(w, 429, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"message":  "已加入队列",
			"queueId":  qi.ID,
			"position": m.queuePosition(qi.ID),
		})
		return
	}

	// 直接启动
	newTaskID, err := m.startTask("续扫-"+task.Name, opt)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"taskId":  newTaskID,
		"message": "续扫已启动",
		"targets": len(targets),
	})
}

var sevOrderMap = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func sevOrder(s string) int {
	if v, ok := sevOrderMap[strings.ToLower(s)]; ok {
		return v
	}
	return 5
}

// GET /results?severity=&page=&pageSize=&search=&sort=&taskId=&showFP=&status=&showDup=
func (m *Module) handleListResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sevFilter := q.Get("severity")
	search := strings.ToLower(q.Get("search"))
	taskID := q.Get("taskId")
	sortBy := q.Get("sort")
	showFP := q.Get("showFP") == "true"
	showDup := q.Get("showDup") == "true" // 是否显示跨任务重复结果
	statusFilter := q.Get("status")

	page, pageSize := 1, 100
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(q.Get("pageSize")); err == nil && ps > 0 && ps <= 500 {
		pageSize = ps
	}

	all := m.store.list()

	stats := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
		"total": 0, "confirmed": 0, "fp": 0, "pending": 0, "follow_up": 0,
		"duplicate": 0,
	}
	for _, res := range all {
		if taskID != "" && res.TaskID != taskID {
			continue
		}
		sev := strings.ToLower(res.Severity)
		if _, ok := stats[sev]; ok {
			stats[sev]++
		}
		stats["total"]++
		switch res.Status {
		case "confirmed":
			stats["confirmed"]++
		case "fp":
			stats["fp"]++
		case "follow_up":
			stats["follow_up"]++
		default:
			stats["pending"]++
		}
		if res.DuplicateOf != "" {
			stats["duplicate"]++
		}
	}

	var filtered []*Result
	for _, res := range all {
		if taskID != "" && res.TaskID != taskID {
			continue
		}
		if !showFP && res.FalsePositive {
			continue
		}
		if !showDup && res.DuplicateOf != "" {
			continue
		}
		if sevFilter != "" && !containsAny(res.Severity, sevFilter) {
			continue
		}
		if statusFilter != "" && res.Status != statusFilter {
			continue
		}
		if search != "" && !strings.Contains(
			strings.ToLower(res.Name+" "+res.Host+" "+res.TemplateID+" "+res.AnalystNote), search) {
			continue
		}
		filtered = append(filtered, res)
	}

	if sortBy == "severity" {
		sort.SliceStable(filtered, func(i, j int) bool {
			return sevOrder(filtered[i].Severity) < sevOrder(filtered[j].Severity)
		})
	} else {
		sort.SliceStable(filtered, func(i, j int) bool {
			return filtered[i].FoundAt.After(filtered[j].FoundAt)
		})
	}

	total := len(filtered)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	writeJSON(w, 200, map[string]interface{}{
		"results":    filtered[start:end],
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
		"stats":      stats,
	})
}

// DELETE /results
func (m *Module) handleClearResults(w http.ResponseWriter, r *http.Request) {
	m.store.clear()
	m.store.save()
	writeJSON(w, 200, map[string]string{"message": "已清空"})
}

// DELETE /result?id=xxx
func (m *Module) handleDeleteResult(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 id 参数"})
		return
	}
	if m.store.deleteByID(id) {
		m.store.save()
		writeJSON(w, 200, map[string]string{"message": "已删除"})
	} else {
		writeJSON(w, 404, map[string]string{"error": "未找到该条记录"})
	}
}

// PATCH /result?id=xxx
func (m *Module) handleUpdateResult(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 id 参数"})
		return
	}
	var body struct {
		FalsePositive *bool   `json:"falsePositive"`
		AnalystNote   *string `json:"analystNote"`
		Status        *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if !m.store.updateResult(id, body.FalsePositive, body.AnalystNote, body.Status) {
		writeJSON(w, 404, map[string]string{"error": "未找到该条记录"})
		return
	}
	m.store.save()
	writeJSON(w, 200, map[string]string{"message": "已更新"})
}

// POST /results/batch — 批量更新多条结果（审阅模式）
// Body: { "ids": ["id1","id2",...], "falsePositive"?: bool, "status"?: string }
func (m *Module) handleBatchUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs           []string `json:"ids"`
		FalsePositive *bool    `json:"falsePositive"`
		Status        *string  `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if len(body.IDs) == 0 {
		writeJSON(w, 400, map[string]string{"error": "ids 不能为空"})
		return
	}
	updated := m.store.batchUpdateResults(body.IDs, body.FalsePositive, body.Status)
	if updated > 0 {
		m.store.save()
	}
	writeJSON(w, 200, map[string]interface{}{"updated": updated, "message": fmt.Sprintf("已更新 %d 条", updated)})
}

// GET /templates
func (m *Module) handleTemplates(w http.ResponseWriter, r *http.Request) {
	resp, err := m.sc.TemplateTree()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, resp)
}

// GET /export?format=csv|json&severity=&search=&taskId=&includeFP=&includeDup=
func (m *Module) handleExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}
	sevF := q.Get("severity")
	srch := strings.ToLower(q.Get("search"))
	taskID := q.Get("taskId")
	includeFP := q.Get("includeFP") == "true"
	includeDup := q.Get("includeDup") == "true"

	all := m.store.list()
	var results []*Result
	for _, res := range all {
		if !includeFP && res.FalsePositive {
			continue
		}
		if !includeDup && res.DuplicateOf != "" {
			continue
		}
		if taskID != "" && res.TaskID != taskID {
			continue
		}
		if sevF != "" && !containsAny(res.Severity, sevF) {
			continue
		}
		if srch != "" && !strings.Contains(strings.ToLower(res.Name+" "+res.Host+" "+res.TemplateID), srch) {
			continue
		}
		results = append(results, res)
	}
	ts := time.Now().Format("20060102_150405")

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vuln-scan-%s.json"`, ts))
		_ = json.NewEncoder(w).Encode(results)
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vuln-scan-%s.csv"`, ts))
		_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"严重性", "状态", "名称", "模板ID", "主机", "命中URL", "IP", "标签", "分析师备注", "发现时间", "TaskID", "重复"})
		for _, res := range results {
			dup := ""
			if res.DuplicateOf != "" {
				dup = "是"
			}
			_ = cw.Write([]string{
				res.Severity, res.Status, res.Name, res.TemplateID, res.Host,
				res.MatchedAt, res.IP, strings.Join(res.Tags, ";"),
				res.AnalystNote, res.FoundAt.Format("2006-01-02 15:04:05"), res.TaskID, dup,
			})
		}
		cw.Flush()
	}
}

// GET /tasks
func (m *Module) handleListTasks(w http.ResponseWriter, r *http.Request) {
	tasks := m.store.listTasks()
	sort.SliceStable(tasks, func(i, j int) bool {
		return tasks[i].StartedAt.After(tasks[j].StartedAt)
	})
	writeJSON(w, 200, map[string]interface{}{"tasks": tasks, "total": len(tasks)})
}

// DELETE /task?id=xxx
func (m *Module) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 id 参数"})
		return
	}
	if m.store.deleteTask(id) {
		writeJSON(w, 200, map[string]string{"message": "任务已删除"})
	} else {
		writeJSON(w, 404, map[string]string{"error": "任务不存在"})
	}
}

// POST /normalize
func (m *Module) handleNormalize(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Raw string `json:"raw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	targets, stats := NormalizeTargets(body.Raw)
	// 应用过滤
	filterResult := m.store.FilterTargets(targets)
	preview := filterResult.Allowed
	if len(preview) > 20 {
		preview = preview[:20]
	}
	writeJSON(w, 200, map[string]interface{}{
		"stats":       stats,
		"filterStats": filterResult,
		"preview":     preview,
	})
}

// GET /target-lists
func (m *Module) handleListTargetLists(w http.ResponseWriter, r *http.Request) {
	lists := m.store.listTargetLists()
	sort.SliceStable(lists, func(i, j int) bool {
		return lists[i].UpdatedAt.After(lists[j].UpdatedAt)
	})
	writeJSON(w, 200, map[string]interface{}{"lists": lists, "total": len(lists)})
}

// POST /target-lists
func (m *Module) handleCreateTargetList(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Raw  string `json:"raw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "name 不能为空"})
		return
	}
	targets, stats := NormalizeTargets(body.Raw)
	if len(targets) == 0 {
		writeJSON(w, 400, map[string]string{"error": "没有有效目标"})
		return
	}
	tl := m.store.createTargetList(body.Name, targets)
	writeJSON(w, 200, map[string]interface{}{"list": tl, "normStats": stats})
}

// DELETE /target-list?id=xxx
func (m *Module) handleDeleteTargetList(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 id 参数"})
		return
	}
	if m.store.deleteTargetList(id) {
		writeJSON(w, 200, map[string]string{"message": "已删除"})
	} else {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
	}
}

// ── 队列路由 ──────────────────────────────────────────────────────────────────

// GET /queue
func (m *Module) handleListQueue(w http.ResponseWriter, r *http.Request) {
	q := m.store.listQueue()
	writeJSON(w, 200, map[string]interface{}{"queue": q, "total": len(q)})
}

// POST /queue — 将扫描参数加入待执行队列
// Body: 与 /start 相同的 scanOptions
func (m *Module) handleEnqueue(w http.ResponseWriter, r *http.Request) {
	var opt scanOptions
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if len(opt.Targets) == 0 {
		writeJSON(w, 400, map[string]string{"error": "targets 不能为空"})
		return
	}

	raw := strings.Join(opt.Targets, "\n")
	normalized, _ := NormalizeTargets(raw)
	if len(normalized) == 0 {
		writeJSON(w, 400, map[string]string{"error": "没有有效目标"})
		return
	}
	filterResult := m.store.FilterTargets(normalized)
	if len(filterResult.Allowed) == 0 {
		writeJSON(w, 400, map[string]string{"error": "所有目标均被过滤"})
		return
	}
	opt.Targets = filterResult.Allowed

	now := time.Now()
	qi := &QueueItem{
		ID:          newTaskID(),
		Name:        "队列扫描-" + now.Format("20060102-150405"),
		Opt:         opt,
		TargetCount: len(opt.Targets),
		Status:      "pending",
		CreatedAt:   now,
	}

	// 如果当前没有正在运行的扫描，尝试直接启动而不入队。
	// startTask 内部原子检查，即使并发请求同时到达也只有一个能成功启动。
	if !m.store.getStatus().Running {
		qi.Status = "running"
		qi.StartedAt = now
		_ = m.store.enqueue(qi)
		opt.QueueID = qi.ID
		taskID, err := m.startTask(qi.Name, opt)
		if err == nil {
			qi.TaskID = taskID
			m.store.updateQueueItemTaskID(qi.ID, taskID)
			writeJSON(w, 200, map[string]interface{}{
				"message": "扫描直接启动",
				"queueId": qi.ID,
				"taskId":  taskID,
				"targets": len(opt.Targets),
			})
			return
		}
		// 极罕见并发竞争：撤销刚才入队的 item，降级为等待队列
		m.store.cancelQueueItem(qi.ID)
		qi = &QueueItem{
			ID:          newTaskID(),
			Name:        qi.Name,
			Opt:         opt,
			TargetCount: len(opt.Targets),
			Status:      "pending",
			CreatedAt:   now,
		}
	}

	if err := m.store.enqueue(qi); err != nil {
		writeJSON(w, 429, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, 200, map[string]interface{}{
		"message":  "已加入队列",
		"queueId":  qi.ID,
		"position": m.queuePosition(qi.ID),
		"targets":  len(opt.Targets),
	})
}

// DELETE /queue?id=xxx 取消单个队列项；DELETE /queue（无id）清空队列
func (m *Module) handleQueueOp(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		m.store.clearQueue()
		writeJSON(w, 200, map[string]string{"message": "队列已清空"})
		return
	}
	if m.store.cancelQueueItem(id) {
		writeJSON(w, 200, map[string]string{"message": "已取消"})
	} else {
		writeJSON(w, 404, map[string]string{"error": "队列项不存在或已在运行中"})
	}
}

// queuePosition 返回 pending 队列项的当前排名（1-based）。
func (m *Module) queuePosition(id string) int {
	pos := 0
	for _, qi := range m.store.listQueue() {
		if qi.Status == "pending" {
			pos++
			if qi.ID == id {
				return pos
			}
		}
	}
	return -1
}

// ── Scope 路由 ────────────────────────────────────────────────────────────────

// GET /scope
func (m *Module) handleGetScope(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, m.store.getScope())
}

// PUT /scope
// Body: { "cidrs": [...], "domains": [...], "mode": "disabled|warn|enforce" }
func (m *Module) handleSetScope(w http.ResponseWriter, r *http.Request) {
	var sc ScopeConfig
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if sc.Mode == "" {
		sc.Mode = "disabled"
	}
	if sc.Mode != "disabled" && sc.Mode != "warn" && sc.Mode != "enforce" {
		writeJSON(w, 400, map[string]string{"error": "mode 必须是 disabled、warn 或 enforce"})
		return
	}
	m.store.setScope(sc)
	writeJSON(w, 200, map[string]interface{}{"message": "已更新", "scope": sc})
}

// ── 排除列表路由 ──────────────────────────────────────────────────────────────

// GET /exclusions
func (m *Module) handleListExclusions(w http.ResponseWriter, r *http.Request) {
	excls := m.store.listExclusions()
	writeJSON(w, 200, map[string]interface{}{"exclusions": excls, "total": len(excls)})
}

// POST /exclusions
// Body: { "pattern": "192.168.1.1", "note": "..." }
func (m *Module) handleAddExclusion(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(body.Pattern) == "" {
		writeJSON(w, 400, map[string]string{"error": "pattern 不能为空"})
		return
	}
	ex := m.store.addExclusion(body.Pattern, body.Note)
	writeJSON(w, 200, map[string]interface{}{"exclusion": ex, "message": "已添加"})
}

// DELETE /exclusion?id=xxx
func (m *Module) handleDeleteExclusion(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 id 参数"})
		return
	}
	if m.store.deleteExclusion(id) {
		writeJSON(w, 200, map[string]string{"message": "已删除"})
	} else {
		writeJSON(w, 404, map[string]string{"error": "未找到"})
	}
}

// ── 报告路由 ──────────────────────────────────────────────────────────────────

// GET /report?taskId=xxx&format=html  生成并下载 HTML 漏洞报告
func (m *Module) handleReport(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 taskId 参数"})
		return
	}
	task := m.store.getTask(taskID)
	if task == nil {
		writeJSON(w, 404, map[string]string{"error": "任务不存在"})
		return
	}
	// 拉取该任务的全部结果
	var results []*Result
	for _, res := range m.store.list() {
		if res.TaskID == taskID {
			results = append(results, res)
		}
	}
	html, err := GenerateHTMLReport(task, results)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "生成报告失败: " + err.Error()})
		return
	}
	filename := fmt.Sprintf("vuln-report-%s.html", taskID[:8])
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(200)
	_, _ = w.Write(html)
}

// ── SSE 实时推送 ──────────────────────────────────────────────────────────────

// GET /events — SSE 实时推送进度、结果、扫描状态变化
func (m *Module) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "不支持流式响应"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)

	// 连接时推送当前状态快照
	if data, err := json.Marshal(m.store.getStatus()); err == nil {
		fmt.Fprintf(w, "event: status\ndata: %s\n\n", data)
		flusher.Flush()
	}

	ch := m.store.bus.Subscribe()
	defer m.store.bus.Unsubscribe(ch)

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return
			}
			if data, err := json.Marshal(evt.Data); err == nil {
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
				flusher.Flush()
			}
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ── Metrics 端点 ──────────────────────────────────────────────────────────────

// GET /metrics — Prometheus 风格的简单指标（无需 push-gateway，curl 可直接抓取）
func (m *Module) handleMetrics(w http.ResponseWriter, r *http.Request) {
	st := m.store.getStatus()
	results := m.store.list()
	tasks := m.store.listTasks()
	queue := m.store.listQueue()

	pending := 0
	for _, q := range queue {
		if q.Status == "pending" {
			pending++
		}
	}
	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	fp, confirmed, dup := 0, 0, 0
	for _, res := range results {
		sev := strings.ToLower(res.Severity)
		if _, ok := sevCounts[sev]; ok {
			sevCounts[sev]++
		}
		if res.FalsePositive {
			fp++
		}
		if res.Status == "confirmed" {
			confirmed++
		}
		if res.DuplicateOf != "" {
			dup++
		}
	}
	running := 0
	if st.Running {
		running = 1
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	lines := []string{
		"# HELP vulnscan_results_total 扫描结果总数",
		"# TYPE vulnscan_results_total gauge",
		fmt.Sprintf("vulnscan_results_total %d", len(results)),
		"# HELP vulnscan_tasks_total 扫描任务总数",
		"# TYPE vulnscan_tasks_total gauge",
		fmt.Sprintf("vulnscan_tasks_total %d", len(tasks)),
		"# HELP vulnscan_running 当前是否正在扫描（0或1）",
		"# TYPE vulnscan_running gauge",
		fmt.Sprintf("vulnscan_running %d", running),
		"# HELP vulnscan_queue_pending 队列中待执行任务数",
		"# TYPE vulnscan_queue_pending gauge",
		fmt.Sprintf("vulnscan_queue_pending %d", pending),
		"# HELP vulnscan_results_by_severity 按严重度分类结果数",
		"# TYPE vulnscan_results_by_severity gauge",
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		lines = append(lines, fmt.Sprintf(`vulnscan_results_by_severity{severity="%s"} %d`, sev, sevCounts[sev]))
	}
	lines = append(lines,
		fmt.Sprintf("vulnscan_results_fp %d", fp),
		fmt.Sprintf("vulnscan_results_confirmed %d", confirmed),
		fmt.Sprintf("vulnscan_results_duplicate %d", dup),
	)
	fmt.Fprintln(w, strings.Join(lines, "\n"))
}

// ── 模板更新 ──────────────────────────────────────────────────────────────────

// POST /templates/update — 后台运行 nuclei -update-templates
func (m *Module) handleUpdateTemplates(w http.ResponseWriter, r *http.Request) {
	if _, err := findNuclei(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	go m.sc.updateTemplates(m.log)
	writeJSON(w, 200, map[string]string{"message": "模板更新已在后台启动，请查看引擎日志"})
}

// ── 指纹库浏览 ────────────────────────────────────────────────────────────────

// ── 工具函数 ──────────────────────────────────────────────────────────────────

func containsAny(severity, filter string) bool {
	sev := strings.ToLower(severity)
	for _, f := range strings.Split(filter, ",") {
		if strings.TrimSpace(strings.ToLower(f)) == sev {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
