package vulnscan

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	dataFile        = "data/vuln-scan-results.json"
	taskFile        = "data/vuln-scan-tasks.json"
	targetListsFile = "data/vuln-scan-target-lists.json"
	queueFile       = "data/vuln-scan-queue.json"
	maxResults      = 50_000
	maxQueueSize    = 50
	saveEvery       = 50 // 每 N 条新结果触发一次异步落盘
)

// Result 对应 nuclei -jsonl 输出的单条漏洞命中。
type Result struct {
	ID         string    `json:"id"`
	TemplateID string    `json:"templateId"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"`
	Tags       []string  `json:"tags"`
	Host       string    `json:"host"`
	MatchedAt  string    `json:"matchedAt"`
	CurlCmd    string    `json:"curlCmd"`
	Request    string    `json:"request"`
	Response   string    `json:"response"`
	IP         string    `json:"ip"`
	FoundAt    time.Time `json:"foundAt"`
	TaskID     string    `json:"taskId"`

	// 分析师工作流字段
	FalsePositive bool   `json:"falsePositive,omitempty"`
	AnalystNote   string `json:"analystNote,omitempty"`
	// Status: "" | "pending" | "confirmed" | "fp" | "follow_up"
	Status string `json:"status,omitempty"`
	// 跨任务去重
	DuplicateOf string `json:"duplicateOf,omitempty"`
}

// Task 记录单次扫描任务的完整元数据。
type Task struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Targets     []string  `json:"targets"`
	TargetCount int       `json:"targetCount"`
	Templates   string    `json:"templates"`
	Severity    string    `json:"severity"`
	ScanMode    string    `json:"scanMode,omitempty"` // "full" | "fingerprint"
	RateLimit   int       `json:"rateLimit"`
	TimeoutSec  int       `json:"timeout"`
	Tags        string    `json:"tags,omitempty"`
	Proxy       string    `json:"proxy,omitempty"`
	Total       int       `json:"total"`
	Capped      bool      `json:"capped,omitempty"`
	Error       string    `json:"error,omitempty"`
	StartedAt   time.Time `json:"startedAt"`
	StoppedAt   time.Time `json:"stoppedAt,omitempty"`
	Running     bool      `json:"running"`
}

// QueueItem 等待执行的扫描任务队列项。
type QueueItem struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Opt         scanOptions `json:"opt"`
	TargetCount int         `json:"targetCount"`
	// Status: "pending" | "running" | "done" | "cancelled"
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	TaskID     string    `json:"taskId,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// TargetList 保存的命名目标列表。
type TargetList struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Targets   []string  `json:"targets"` // 已规范化
	Count     int       `json:"count"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ScanProgress 从 nuclei stderr 解析的实时进度。
type ScanProgress struct {
	Scanned int     `json:"scanned"`
	Total   int     `json:"total"`
	Percent float64 `json:"percent"`
	RPS     int     `json:"rps"`
	ETA     string  `json:"eta,omitempty"`
	Phase   string  `json:"phase,omitempty"` // "fingerprint"(指纹检测中) | "scan"(漏洞扫描中)
}

// ScanStatus 暴露给前端的实时状态。
type ScanStatus struct {
	Running       bool          `json:"running"`
	TaskID        string        `json:"taskId"`
	TaskName      string        `json:"taskName"`
	Targets       []string      `json:"targets"`
	Templates     string        `json:"templates"`
	Severity      string        `json:"severity"`
	ScanMode      string        `json:"scanMode,omitempty"`      // "full" | "fingerprint"
	DetectedTechs []string      `json:"detectedTechs,omitempty"` // 指纹检测到的技术
	Total         int           `json:"total"`
	Capped        bool          `json:"capped,omitempty"`
	StartedAt     time.Time     `json:"startedAt,omitempty"`
	StoppedAt     time.Time     `json:"stoppedAt,omitempty"`
	Error         string        `json:"error,omitempty"`
	Progress      *ScanProgress `json:"progress,omitempty"` // nil = 未知进度
	QueueLen      int           `json:"queueLen"`            // 队列等待数
}

type store struct {
	mu           sync.RWMutex
	results      []*Result
	tasks        []*Task
	targetLists  []*TargetList
	queue        []*QueueItem
	fingerprints map[string]string // 跨任务去重：fp → 首次发现的 resultID
	// scope 和 exclusions 在 scope.go 中操作
	scope      ScopeConfig
	exclusions []*Exclusion
	status     ScanStatus
	cancelFn   context.CancelFunc
	saveMu     sync.Mutex
	// 实时落盘计数器
	resultsSinceSave int
	// SSE 事件总线
	bus *eventBus
}

func newStore() *store {
	return &store{
		fingerprints: make(map[string]string),
		scope:        ScopeConfig{Mode: "disabled", CIDRs: []string{}, Domains: []string{}},
		exclusions:   []*Exclusion{},
		queue:        []*QueueItem{},
		bus:          newEventBus(),
	}
}

// resultFingerprint 计算跨任务去重的指纹（模板ID + 命中URL）。
func resultFingerprint(templateID, matchedAt string) string {
	h := sha1.New()
	h.Write([]byte(templateID + "::" + matchedAt))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// ── 结果相关 ──────────────────────────────────────────────────────────────────

func (s *store) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.results)
}

func (s *store) list() []*Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Result, len(s.results))
	copy(out, s.results)
	return out
}

func (s *store) append(r *Result) {
	s.mu.Lock()
	// 跨任务去重
	fp := resultFingerprint(r.TemplateID, r.MatchedAt)
	if existingID, ok := s.fingerprints[fp]; ok {
		r.DuplicateOf = existingID
	} else {
		s.fingerprints[fp] = r.ID
	}
	if len(s.results) < maxResults {
		s.results = append(s.results, r)
		if len(s.results) >= maxResults {
			s.status.Capped = true
		}
	}
	s.status.Total = len(s.results)
	s.resultsSinceSave++
	shouldSave := s.resultsSinceSave >= saveEvery
	if shouldSave {
		s.resultsSinceSave = 0
	}
	s.mu.Unlock()
	// 每 saveEvery 条触发一次异步落盘（防止扫描中崩溃丢数据）
	if shouldSave {
		go s.save()
	}
	// SSE 推送新结果（只推送精简字段，避免大 body）
	go s.bus.Publish("result", map[string]interface{}{
		"id": r.ID, "name": r.Name, "severity": r.Severity,
		"host": r.Host, "matchedAt": r.MatchedAt, "taskId": r.TaskID,
	})
}

func (s *store) clear() {
	s.mu.Lock()
	s.results = nil
	s.status.Total = 0
	s.mu.Unlock()
}

func (s *store) clearByTask(taskID string) {
	s.mu.Lock()
	n := s.results[:0]
	for _, r := range s.results {
		if r.TaskID != taskID {
			n = append(n, r)
		}
	}
	s.results = n
	s.status.Total = len(s.results)
	s.mu.Unlock()
}

func (s *store) deleteByID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.results {
		if r.ID == id {
			s.results = append(s.results[:i], s.results[i+1:]...)
			s.status.Total = len(s.results)
			return true
		}
	}
	return false
}

// updateResult 更新单条结果的分析师字段（FP / 备注 / 状态）。
// 参数用指针：nil 表示不修改该字段。
func (s *store) updateResult(id string, fp *bool, note *string, status *string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.results {
		if r.ID == id {
			if fp != nil {
				r.FalsePositive = *fp
				if *fp && (r.Status == "" || r.Status == "pending") {
					r.Status = "fp"
				} else if !*fp && r.Status == "fp" {
					r.Status = "pending"
				}
			}
			if note != nil {
				r.AnalystNote = *note
			}
			if status != nil {
				r.Status = *status
				if *status == "fp" {
					r.FalsePositive = true
				} else if r.FalsePositive && *status != "fp" {
					r.FalsePositive = false
				}
			}
			return true
		}
	}
	return false
}

// batchUpdateResults 批量更新一组结果的状态/FP。返回更新数量。
func (s *store) batchUpdateResults(ids []string, fp *bool, status *string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	count := 0
	for _, r := range s.results {
		if !idSet[r.ID] {
			continue
		}
		if fp != nil {
			r.FalsePositive = *fp
			if *fp {
				r.Status = "fp"
			} else if r.Status == "fp" {
				r.Status = "pending"
			}
		}
		if status != nil {
			r.Status = *status
			if *status == "fp" {
				r.FalsePositive = true
			} else if r.FalsePositive && *status != "fp" {
				r.FalsePositive = false
			}
		}
		count++
	}
	return count
}

// ── 状态与进度 ────────────────────────────────────────────────────────────────

func (s *store) getStatus() ScanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.status
	st.Total = len(s.results)
	// 计算待执行队列数
	qLen := 0
	for _, qi := range s.queue {
		if qi.Status == "pending" {
			qLen++
		}
	}
	st.QueueLen = qLen
	return st
}

func (s *store) updateProgress(p ScanProgress) {
	s.mu.Lock()
	// 保留 Phase，避免进度刷新时把阶段清掉
	if s.status.Progress != nil && p.Phase == "" {
		p.Phase = s.status.Progress.Phase
	}
	s.status.Progress = &p
	s.mu.Unlock()
	go s.bus.Publish("progress", p)
}

// setPhase 切换扫描阶段（"fingerprint" / "scan"），可同时更新指纹检测结果。
func (s *store) setPhase(phase string, techs []string) {
	s.mu.Lock()
	if s.status.Progress == nil {
		s.status.Progress = &ScanProgress{}
	}
	s.status.Progress.Phase = phase
	if techs != nil {
		s.status.DetectedTechs = techs
	}
	snap := s.status
	s.mu.Unlock()
	go s.bus.Publish("phase", snap)
}

func (s *store) beginScanTask(t *Task) {
	s.mu.Lock()
	s.tasks = append(s.tasks, t)
	s.status = ScanStatus{
		Running:   true,
		TaskID:    t.ID,
		TaskName:  t.Name,
		Targets:   t.Targets,
		Templates: t.Templates,
		Severity:  t.Severity,
		ScanMode:  t.ScanMode,
		StartedAt: t.StartedAt,
	}
	s.mu.Unlock()
	s.saveTasks()
	go s.bus.Publish("start", map[string]interface{}{"taskId": t.ID, "taskName": t.Name, "targetCount": t.TargetCount})
}

// tryBeginScan 原子地检查是否有任务在运行，若无则立即开启新任务并返回 true；
// 若已有任务运行则返回 false（无副作用）。解决 handler 层 TOCTOU 竞态。
func (s *store) tryBeginScan(t *Task) bool {
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return false
	}
	s.tasks = append(s.tasks, t)
	s.status = ScanStatus{
		Running:   true,
		TaskID:    t.ID,
		TaskName:  t.Name,
		Targets:   t.Targets,
		Templates: t.Templates,
		Severity:  t.Severity,
		ScanMode:  t.ScanMode,
		StartedAt: t.StartedAt,
	}
	s.mu.Unlock()
	s.saveTasks()
	go s.bus.Publish("start", map[string]interface{}{"taskId": t.ID, "taskName": t.Name, "targetCount": t.TargetCount})
	return true
}

func (s *store) endScan(errMsg string) {
	s.mu.Lock()
	s.status.Running = false
	s.status.StoppedAt = time.Now()
	s.status.Error = errMsg
	s.status.Progress = nil
	s.cancelFn = nil
	taskID := s.status.TaskID
	total := s.status.Total
	capped := s.status.Capped
	stopTime := s.status.StoppedAt
	for _, t := range s.tasks {
		if t.ID == taskID {
			t.Running = false
			t.Total = total
			t.Capped = capped
			t.Error = errMsg
			t.StoppedAt = stopTime
			break
		}
	}
	s.mu.Unlock()
	s.save()
	s.saveTasks()
	go s.bus.Publish("end", map[string]interface{}{"error": errMsg, "total": total})
}

func (s *store) setCancel(fn context.CancelFunc) {
	s.mu.Lock()
	s.cancelFn = fn
	s.mu.Unlock()
}

func (s *store) stop() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.status.Running || s.cancelFn == nil {
		return false
	}
	s.cancelFn()
	return true
}

// ── 扫描队列 ──────────────────────────────────────────────────────────────────

func (s *store) enqueue(item *QueueItem) error {
	s.mu.Lock()
	pending := 0
	for _, qi := range s.queue {
		if qi.Status == "pending" {
			pending++
		}
	}
	if pending >= maxQueueSize {
		s.mu.Unlock()
		return fmt.Errorf("队列已满（最多 %d 个待执行任务）", maxQueueSize)
	}
	s.queue = append(s.queue, item)
	s.mu.Unlock()
	s.saveQueue()
	return nil
}

// dequeueNext 取出下一个待执行队列项并标记为 running。
// 仅当当前无正在进行的扫描时才返回非 nil。
func (s *store) dequeueNext() *QueueItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Running {
		return nil
	}
	for _, qi := range s.queue {
		if qi.Status == "pending" {
			qi.Status = "running"
			qi.StartedAt = time.Now()
			return qi
		}
	}
	return nil
}

// finishQueueItem 标记队列项为已完成或已取消。
func (s *store) finishQueueItem(id, taskID, errMsg string) {
	s.mu.Lock()
	for _, qi := range s.queue {
		if qi.ID == id {
			if errMsg != "" {
				qi.Status = "cancelled"
				qi.Error = errMsg
			} else {
				qi.Status = "done"
			}
			qi.FinishedAt = time.Now()
			if taskID != "" {
				qi.TaskID = taskID
			}
			break
		}
	}
	s.mu.Unlock()
	s.saveQueue()
}

// updateQueueItemTaskID 在知道 taskID 后补写队列项。
func (s *store) updateQueueItemTaskID(id, taskID string) {
	s.mu.Lock()
	for _, qi := range s.queue {
		if qi.ID == id {
			qi.TaskID = taskID
			break
		}
	}
	s.mu.Unlock()
	s.saveQueue()
}

// cancelQueueItem 取消一个 pending 队列项。
func (s *store) cancelQueueItem(id string) bool {
	s.mu.Lock()
	found := false
	for _, qi := range s.queue {
		if qi.ID == id && qi.Status == "pending" {
			qi.Status = "cancelled"
			qi.FinishedAt = time.Now()
			found = true
			break
		}
	}
	s.mu.Unlock()
	if found {
		s.saveQueue()
	}
	return found
}

// clearQueue 清除所有非 running 的队列项。
func (s *store) clearQueue() {
	s.mu.Lock()
	n := s.queue[:0]
	for _, qi := range s.queue {
		if qi.Status == "running" {
			n = append(n, qi)
		}
	}
	s.queue = n
	s.mu.Unlock()
	s.saveQueue()
}

func (s *store) listQueue() []*QueueItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*QueueItem, len(s.queue))
	copy(out, s.queue)
	return out
}

// ── 任务 CRUD ─────────────────────────────────────────────────────────────────

func (s *store) listTasks() []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Task, len(s.tasks))
	copy(out, s.tasks)
	return out
}

func (s *store) getTask(id string) *Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tasks {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (s *store) deleteTask(id string) bool {
	s.mu.Lock()
	found := false
	n := s.tasks[:0]
	for _, t := range s.tasks {
		if t.ID == id {
			found = true
		} else {
			n = append(n, t)
		}
	}
	if found {
		s.tasks = n
		r2 := s.results[:0]
		for _, r := range s.results {
			if r.TaskID != id {
				r2 = append(r2, r)
			}
		}
		s.results = r2
		s.status.Total = len(s.results)
	}
	s.mu.Unlock()
	if found {
		s.save()
		s.saveTasks()
	}
	return found
}

// ── 目标列表 CRUD ─────────────────────────────────────────────────────────────

func (s *store) listTargetLists() []*TargetList {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*TargetList, len(s.targetLists))
	copy(out, s.targetLists)
	return out
}

func (s *store) createTargetList(name string, targets []string) *TargetList {
	tl := &TargetList{
		ID:        newTaskID(),
		Name:      name,
		Targets:   targets,
		Count:     len(targets),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	s.mu.Lock()
	s.targetLists = append(s.targetLists, tl)
	s.mu.Unlock()
	s.saveTargetLists()
	return tl
}

func (s *store) deleteTargetList(id string) bool {
	s.mu.Lock()
	found := false
	n := s.targetLists[:0]
	for _, tl := range s.targetLists {
		if tl.ID == id {
			found = true
		} else {
			n = append(n, tl)
		}
	}
	if found {
		s.targetLists = n
	}
	s.mu.Unlock()
	if found {
		s.saveTargetLists()
	}
	return found
}

// ── 持久化 ────────────────────────────────────────────────────────────────────

func atomicWrite(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	// Rename 可能在跨分区容器环境失败，回退到直接覆盖写
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		_ = os.WriteFile(path, data, 0o644)
	}
}

func (s *store) save() {
	s.mu.RLock()
	cp := make([]*Result, len(s.results))
	copy(cp, s.results)
	s.mu.RUnlock()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	atomicWrite(dataFile, cp)
}

func (s *store) load() {
	data, err := os.ReadFile(dataFile)
	if err == nil {
		var results []*Result
		if json.Unmarshal(data, &results) == nil {
			s.mu.Lock()
			s.results = results
			s.status.Total = len(results)
			// 重建去重指纹
			s.fingerprints = make(map[string]string)
			for _, r := range results {
				fp := resultFingerprint(r.TemplateID, r.MatchedAt)
				if _, ok := s.fingerprints[fp]; !ok {
					s.fingerprints[fp] = r.ID
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *store) saveTasks() {
	s.mu.RLock()
	tasks := make([]*Task, len(s.tasks))
	copy(tasks, s.tasks)
	s.mu.RUnlock()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	atomicWrite(taskFile, tasks)
}

func (s *store) loadTasks() {
	data, err := os.ReadFile(taskFile)
	if err != nil {
		return
	}
	var tasks []*Task
	if json.Unmarshal(data, &tasks) == nil {
		for _, t := range tasks {
			if t.Running {
				t.Running = false
				t.Error = "引擎重启，任务中断"
				if t.StoppedAt.IsZero() {
					t.StoppedAt = time.Now()
				}
			}
		}
		s.mu.Lock()
		s.tasks = tasks
		s.mu.Unlock()
	}
}

func (s *store) saveTargetLists() {
	s.mu.RLock()
	lists := make([]*TargetList, len(s.targetLists))
	copy(lists, s.targetLists)
	s.mu.RUnlock()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	atomicWrite(targetListsFile, lists)
}

func (s *store) loadTargetLists() {
	data, err := os.ReadFile(targetListsFile)
	if err != nil {
		return
	}
	var lists []*TargetList
	if json.Unmarshal(data, &lists) == nil {
		s.mu.Lock()
		s.targetLists = lists
		s.mu.Unlock()
	}
}

func (s *store) saveQueue() {
	s.mu.RLock()
	q := make([]*QueueItem, len(s.queue))
	copy(q, s.queue)
	s.mu.RUnlock()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	atomicWrite(queueFile, q)
}

func (s *store) loadQueue() {
	data, err := os.ReadFile(queueFile)
	if err != nil {
		return
	}
	var q []*QueueItem
	if json.Unmarshal(data, &q) == nil {
		// 引擎重启：running 状态的队列项重置为 cancelled
		for _, qi := range q {
			if qi.Status == "running" {
				qi.Status = "cancelled"
				qi.Error = "引擎重启，任务中断"
			}
		}
		s.mu.Lock()
		s.queue = q
		s.mu.Unlock()
	}
}
