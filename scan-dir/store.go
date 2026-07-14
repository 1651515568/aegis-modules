package scandir

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// tasksFile 是扫描历史(多任务)的本地实时视图落盘路径。data/ 已在 .gitignore 中。
// 注意:跨页面/可审计的权威任务台账走 AEGIS 统一 task_id(m_scan_dir_task_runs +
// m_scan_dir_findings),本文件仅供引擎本地保留「最近扫描」实时视图,重启不致全空。
const tasksFile = "data/scan-dir/tasks.json"

// maxHistory 限制后端保留的历史任务数,避免无限增长。
const maxHistory = 50

// Hit 是一条目录扫描命中(被判定为「存在」的路径)。
type Hit struct {
	URL         string `json:"url"`         // 完整 URL
	Path        string `json:"path"`        // 相对路径(含扩展名)
	Status      int    `json:"status"`      // HTTP 状态码
	Length      int64  `json:"length"`      // 响应体字节数
	Words       int    `json:"words"`       // 响应体词数(便于人工辨别同质页面)
	Lines       int    `json:"lines"`       // 响应体行数
	Redirect    string `json:"redirect"`    // 30x 时的 Location
	ContentType string `json:"contentType"` // Content-Type
	Depth       int    `json:"depth"`       // 递归深度(0=入口层)
	IsDir       bool   `json:"isDir"`       // 是否被判定为目录(可递归)
	Severity    string `json:"severity"`    // 敏感度分级:critical/high/medium/low/info
	Kind        string `json:"kind"`        // 命中类别中文说明(高价值命中)
}

// scanStatus 是一次扫描任务的实时进度快照。
type scanStatus struct {
	Running   bool   `json:"running"`
	Phase     string `json:"phase"`
	Total     int    `json:"total"`     // 已规划的请求总数(递归时动态增长)
	Probed    int    `json:"probed"`    // 已完成请求数
	Found     int    `json:"found"`     // 命中数
	Filtered  int    `json:"filtered"`  // 被软 404/状态过滤掉的数
	Rate      int    `json:"rate"`      // 生效限速 req/s,0=不限
	ElapsedMs int64  `json:"elapsedMs"`
	Target    string `json:"target"`
	StartedAt string `json:"startedAt"`
	EndedAt   string `json:"endedAt"`
	Err       string `json:"err"`
	Resumable bool   `json:"resumable"` // 是否可断点续扫(被中断且尚有未完成基目录)
}

// PendingBase 是 BFS 队列里一个待扫基目录的可序列化形态(断点续扫用)。
type PendingBase struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
}

// taskRecord 是一个扫描任务(含参数、进度、结果),后端历史的基本单元。
type taskRecord struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Targets   []string      `json:"targets"`
	Opts      scanOptions   `json:"opts"`
	St        scanStatus    `json:"status"`
	Hits      []Hit         `json:"hits"`
	Completed []string      `json:"completed"` // 已扫完的基目录 URL(断点续扫:跳过)
	Pending   []PendingBase `json:"pending"`   // 尚未扫的基目录队列快照(断点续扫:继续)

	startedTime time.Time
	endedTime   time.Time
	seen        map[string]struct{} // 命中 URL 去重(内存态,load/begin 时重建)
}

// taskSummary 是列表接口用的轻量摘要(不含完整命中列表)。
type taskSummary struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Targets   []string    `json:"targets"`
	Opts      scanOptions `json:"opts"`
	Status    scanStatus  `json:"status"`
	CreatedAt string      `json:"createdAt"`
	HitCount  int         `json:"hitCount"`
}

type store struct {
	mu        sync.RWMutex
	tasks     []*taskRecord // 历史,最早在前
	cur       *taskRecord   // 当前(或最近一次)任务
	cancel    context.CancelFunc
	path      string
	persistMu sync.Mutex
}

func newStore(path string) *store { return &store{path: path} }

func nowStamp() string { return time.Now().Format("2006-01-02 15:04:05") }

// beginScan 新建一个任务并设为当前,标记运行中。
func (s *store) beginScan(id, name string, targets []string, opts scanOptions) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &taskRecord{
		ID: id, Name: name, Targets: targets, Opts: opts,
		St:          scanStatus{Running: true, Target: "(解析中…)", StartedAt: nowStamp()},
		startedTime: time.Now(),
		seen:        make(map[string]struct{}),
	}
	s.tasks = append(s.tasks, t)
	if len(s.tasks) > maxHistory {
		s.tasks = s.tasks[len(s.tasks)-maxHistory:]
	}
	s.cur = t
}

// tryBeginScan 原子地检查并设置运行态，防止并发双启动（TOCTOU）。
// 若已在运行返回 false；否则等价于 beginScan，返回 true。
func (s *store) tryBeginScan(id, name string, targets []string, opts scanOptions) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil && s.cur.St.Running {
		return false
	}
	t := &taskRecord{
		ID: id, Name: name, Targets: targets, Opts: opts,
		St:          scanStatus{Running: true, Target: "(解析中…)", StartedAt: nowStamp()},
		startedTime: time.Now(),
		seen:        make(map[string]struct{}),
	}
	s.tasks = append(s.tasks, t)
	if len(s.tasks) > maxHistory {
		s.tasks = s.tasks[len(s.tasks)-maxHistory:]
	}
	s.cur = t
	return true
}

// ---- 以下 mutator 均作用于当前任务 ----

func (s *store) setTarget(t string) { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Target = t } }
func (s *store) setPhase(p string)  { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Phase = p } }
func (s *store) addTotal(n int)     { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Total += n } }
func (s *store) incProbed()         { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Probed++ } }
func (s *store) incFiltered()       { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Filtered++ } }
func (s *store) setRate(n int)      { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Rate = n } }

// addHit 记录命中,按 URL 去重(防递归/抽链/续扫重复)。返回是否为新命中。
func (s *store) addHit(h Hit) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return false
	}
	if s.cur.seen == nil {
		s.cur.seen = make(map[string]struct{})
	}
	if _, ok := s.cur.seen[h.URL]; ok {
		return false
	}
	s.cur.seen[h.URL] = struct{}{}
	s.cur.Hits = append(s.cur.Hits, h)
	s.cur.St.Found++
	return true
}

// setPending 设置当前任务的待扫队列快照并落盘(首检查点)。
func (s *store) setPending(pending []PendingBase) {
	s.mu.Lock()
	if s.cur != nil {
		s.cur.Pending = pending
	}
	s.mu.Unlock()
	s.persist()
}

// markBaseDone 记录一个基目录扫描完成,并快照剩余队列后落盘(断点续扫的检查点)。
func (s *store) markBaseDone(baseURL string, pending []PendingBase) {
	s.mu.Lock()
	if s.cur != nil {
		s.cur.Completed = append(s.cur.Completed, baseURL)
		s.cur.Pending = pending
	}
	s.mu.Unlock()
	s.persist()
}

// resumeState 返回可续扫任务的待扫队列与已完成集合(供 run 续扫)。无可续扫则 ok=false。
func (s *store) resumeState() (queue []baseNode, completed map[string]struct{}, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 不校验 Running:调用方 beginResume 已置运行态并把关;此处只据 Pending 恢复队列。
	if s.cur == nil || len(s.cur.Pending) == 0 {
		return nil, nil, false
	}
	completed = make(map[string]struct{}, len(s.cur.Completed))
	for _, c := range s.cur.Completed {
		completed[c] = struct{}{}
	}
	for _, p := range s.cur.Pending {
		queue = append(queue, baseNode{url: p.URL, depth: p.Depth})
	}
	return queue, completed, true
}

// beginResume 把当前(被中断)任务重新置为运行态,保留已有命中/已完成/队列。
func (s *store) beginResume() (scanOptions, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil || s.cur.St.Running || len(s.cur.Pending) == 0 {
		return scanOptions{}, false
	}
	s.cur.St.Running = true
	s.cur.St.Err = ""
	s.cur.St.EndedAt = ""
	s.cur.St.Resumable = false
	s.cur.startedTime = time.Now()
	return s.cur.Opts, true
}

func (s *store) finishScan(errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.St.Running = false
		s.cur.St.EndedAt = nowStamp()
		s.cur.St.Err = errMsg
		s.cur.St.Resumable = len(s.cur.Pending) > 0 // 尚有未完成基目录 → 可续扫
		s.cur.endedTime = time.Now()
		if !s.cur.startedTime.IsZero() {
			s.cur.St.ElapsedMs = s.cur.endedTime.Sub(s.cur.startedTime).Milliseconds()
		}
	}
	s.cancel = nil
}

// status 返回当前任务的状态(运行中则实时计算耗时)。
func (s *store) status() scanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return scanStatus{}
	}
	st := s.cur.St
	if st.Running && !s.cur.startedTime.IsZero() {
		st.ElapsedMs = time.Since(s.cur.startedTime).Milliseconds()
	}
	return st
}

// list 返回当前任务的命中结果(/hits 用,含运行期实时结果)。
func (s *store) list() []Hit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return nil
	}
	out := make([]Hit, len(s.cur.Hits))
	copy(out, s.cur.Hits)
	return out
}

func (s *store) currentID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return ""
	}
	return s.cur.ID
}

// listTasks 返回历史任务摘要(最新在前)。
func (s *store) listTasks() []taskSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]taskSummary, 0, len(s.tasks))
	for i := len(s.tasks) - 1; i >= 0; i-- {
		t := s.tasks[i]
		st := t.St
		if st.Running && !t.startedTime.IsZero() {
			st.ElapsedMs = time.Since(t.startedTime).Milliseconds()
		}
		out = append(out, taskSummary{
			ID: t.ID, Name: t.Name, Targets: t.Targets, Opts: t.Opts,
			Status: st, CreatedAt: st.StartedAt, HitCount: len(t.Hits),
		})
	}
	return out
}

// taskByID 返回某任务的完整记录(含命中)。
func (s *store) taskByID(id string) (*taskRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tasks {
		if t.ID == id {
			cp := *t
			cp.Hits = append([]Hit(nil), t.Hits...)
			if cp.St.Running && !t.startedTime.IsZero() {
				cp.St.ElapsedMs = time.Since(t.startedTime).Milliseconds()
			}
			return &cp, true
		}
	}
	return nil, false
}

// deleteTask 删除一个任务(运行中的不删)。
func (s *store) deleteTask(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.tasks {
		if t.ID == id {
			if t.St.Running {
				return false
			}
			s.tasks = append(s.tasks[:i], s.tasks[i+1:]...)
			if s.cur == t {
				s.cur = nil
			}
			return true
		}
	}
	return false
}

func (s *store) setCancel(fn context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancel = fn
}

func (s *store) stop() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil && s.cur != nil && s.cur.St.Running {
		s.cancel()
		return true
	}
	return false
}

// ---- 持久化(本地实时视图) ----

type persistedDoc struct {
	Tasks   []*taskRecord `json:"tasks"`
	SavedAt string        `json:"savedAt"`
}

func (s *store) persist() {
	if s.path == "" {
		return
	}
	// 在持锁期间做深拷贝（含 Hits 切片），避免序列化期间与 addHit 并发读写造成 DATA RACE。
	s.mu.RLock()
	tasks := make([]*taskRecord, len(s.tasks))
	for i, t := range s.tasks {
		cp := *t
		cp.Hits = append([]Hit(nil), t.Hits...)
		tasks[i] = &cp
	}
	savedAt := nowStamp()
	s.mu.RUnlock()
	doc := persistedDoc{Tasks: tasks, SavedAt: savedAt}
	if buf, err := json.MarshalIndent(doc, "", "  "); err == nil {
		s.writeAtomic(s.path, buf)
	}
}

func (s *store) writeAtomic(path string, buf []byte) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// load 启动时从盘加载历史任务。
func (s *store) load() bool {
	if s.path == "" {
		return false
	}
	buf, err := os.ReadFile(s.path)
	if err != nil {
		return false
	}
	var doc persistedDoc
	if err := json.Unmarshal(buf, &doc); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = doc.Tasks
	for _, t := range s.tasks {
		t.St.Running = false                      // 重启后必非运行态
		t.St.Resumable = len(t.Pending) > 0       // 有残留队列 → 可续扫(进程中途退出)
		t.seen = make(map[string]struct{}, len(t.Hits))
		for _, h := range t.Hits { // 重建命中去重集
			t.seen[h.URL] = struct{}{}
		}
	}
	if len(s.tasks) > 0 {
		s.cur = s.tasks[len(s.tasks)-1]
	}
	return len(s.tasks) > 0
}
