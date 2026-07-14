package portscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// tasksFile 是扫描历史(多任务)的本地实时视图落盘路径。data/ 已在 .gitignore 中。
// 注意:跨页面/可审计的权威任务台账走 AEGIS 统一 task_id(m_scan_port_task_runs +
// m_scan_port_findings),本文件仅供引擎本地保留「最近扫描」实时视图,重启不致全空。
const tasksFile = "data/scan-port/tasks.json"

// maxHistory 限制后端保留的历史任务数,避免无限增长。
const maxHistory = 50

// Port 是一条端口扫描结果(开放端口)。
type Port struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	OsGuess string `json:"osGuess,omitempty"` // OS 指纹猜测(TTL/窗口/banner 推断;仅供参考)
}

// scanStatus 是一次扫描任务的实时进度快照。
type scanStatus struct {
	Running   bool   `json:"running"`
	Phase     string `json:"phase"`
	Total     int    `json:"total"`
	Probed    int    `json:"probed"`
	Found     int    `json:"found"`
	Closed    int    `json:"closed"`
	Filtered  int    `json:"filtered"`
	Alive     int    `json:"alive"`
	Rate      int    `json:"rate"` // 当前生效速率(自适应时实时变化),0=不限
	Engine    string `json:"engine"`
	ElapsedMs int64  `json:"elapsedMs"`
	Target    string `json:"target"`
	StartedAt string `json:"startedAt"`
	EndedAt   string `json:"endedAt"`
	Err       string `json:"err"`
}

// taskRecord 是一个扫描任务(含参数、进度、结果),后端历史的基本单元。
type taskRecord struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Targets []string    `json:"targets"`
	Opts    scanOptions `json:"opts"`
	St      scanStatus  `json:"status"`
	Ports   []Port      `json:"ports"`

	startedTime time.Time
	endedTime   time.Time
}

// taskSummary 是列表接口用的轻量摘要(不含完整端口列表)。
type taskSummary struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Targets   []string    `json:"targets"`
	Opts      scanOptions `json:"opts"`
	Status    scanStatus  `json:"status"`
	CreatedAt string      `json:"createdAt"`
	PortCount int         `json:"portCount"`
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
func (s *store) setEngine(e string) { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Engine = e } }
func (s *store) setAlive(n int)     { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Alive = n } }
func (s *store) setTotal(n int)     { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Total = n } }
func (s *store) setProbed(n int)    { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Probed = n } }
func (s *store) incProbed()         { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Probed++ } }
func (s *store) incClosed()         { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Closed++ } }
func (s *store) incFiltered()       { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Filtered++ } }
func (s *store) setFiltered(n int)  { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Filtered = n } }
func (s *store) setRate(n int)      { s.mu.Lock(); defer s.mu.Unlock(); if s.cur != nil { s.cur.St.Rate = n } }

func (s *store) addPort(p Port) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.Ports = append(s.cur.Ports, p)
		s.cur.St.Found++
	}
}

// updatePort 回填某个开放端口的服务名/banner/OsGuess(SYN/masscan 发现后二次抓 banner 用)。
func (s *store) updatePort(host string, port int, service, banner, osGuess string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return
	}
	for i := range s.cur.Ports {
		if s.cur.Ports[i].Host == host && s.cur.Ports[i].Port == port {
			if service != "" {
				s.cur.Ports[i].Service = service
			}
			if banner != "" {
				s.cur.Ports[i].Banner = banner
			}
			if osGuess != "" && s.cur.Ports[i].OsGuess == "" {
				// 仅在 SYN 扫描未能推断时补充 banner 推断结果
				s.cur.Ports[i].OsGuess = osGuess
			}
			return
		}
	}
}

func (s *store) finishScan(errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.St.Running = false
		s.cur.St.EndedAt = nowStamp()
		s.cur.St.Err = errMsg
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

// list 返回当前任务的端口结果(/ports 用,含运行期实时结果)。
func (s *store) list() []Port {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return nil
	}
	out := make([]Port, len(s.cur.Ports))
	copy(out, s.cur.Ports)
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
			Status: st, CreatedAt: st.StartedAt, PortCount: len(t.Ports),
		})
	}
	return out
}

// taskByID 返回某任务的完整记录(含端口)。
func (s *store) taskByID(id string) (*taskRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tasks {
		if t.ID == id {
			cp := *t
			cp.Ports = append([]Port(nil), t.Ports...)
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
	// 在持锁期间做深拷贝（含 Ports 切片），避免序列化期间与 addPort 并发读写造成 DATA RACE。
	s.mu.RLock()
	tasks := make([]*taskRecord, len(s.tasks))
	for i, t := range s.tasks {
		cp := *t
		cp.Ports = append([]Port(nil), t.Ports...)
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
		t.St.Running = false // 重启后必非运行态
	}
	if len(s.tasks) > 0 {
		s.cur = s.tasks[len(s.tasks)-1]
	}
	return len(s.tasks) > 0
}
