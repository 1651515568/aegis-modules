package vulnpoc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const dataFile = "data/vuln-poc-entries.json"

// Status 漏洞生命周期状态。
type Status string

const (
	StatusUnconfirmed Status = "unconfirmed" // 待确认（刚创建或验证失败）
	StatusConfirmed   Status = "confirmed"   // 已确认存在
	StatusFixing      Status = "fixing"      // 修复中
	StatusFixed       Status = "fixed"       // 已修复
)

// RunResult 单次验证运行结果。
type RunResult struct {
	RunAt    time.Time `json:"runAt"`
	Found    bool      `json:"found"`
	Output   string    `json:"output,omitempty"`
	CurlCmd  string    `json:"curlCmd,omitempty"`
	Request  string    `json:"request,omitempty"`
	Response string    `json:"response,omitempty"`
	ErrMsg   string    `json:"errMsg,omitempty"`
}

// Entry 是一条 PoC 验证条目。
type Entry struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`       // 漏洞名称（可手填或从扫描导入）
	Target     string      `json:"target"`     // 目标 URL / IP
	Template   string      `json:"template"`   // nuclei 模板路径或 template-id
	Severity   string      `json:"severity"`   // critical/high/medium/low/info
	Tags       []string    `json:"tags"`
	Status     Status      `json:"status"`
	Note       string      `json:"note,omitempty"` // 手工备注
	Runs       []RunResult `json:"runs"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	// 来源（从 vuln-scan 导入时填写）
	SourceScan string `json:"sourceScan,omitempty"` // vuln-scan taskId
	SourceHit  string `json:"sourceHit,omitempty"`  // vuln-scan result id
}

func (e *Entry) LastRun() *RunResult {
	if len(e.Runs) == 0 {
		return nil
	}
	return &e.Runs[len(e.Runs)-1]
}

// runState 跟踪某条 entry 的异步运行状态。
type runState struct {
	running  bool
	cancelFn context.CancelFunc
}

type store struct {
	mu      sync.RWMutex
	entries []*Entry
	runs    map[string]*runState // entryID → 运行状态
	saveMu  sync.Mutex           // 串行化文件写操作
}

func newStore() *store {
	return &store{runs: make(map[string]*runState)}
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *store) list() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *store) get(id string) *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.ID == id {
			cp := *e
			return &cp
		}
	}
	return nil
}

func (s *store) create(e *Entry) {
	e.ID = newID()
	e.CreatedAt = time.Now()
	e.UpdatedAt = time.Now()
	if e.Status == "" {
		e.Status = StatusUnconfirmed
	}
	s.mu.Lock()
	s.entries = append(s.entries, e)
	s.mu.Unlock()
}

func (s *store) update(id string, fn func(*Entry)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.ID == id {
			fn(e)
			e.UpdatedAt = time.Now()
			return true
		}
	}
	return false
}

func (s *store) delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e.ID == id {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return true
		}
	}
	return false
}

func (s *store) isRunning(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := s.runs[id]
	return rs != nil && rs.running
}

func (s *store) beginRun(id string, cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.runs[id]
	if rs != nil && rs.running {
		return false
	}
	s.runs[id] = &runState{running: true, cancelFn: cancel}
	return true
}

func (s *store) endRun(id string) {
	s.mu.Lock()
	s.runs[id] = &runState{}
	s.mu.Unlock()
}

func (s *store) stopRun(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.runs[id]
	if rs == nil || !rs.running || rs.cancelFn == nil {
		return false
	}
	rs.cancelFn()
	return true
}

func (s *store) save() {
	s.mu.RLock()
	data, _ := json.MarshalIndent(s.entries, "", "  ")
	s.mu.RUnlock()
	_ = os.MkdirAll(filepath.Dir(dataFile), 0o755)
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	tmp := dataFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, dataFile)
	}
}

func (s *store) load() {
	data, err := os.ReadFile(dataFile)
	if err != nil {
		return
	}
	var entries []*Entry
	if json.Unmarshal(data, &entries) == nil {
		s.mu.Lock()
		s.entries = entries
		s.mu.Unlock()
	}
}
