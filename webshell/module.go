package webshell

import (
	"context"
	"embed"
	"io/fs"
	"sync"
	"time"

	"redops/core"
)

//go:embed manifest.yaml
var manifestBytes []byte

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Module struct {
	manifest core.Manifest
	log      core.Logger
	db       core.DB
	store    *shellStore
	proxies  *proxyManager

	// agentCache 为每个 shell 保持持久 HTTP 会话（维持 PHPSESSID cookie），
	// 这是冰蝎协议的必要条件：所有请求必须共享同一 PHP Session。
	agentMu       sync.RWMutex
	agentCache    map[string]*Agent     // shellID → *Agent
	agentLastUsed map[string]time.Time  // shellID → 最后使用时间
	agentStop     chan struct{}          // 关闭信号，终止 TTL 清理 goroutine
}

func New() *Module {
	return &Module{
		manifest: core.MustParseManifest(manifestBytes),
	}
}

func (m *Module) Manifest() core.Manifest { return m.manifest }

func (m *Module) Migrations() (fs.FS, string) { return migrationsFS, "migrations" }

func (m *Module) FrontendFS() fs.FS { return nil }

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.db = k.DB(m.manifest.ID)
	if m.db != nil {
		m.store = newShellStore(m.db)
	}
	m.proxies = newProxyManager()
	m.agentCache = make(map[string]*Agent)
	m.agentLastUsed = make(map[string]time.Time)
	m.log.Info("webshell module initialized")
	return nil
}

// getAgent 返回指定 shell 的持久 Agent（含 cookie jar），
// 如果 shell 的 URL/密码变动，需先调用 evictAgent 使缓存失效。
func (m *Module) getAgent(sh *shellRecord) *Agent {
	m.agentMu.RLock()
	a, ok := m.agentCache[sh.ID]
	m.agentMu.RUnlock()
	if ok {
		// 更新最后使用时间（升级为写锁）
		m.agentMu.Lock()
		m.agentLastUsed[sh.ID] = time.Now()
		m.agentMu.Unlock()
		return a
	}
	m.agentMu.Lock()
	defer m.agentMu.Unlock()
	// 双检
	if a, ok = m.agentCache[sh.ID]; ok {
		m.agentLastUsed[sh.ID] = time.Now()
		return a
	}
	a = newAgent(sh.URL, sh.Password, sh.Protocol, sh.CustomHeaders, sh.ShellType)
	m.agentCache[sh.ID] = a
	m.agentLastUsed[sh.ID] = time.Now()
	return a
}

// evictAgent 清除指定 shell 的缓存 Agent（如密码/URL 更新后调用）。
func (m *Module) evictAgent(shellID string) {
	m.agentMu.Lock()
	delete(m.agentCache, shellID)
	delete(m.agentLastUsed, shellID)
	m.agentMu.Unlock()
}

func (m *Module) OnEnable(_ context.Context) error {
	m.agentStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-m.agentStop:
				return
			case <-ticker.C:
				m.evictStaleAgents(30 * time.Minute)
			}
		}
	}()
	m.log.Info("webshell module enabled")
	return nil
}

// evictStaleAgents 删除超过 maxIdle 时间未使用的 Agent。
func (m *Module) evictStaleAgents(maxIdle time.Duration) {
	deadline := time.Now().Add(-maxIdle)
	m.agentMu.Lock()
	defer m.agentMu.Unlock()
	for id, lastUsed := range m.agentLastUsed {
		if lastUsed.Before(deadline) {
			delete(m.agentCache, id)
			delete(m.agentLastUsed, id)
			m.log.Info("evicted stale agent", "shellID", id, "lastUsed", lastUsed)
		}
	}
}

func (m *Module) OnDisable(_ context.Context) error {
	if m.agentStop != nil {
		close(m.agentStop)
		m.agentStop = nil
	}
	m.proxies.stopAll()
	m.log.Info("webshell module disabled")
	return nil
}
