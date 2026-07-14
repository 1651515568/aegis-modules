package bruteforce

// module.go —— 弱口令爆破模块入口。
//
// 与 scan-backup 同构：manifest + module + register + handler + findings + functions + scanner。
// 框架透过 core.Module 接口驱动生命周期，无需自行监听端口或管理数据库连接。

import (
	"context"
	"embed"
	"io/fs"
	"sync"

	"redops/core"
)

//go:embed manifest.yaml
var manifestBytes []byte

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Module implements core.Module + core.Migrator for the 弱口令爆破 capability.
type Module struct {
	manifest core.Manifest
	log      core.Logger
	sc       *bruteScanner  // 无状态扫描器，模块级复用
	db       core.DB
	runs     *core.TaskRuns
	mu       sync.Mutex
	cancel   context.CancelFunc // 当前运行中的任务取消句柄，nil 表示空闲
}

func New() *Module {
	return &Module{
		manifest: core.MustParseManifest(manifestBytes),
		sc:       newBruteScanner(),
	}
}

func (m *Module) Manifest() core.Manifest     { return m.manifest }
func (m *Module) Migrations() (fs.FS, string) { return migrationsFS, "migrations" }
func (m *Module) FrontendFS() fs.FS           { return nil }

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.db = k.DB(m.manifest.ID)
	if m.db != nil {
		m.runs = core.NewTaskRuns(m.db)
	}
	m.log.Info("brute-force module initialized")
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	if m.runs != nil {
		if err := m.runs.Ensure(); err != nil {
			return err
		}
	}
	m.log.Info("brute-force module enabled")
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	// 停止正在运行的爆破任务（若有）。
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
	m.log.Info("brute-force module disabled")
	return nil
}
