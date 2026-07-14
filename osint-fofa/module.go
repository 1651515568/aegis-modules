// Package osintfofa —— 空间测绘查询模块。
//
// 对接 FOFA / Hunter / Shodan / ZoomEye 等主流空间测绘平台，
// 允许用户输入各平台自有查询语法，批量拉取、去重、归档资产结果。
// 架构与 asset-collect / scan-backup 同构：manifest + module + register + handler + functions + api_sources + findings。
package osintfofa

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

// Module 实现 core.Module + core.Migrator 接口，为空间测绘能力提供服务。
type Module struct {
	manifest core.Manifest
	log      core.Logger
	db       core.DB
	runs     *core.TaskRuns
	mu       sync.Mutex
	cancel   context.CancelFunc // 当前运行中查询任务的取消函数
}

// New 创建模块实例，在 init() 中被调用以完成自注册。
func New() *Module {
	return &Module{manifest: core.MustParseManifest(manifestBytes)}
}

func (m *Module) Manifest() core.Manifest     { return m.manifest }
func (m *Module) Migrations() (fs.FS, string) { return migrationsFS, "migrations" }
func (m *Module) FrontendFS() fs.FS           { return nil }

// Init 在引擎启动时调用，注入内核依赖（日志、数据库）。
func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.db = k.DB(m.manifest.ID)
	if m.db != nil {
		m.runs = core.NewTaskRuns(m.db)
	}
	m.log.Info("osint-fofa 模块初始化完成")
	return nil
}

// OnEnable 在前端启用模块时调用，幂等建立任务运行表。
func (m *Module) OnEnable(_ context.Context) error {
	if m.runs != nil {
		if err := m.runs.Ensure(); err != nil {
			return err
		}
	}
	m.log.Info("osint-fofa 模块已启用")
	return nil
}

// OnDisable 在前端禁用模块时调用，取消正在运行的查询任务。
func (m *Module) OnDisable(_ context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
	m.log.Info("osint-fofa 模块已禁用")
	return nil
}
