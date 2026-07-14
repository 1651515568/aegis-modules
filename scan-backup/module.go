// Package backup —— 备份文件模块。
//
// 与示范模块 operations 同构：manifest + module + register + handler + store。
// 启用时先注入一组演示种子命中；触发 /scan 后改为对真实目标做存在性探测
// （HEAD / Range，绝不下载文件体），结果通过 /api/m/backup/* 暴露给前端。
package backup

import (
	"context"
	"embed"
	"io/fs"

	"redops/core"
)

//go:embed manifest.yaml
var manifestBytes []byte

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Module struct {
	manifest core.Manifest
	log      core.Logger
	store    *store
	sc       *scanner
	db       core.DB       // 作用域持久化句柄(m_scan_backup_*)
	runs     *core.TaskRuns // 按系统 task_id 落库的任务运行表
}

func New() *Module {
	return &Module{
		manifest: core.MustParseManifest(manifestBytes),
		store:    newStore(hitsFile),
	}
}

func (m *Module) Manifest() core.Manifest { return m.manifest }

// Migrations 声明模块自有表的迁移 FS,框架在启用时自动建表(core.Migrator)。
func (m *Module) Migrations() (fs.FS, string) { return migrationsFS, "migrations" }

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.sc = newScanner(m.log, m.store)
	m.db = k.DB(m.manifest.ID)
	if m.db != nil {
		m.runs = core.NewTaskRuns(m.db)
	}
	m.log.Info("backup module initialized")
	return nil
}

func (m *Module) FrontendFS() fs.FS { return nil }

func (m *Module) OnEnable(_ context.Context) error {
	// 标准任务表幂等建表(框架 DDL);自有 findings 表已由框架据 Migrator 建好。
	if m.runs != nil {
		if err := m.runs.Ensure(); err != nil {
			return err
		}
	}
	// 优先从盘加载历史命中(持久化);无历史时回落到演示种子。
	if m.store.load() {
		m.log.Info("backup enabled — loaded persisted hits", "count", len(m.store.list()))
	} else {
		m.store.seed()
		m.log.Info("backup enabled — seeded demo hits")
	}
	// 载入上次任务描述:若进程曾在扫描中途退出,则标记为可续扫。
	if j := m.store.loadJob(); j != nil && j.Status != "done" && j.remaining() > 0 {
		m.log.Info("backup resumable scan detected", "completed", len(j.Completed), "remaining", j.remaining())
	}
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.log.Info("backup disabled")
	return nil
}
