// Package scandir —— 目录扫描能力模块(AEGIS id: scan-dir)。
//
// 与参考模块 scan-port / scan-backup 同构:manifest + module + register + handler +
// store + scanner + functions + findings + export。对授权 Web 目标做目录/文件爆破:
// 内置字典 × 扩展名展开 → 逐路径 HTTP 探测,带软 404(wildcard)基线过滤、全局限速 +
// 429/503 自适应退避、可选递归发现。结果通过 /api/m/scan-dir/* 暴露,异步扫描走统一
// task_id(/functions + /invoke + /tasks),命中按 task_id 归档进自有表 m_scan_dir_findings。
//
// 注意:Go 包名为 scandir(包名不能含 '-'),但能力 id 以 manifest.yaml 的 scan-dir 为准。
package scandir

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
	db       core.DB        // 作用域持久化句柄(m_scan_dir_*),未配持久化时为 nil
	runs     *core.TaskRuns // 按系统 task_id 落库的任务运行表
}

func New() *Module {
	return &Module{
		manifest: core.MustParseManifest(manifestBytes),
		store:    newStore(tasksFile),
	}
}

func (m *Module) Manifest() core.Manifest { return m.manifest }

// Migrations 声明模块自有表的迁移 FS,框架在启用时自动建表(core.Migrator)。
func (m *Module) Migrations() (fs.FS, string) { return migrationsFS, "migrations" }

func (m *Module) FrontendFS() fs.FS { return nil } // AEGIS 集成固定 nil,界面走 React

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.db = k.DB(m.manifest.ID)
	if m.db != nil {
		m.runs = core.NewTaskRuns(m.db)
	}
	m.log.Info("scan-dir module initialized")
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	// 标准任务表幂等建表(框架 DDL);自有 findings 表已由框架据 Migrator 建好。
	if m.runs != nil {
		if err := m.runs.Ensure(); err != nil {
			return err
		}
	}
	// 加载本地实时视图历史(最近扫描),仅用于直连引擎调试展示;不影响权威台账。
	if m.store.load() {
		m.log.Info("scan-dir enabled — loaded local scan history", "tasks", len(m.store.listTasks()))
	}
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.store.stop() // 若有扫描在跑,停掉
	m.log.Info("scan-dir disabled")
	return nil
}
