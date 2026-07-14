// Package portscan —— 端口扫描能力模块(AEGIS id: scan-port)。
//
// 与参考模块 scan-backup 同构:manifest + module + register + handler + store + functions + findings。
// 扫描引擎默认使用内嵌的 masscan 二进制(masscan.go),无管理员/无 libpcap/Npcap/无二进制时
// 自动回退到纯 Go connect/UDP 扫描(scanner.go)。结果通过 /api/m/scan-port/* 暴露,
// 异步扫描走统一 task_id(/functions + /invoke + /tasks),命中按 task_id 归档进自有表。
//
// 注意:Go 包名为 portscan(包名不能含 '-'),但能力 id 以 manifest.yaml 的 scan-port 为准。
package portscan

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
	db       core.DB        // 作用域持久化句柄(m_scan_port_*),未配持久化时为 nil
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
	m.log.Info("scan-port module initialized")
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
		m.log.Info("scan-port enabled — loaded local scan history", "tasks", len(m.store.listTasks()))
	}
	// 探测内嵌 masscan 是否就绪(best-effort,失败仅日志:运行期会自动回退 connect)。
	if exe, err := ensureMasscan(); err != nil {
		m.log.Info("scan-port enabled — masscan 不可用,将使用 connect 引擎", "reason", err.Error())
	} else {
		m.log.Info("scan-port enabled — masscan engine ready", "exe", exe)
	}
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.store.stop() // 若有扫描在跑,停掉
	m.log.Info("scan-port disabled")
	return nil
}
