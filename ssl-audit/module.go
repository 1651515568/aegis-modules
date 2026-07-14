// Package sslaudit —— SSL/TLS 安全审计模块。
//
// 对目标批量检测：证书有效性与链信任、TLS 协议版本（1.0/1.1 弃用）、
// 弱密码套件（RC4/3DES/无前向保密）、HSTS 响应头配置。
// 检测结果按系统 task_id 落 SQLite；同一时刻只允许一次扫描在跑。
package sslaudit

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

// Module 是 ssl-audit 的生命周期持有者。
type Module struct {
	manifest core.Manifest
	log      core.Logger
	db       core.DB
	runs     *core.TaskRuns

	mu     sync.Mutex
	cancel context.CancelFunc // 当前扫描的取消句柄，nil 表示空闲
	st     *scanState         // 当前扫描内存态（实时 /status /results 使用）
}

func New() *Module { return &Module{manifest: core.MustParseManifest(manifestBytes)} }

func (m *Module) Manifest() core.Manifest     { return m.manifest }
func (m *Module) Migrations() (fs.FS, string) { return migrationsFS, "migrations" }
func (m *Module) FrontendFS() fs.FS           { return nil }

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.db = k.DB(m.manifest.ID)
	if m.db != nil {
		m.runs = core.NewTaskRuns(m.db)
	}
	m.log.Info("ssl-audit module initialized")
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	if m.runs != nil {
		if err := m.runs.Ensure(); err != nil {
			return err
		}
	}
	m.log.Info("ssl-audit enabled")
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.log.Info("ssl-audit disabled")
	return nil
}
