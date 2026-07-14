package assetcollect

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

// Module implements core.Module + core.Migrator for the 资产收集 capability.
type Module struct {
	manifest core.Manifest
	log      core.Logger
	db       core.DB
	runs     *core.TaskRuns
	mu       sync.Mutex
	cancel   context.CancelFunc
}

func New() *Module {
	return &Module{manifest: core.MustParseManifest(manifestBytes)}
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
	m.log.Info("asset-collect module initialized")
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	if m.runs != nil {
		if err := m.runs.Ensure(); err != nil {
			return err
		}
	}
	m.log.Info("asset-collect module enabled")
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
	m.log.Info("asset-collect module disabled")
	return nil
}
