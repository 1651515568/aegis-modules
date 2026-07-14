package vulnscan

import (
	"context"
	_ "embed"
	"io/fs"

	"redops/core"
)

//go:embed manifest.yaml
var manifestBytes []byte

type Module struct {
	manifest core.Manifest
	log      core.Logger
	store    *store
	sc       *scanner
}

func New() *Module { return &Module{manifest: core.MustParseManifest(manifestBytes)} }

func (m *Module) Manifest() core.Manifest { return m.manifest }
func (m *Module) FrontendFS() fs.FS       { return nil }

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.store = newStore()
	m.sc = newScanner(m.log, m.store)
	m.log.Info("vuln-scan initialized")
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	m.store.load()
	m.store.loadTasks()
	m.store.loadTargetLists()
	m.store.loadScope()
	m.store.loadExclusions()
	m.store.loadQueue()
	m.log.Info("vuln-scan enabled",
		"results", m.store.count(),
		"tasks", len(m.store.listTasks()),
		"targetLists", len(m.store.listTargetLists()),
		"exclusions", len(m.store.listExclusions()),
		"queue", len(m.store.listQueue()),
	)
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.sc.engineCancel() // 取消所有由队列自动触发的扫描任务
	m.store.save()
	m.log.Info("vuln-scan disabled")
	return nil
}
