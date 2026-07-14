package fpbrowser

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
}

func New() *Module {
	return &Module{manifest: core.MustParseManifest(manifestBytes)}
}

func (m *Module) Manifest() core.Manifest          { return m.manifest }
func (m *Module) FrontendFS() fs.FS                { return nil }
func (m *Module) OnEnable(_ context.Context) error  { m.log.Info("fp-browser enabled"); return nil }
func (m *Module) OnDisable(_ context.Context) error { m.log.Info("fp-browser disabled"); return nil }

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	m.log.Info("fp-browser initialized")
	return nil
}
