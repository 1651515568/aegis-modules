package xcvuln

import (
	"context"
	_ "embed"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"redops/core"
)

//go:embed manifest.yaml
var manifestBytes []byte

type Module struct {
	manifest core.Manifest
	log      core.Logger

	mu         sync.RWMutex
	cache      []TemplateItem
	cacheReady bool
}

func New() *Module {
	return &Module{
		manifest: core.MustParseManifest(manifestBytes),
	}
}

func (m *Module) Manifest() core.Manifest { return m.manifest }
func (m *Module) FrontendFS() fs.FS       { return nil }

func autoExtract(tarGz, destDir string) {
	if _, err := os.Stat(destDir); err == nil {
		return
	}
	if _, err := os.Stat(tarGz); err != nil {
		return
	}
	if err := exec.Command("tar", "xzf", tarGz, "-C", filepath.Dir(tarGz)).Run(); err == nil {
		_ = os.Remove(tarGz)
	}
}

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", "xc-vuln")
	autoExtract("modules/xc-vuln/xinchuang-templates.tar.gz", "modules/xc-vuln/xinchuang-templates")
	m.log.Info("xc-vuln module initialized")
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	m.log.Info("xc-vuln enabled，开始预热模板缓存")
	// 异步预热，不阻塞启动
	go m.rebuildCache()
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.mu.Lock()
	m.cache = nil
	m.cacheReady = false
	m.mu.Unlock()
	m.log.Info("xc-vuln disabled")
	return nil
}

// getTemplates 返回缓存；若未就绪则同步构建一次（首次请求兜底）。
func (m *Module) getTemplates() []TemplateItem {
	m.mu.RLock()
	if m.cacheReady {
		items := m.cache
		m.mu.RUnlock()
		return items
	}
	m.mu.RUnlock()

	// 缓存未就绪，同步构建
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cacheReady {
		m.cache = m.loadTemplates()
		m.cacheReady = true
		m.log.Info("xc-vuln 模板缓存构建完成", "count", len(m.cache))
	}
	return m.cache
}

// rebuildCache 强制重建缓存（异步调用）。
func (m *Module) rebuildCache() {
	items := m.loadTemplates()
	m.mu.Lock()
	m.cache = items
	m.cacheReady = true
	m.mu.Unlock()
	m.log.Info("xc-vuln 模板缓存预热完成", "count", len(items))
}
