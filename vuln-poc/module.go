package vulnpoc

import (
	"context"
	_ "embed"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"redops/core"
)

//go:embed manifest.yaml
var manifestBytes []byte

type Module struct {
	manifest core.Manifest
	log      core.Logger
	store    *store
	runner   *runner
	lib      *library
}

func New() *Module { return &Module{manifest: core.MustParseManifest(manifestBytes)} }

func (m *Module) Manifest() core.Manifest { return m.manifest }
func (m *Module) FrontendFS() fs.FS       { return nil }

// autoExtract 若 destDir 不存在且 tarGz 存在，则自动解压（解压后删除压缩包）。
func autoExtract(tarGz, destDir string) {
	if _, err := os.Stat(destDir); err == nil {
		return // 目录已存在，无需解压
	}
	if _, err := os.Stat(tarGz); err != nil {
		return // 压缩包不存在，跳过
	}
	// tar xzf <tarGz> -C <parent>，Linux 原生支持中文文件名
	if err := exec.Command("tar", "xzf", tarGz, "-C", filepath.Dir(tarGz)).Run(); err == nil {
		_ = os.Remove(tarGz)
	}
}

func (m *Module) Init(k core.Kernel) error {
	m.log = k.Logger().With("module", m.manifest.ID)
	// 自动解压打包在模块内的模板库（同事部署时无需手动操作）
	autoExtract("modules/vuln-poc/poc-exploits.tar.gz", "modules/vuln-poc/poc-exploits")
	autoExtract("modules/vuln-poc/nuclei-templates.tar.gz", "modules/vuln-poc/nuclei-templates")
	autoExtract("modules/vuln-poc/custom-templates.tar.gz", "modules/vuln-poc/custom-templates")
	m.store = newStore()
	m.runner = newRunner(m.log, m.store)
	m.lib = newLibrary(m.log)
	if err := m.lib.open(); err != nil {
		m.log.Warn("漏洞库数据库初始化失败", "err", err)
	}
	return nil
}

func (m *Module) OnEnable(_ context.Context) error {
	m.store.load()
	m.log.Info("vuln-poc enabled", "entries", len(m.store.list()))
	m.lib.StartBuild()
	return nil
}

func (m *Module) OnDisable(_ context.Context) error {
	m.store.save()
	return nil
}
