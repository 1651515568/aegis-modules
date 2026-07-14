package vulnscan

// nuclei_embed.go — 内嵌 nuclei 可执行文件，运行时解压到 data/vuln-scan/bin/。
// 命名约定: nuclei-<os>-<arch>，与 masscan.go 保持一致。

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed bin
var nucleiBins embed.FS

const nucleiRunDir = "data/vuln-scan/bin"

// nucleiBinName 返回当前平台对应的内嵌文件名。
func nucleiBinName() string {
	name := "nuclei-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// ensureNuclei 将内嵌 nuclei 释放到 nucleiRunDir，返回可执行路径。
// 若当前平台无内嵌二进制则返回 error，由调用方 fallback 到 PATH 查找。
func ensureNuclei() (string, error) {
	name := nucleiBinName()
	data, err := nucleiBins.ReadFile("bin/" + name)
	if err != nil {
		return "", fmt.Errorf("未内嵌当前平台 nuclei（缺 bin/%s）", name)
	}
	if len(data) < 1024 {
		return "", fmt.Errorf("内嵌 bin/%s 异常，疑为占位文件", name)
	}
	// 简单 magic 校验：ELF 或 PE
	if !isNucleiValidMagic(data) {
		return "", fmt.Errorf("内嵌 bin/%s 非有效可执行文件", name)
	}
	if err := os.MkdirAll(nucleiRunDir, 0o755); err != nil {
		return "", fmt.Errorf("创建释放目录失败: %w", err)
	}
	dest := filepath.Join(nucleiRunDir, name)
	// SHA-256 增量校验：内容相同则跳过写入
	wantSum := sha256.Sum256(data)
	if fi, err := os.Stat(dest); err == nil && fi.Size() == int64(len(data)) {
		if existing, err2 := os.ReadFile(dest); err2 == nil && sha256.Sum256(existing) == wantSum {
			return dest, nil
		}
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		return "", fmt.Errorf("释放 nuclei 失败: %w", err)
	}
	return dest, nil
}

func isNucleiValidMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ELF: 0x7f E L F
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}
	// PE: M Z
	if data[0] == 'M' && data[1] == 'Z' {
		return true
	}
	return false
}