//go:build !npcap && !linux

package portscan

import (
	"context"
	"errors"
	"time"
)

// 非 Linux + 非 npcap 环境下的占位实现。
// Linux 用 synscan_linux.go（原生 raw socket）；npcap 用 synscan.go（gopacket）。

func synAvailable() bool { return false }

func (m *Module) synScan(_ context.Context, _ []string, _ []int, _ scanOptions, _ time.Duration) error {
	return errors.New("SYN 扫描不可用：Linux 平台原生支持；其他平台需 -tags npcap 构建")
}
