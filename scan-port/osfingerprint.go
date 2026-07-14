package portscan

// osfingerprint.go —— 轻量 OS 指纹推断（仅供参考，非精确判断）。
//
// 两种推断路径：
//   1. TTL + TCP 窗口大小（SYN 扫描从原始 SYN-ACK 报文中提取）
//      - TTL 指示初始跳数：Linux/macOS=64，Windows=128，Cisco/网络设备=255
//      - 窗口大小辅助区分同 TTL 段内的 OS（如 Windows 10 常用 65535，Linux 常用 29200）
//   2. Banner 字符串模式匹配（connect 模式；从 SSH/FTP/SMTP 问候行中提取）
//
// 因路由器每过一跳 TTL-1，故判断 OS 时用 "最近归一" 策略：
//   实测 TTL ≤ 64  → 推断初始 TTL=64  → Linux/macOS
//   实测 TTL ≤ 128 → 推断初始 TTL=128 → Windows
//   实测 TTL ≤ 255 → 推断初始 TTL=255 → 网络设备/Cisco/BSD

import "strings"

// guessOSFromTTLWindow 用 TTL 和 TCP 窗口大小推断 OS。
// ttl 是从收到的 SYN-ACK IP 头中读取的实测值；winSize 是 SYN-ACK TCP 头中的窗口大小。
func guessOSFromTTLWindow(ttl uint8, winSize uint16) string {
	base := ""
	switch {
	case ttl > 128: // 初始 TTL=255 ← Cisco IOS / FreeBSD / OpenBSD
		base = "网络设备/Cisco/BSD"
	case ttl > 64: // 初始 TTL=128 ← Windows
		switch winSize {
		case 8192:
			base = "Windows (窗口=8192)"
		case 65535:
			base = "Windows (窗口=65535)"
		default:
			base = "Windows"
		}
	case ttl > 0: // 初始 TTL=64 ← Linux / macOS
		switch winSize {
		case 5840, 14600, 29200:
			base = "Linux"
		case 65535:
			base = "macOS/Linux"
		default:
			base = "Linux/macOS"
		}
	}
	return base
}

// guessOSFromBanner 从 banner/问候行中用关键词推断 OS（connect 模式补充）。
// 返回空串表示无法推断。
func guessOSFromBanner(banner string) string {
	b := strings.ToLower(banner)
	switch {
	// SSH banner
	case strings.Contains(b, "ubuntu"):
		return "Linux (Ubuntu)"
	case strings.Contains(b, "debian"):
		return "Linux (Debian)"
	case strings.Contains(b, "centos"):
		return "Linux (CentOS)"
	case strings.Contains(b, "fedora"):
		return "Linux (Fedora)"
	case strings.Contains(b, "alpine"):
		return "Linux (Alpine)"
	case strings.Contains(b, "openssh"):
		return "Linux/Unix"
	// Windows-specific services
	case strings.Contains(b, "microsoft") || strings.Contains(b, "windows") || strings.Contains(b, "iis"):
		return "Windows"
	// Network devices
	case strings.Contains(b, "cisco") || strings.Contains(b, "ios"):
		return "Cisco IOS"
	case strings.Contains(b, "juniper"):
		return "Juniper"
	case strings.Contains(b, "huawei") || strings.Contains(b, "vrp"):
		return "Huawei VRP"
	case strings.Contains(b, "mikrotik") || strings.Contains(b, "routeros"):
		return "MikroTik RouterOS"
	case strings.Contains(b, "fortinet") || strings.Contains(b, "fortigate"):
		return "Fortinet FortiOS"
	}
	return ""
}
