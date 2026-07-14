package portscan

// cookie.go —— SYN cookie:把 (目标IP,端口) 确定性编码进 TCP 序列号,
// 使 SYN 扫描无状态(回包 ACK-1 必须等于该 cookie 才认定是对我们 SYN 的应答)。
// 放在无构建标签的文件中,便于默认测试覆盖。

import (
	"encoding/binary"
	"net"
)

func synCookie(ip net.IP, port int, secret uint64) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	v := uint64(binary.BigEndian.Uint32(ip))<<16 | uint64(uint16(port))
	return uint32(mix(v ^ secret))
}
