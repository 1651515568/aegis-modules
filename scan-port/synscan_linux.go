//go:build linux && !npcap

package portscan

// synscan_linux.go —— Linux 原生 SYN 半开扫描（无第三方依赖）。
//
// 实现原理：
//   TX: socket(AF_INET, SOCK_RAW, IPPROTO_RAW) + IP_HDRINCL
//       手动构造 IPv4 + TCP 头，SYN cookie 编入序列号，伪随机顺序(BlackRock 置换)发送。
//   RX: socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
//       接收所有 TCP 报文，过滤目标端口、校验 SYN cookie；
//       SYN|ACK → 端口开放（同时提取 TTL/窗口做 OS 指纹）；RST → 关闭。
//
// 内核行为：SYN-ACK 到达时，因端口 linuxSynSrcPort 无绑定 socket，
// 内核会自动回 RST（半开扫描期望行为），raw socket 在此之前已捕获 SYN-ACK，互不干扰。
//
// 权限要求：root 或 CAP_NET_RAW。

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func synAvailable() bool { return true }

// linuxSynSrcPort 是 SYN 报文的源端口（固定值，用于在 RX 侧过滤回包）。
// 该端口在扫描机上应无服务监听。
const linuxSynSrcPort = 54321

func (m *Module) synScan(ctx context.Context, hosts []string, ports []int, opt scanOptions, timeout time.Duration) error {
	// ── 1. 目标 IP 解析 ──
	var ips []net.IP
	label := make(map[string]string, len(hosts))
	for _, h := range hosts {
		ipa, err := net.ResolveIPAddr("ip4", h)
		if err != nil || ipa.IP.To4() == nil {
			continue
		}
		ip := ipa.IP.To4()
		ips = append(ips, cloneIP(ip))
		label[ip.String()] = h
	}
	if len(ips) == 0 {
		return fmt.Errorf("无可解析的 IPv4 目标(SYN 模式仅支持 IPv4)")
	}

	srcIP, err := outboundIPv4()
	if err != nil {
		return fmt.Errorf("获取本机出口 IPv4 失败: %w", err)
	}
	m.log.Info("synscan-linux started", "srcIP", srcIP, "hosts", len(ips), "ports", len(ports))

	// ── 2. TX socket: IPPROTO_RAW + IP_HDRINCL ──
	txFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("TX raw socket: %w (需 root 或 CAP_NET_RAW)", err)
	}
	defer syscall.Close(txFd)
	if err := syscall.SetsockoptInt(txFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("IP_HDRINCL: %w", err)
	}

	// ── 3. RX socket: IPPROTO_TCP（接收所有 TCP 原始报文） ──
	rxFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("RX raw socket: %w", err)
	}
	// sync.Once 保护：rxFd 在正常路径被显式关闭（触发 RX goroutine 退出），
	// 同时 defer 兜底确保 panic/早返回时不泄漏 fd；Once 防止双关闭。
	var rxCloseOnce sync.Once
	closeRx := func() { rxCloseOnce.Do(func() { syscall.Close(rxFd) }) }
	defer closeRx()
	// 增大接收缓冲区，应对高速扫描时的 SYN-ACK 洪峰
	_ = syscall.SetsockoptInt(rxFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)

	secret := uint64(time.Now().UnixNano())
	lim := newRateLimiter(opt.Rate)
	var seen sync.Map

	// ── 4. RX goroutine: 解析 SYN-ACK / RST ──
	rxClosed := make(chan struct{})
	go func() {
		defer close(rxClosed)
		buf := make([]byte, 65535)
		for {
			if ctx.Err() != nil {
				return
			}
			// 设 100ms 接收超时，使 goroutine 能定期检查 ctx
			tv := syscall.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
			_ = syscall.SetsockoptTimeval(rxFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
			n, _, err := syscall.Recvfrom(rxFd, buf, 0)
			if err != nil || n < 40 {
				continue
			}
			// IP 头长度（低 4 位 × 4）
			ihl := int(buf[0]&0x0f) * 4
			if buf[9] != syscall.IPPROTO_TCP || n < ihl+20 {
				continue
			}
			tcp := buf[ihl:]
			dstPort := int(binary.BigEndian.Uint16(tcp[2:4])) // 目标端口 = 我们的源端口
			if dstPort != linuxSynSrcPort {
				continue
			}
			srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
			ackNum := binary.BigEndian.Uint32(tcp[8:12])
			flags := tcp[13]

			srcIPBytes := make(net.IP, 4)
			copy(srcIPBytes, buf[12:16])

			// 校验 SYN cookie：ack-1 必须等于我们对 (srcIP, srcPort) 发出的 cookie
			cookie := synCookie(srcIPBytes, srcPort, secret)
			if ackNum-1 != cookie {
				continue
			}
			key := srcIPBytes.String() + ":" + strconv.Itoa(srcPort)
			if _, loaded := seen.LoadOrStore(key, struct{}{}); loaded {
				continue // 去重：SYN-ACK 可能重传
			}

			ttl := buf[8]
			winSize := binary.BigEndian.Uint16(tcp[14:16])

			const flagSYN = 0x02
			const flagACK = 0x10
			const flagRST = 0x04

			switch {
			case flags&(flagSYN|flagACK) == (flagSYN | flagACK): // 端口开放
				host := label[srcIPBytes.String()]
				if host == "" {
					host = srcIPBytes.String()
				}
				m.store.addPort(Port{
					Host:    host,
					Port:    srcPort,
					Proto:   "tcp",
					Service: serviceName(srcPort),
					OsGuess: guessOSFromTTLWindow(ttl, winSize),
				})
			case flags&flagRST != 0: // 端口关闭
				m.store.incClosed()
			}
		}
	}()

	// ── 5. TX: 伪随机顺序发送 SYN 报文 ──
	total := len(ips) * len(ports)
	np := uint64(len(ports))
	perm := newPermutation(uint64(total), secret)

	for i := uint64(0); i < uint64(total); i++ {
		if ctx.Err() != nil {
			break
		}
		if lim.wait(ctx) != nil {
			break
		}
		idx := perm.at(i)
		dst := ips[idx/np]
		port := ports[idx%np]
		pkt := buildSynPkt(srcIP, dst, linuxSynSrcPort, port, synCookie(dst, port, secret))
		sa := &syscall.SockaddrInet4{Port: port}
		copy(sa.Addr[:], dst.To4())
		_ = syscall.Sendto(txFd, pkt, 0, sa)
		m.store.incProbed()
	}

	// ── 6. 等待迟到的 SYN-ACK ──
	waitCtx, waitCancel := context.WithTimeout(ctx, timeout+600*time.Millisecond)
	defer waitCancel()
	<-waitCtx.Done()

	closeRx() // 关闭 RX socket，使 Recvfrom 返回错误，RX goroutine 退出
	<-rxClosed

	// ── 7. Banner 抓取：对开放端口做二次 connect ──
	if opt.Banner && ctx.Err() == nil {
		open := m.store.list()
		if len(open) > 0 {
			m.store.setPhase("服务识别")
			m.log.Info("synscan-linux banner enrichment", "open", len(open))
			m.enrichBanners(ctx, open, opt, timeout)
		}
	}
	return nil
}

// outboundIPv4 通过 UDP dial 探测本机出口 IPv4 地址（不发送任何数据）。
func outboundIPv4() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("本机出口地址非 IPv4")
	}
	return ip, nil
}

// buildSynPkt 构造原始 IPv4 + TCP SYN 报文（40 字节，无选项）。
func buildSynPkt(src, dst net.IP, srcPort, dstPort int, seq uint32) []byte {
	pkt := make([]byte, 40) // 20 IP + 20 TCP

	// ── IPv4 头 ──
	pkt[0] = 0x45                                       // version=4, IHL=5(×4=20B)
	pkt[1] = 0                                          // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], 40)            // 总长度
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rand.Uint32())) // IP ID（随机）
	pkt[6] = 0x40                                       // Flags: DF=1, MF=0
	pkt[7] = 0                                          // Fragment offset
	pkt[8] = 64                                         // TTL
	pkt[9] = syscall.IPPROTO_TCP                        // Protocol
	// [10:12] 校验和（下方计算后回填）
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], rawChecksum(pkt[:20]))

	// ── TCP 头 ──
	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[24:28], seq)         // Seq = SYN cookie
	binary.BigEndian.PutUint32(pkt[28:32], 0)           // Ack = 0
	pkt[32] = 0x50                                      // Data offset = 5 (20B), reserved=0
	pkt[33] = 0x02                                      // Flags: SYN
	binary.BigEndian.PutUint16(pkt[34:36], 65535)       // Window size
	// [36:38] TCP 校验和（下方计算后回填）
	binary.BigEndian.PutUint16(pkt[38:40], 0)           // Urgent pointer

	// TCP 伪头 + TCP 头联合计算校验和
	pseudo := make([]byte, 12+20)
	copy(pseudo[:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], 20)       // TCP 段长度（无数据）
	copy(pseudo[12:], pkt[20:40])
	binary.BigEndian.PutUint16(pkt[36:38], rawChecksum(pseudo))

	return pkt
}

// rawChecksum 计算 IP/TCP 头的反码校验和。
func rawChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
