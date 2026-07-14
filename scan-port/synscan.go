//go:build npcap

package portscan

// synscan.go —— masscan 式 SYN 半开扫描(gopacket + Npcap)。
//
// 思路:用 pcap 自行注入 TCP SYN 包,独立 goroutine 抓回包:
//   * 收到 SYN+ACK → 端口开放(随后内核可能回 RST,无所谓,我们已捕获)
//   * 收到 RST     → 端口关闭
//   * 无回包       → 被过滤
// 无状态:把 (目标IP,端口) 编码进 SYN 的序列号(SYN cookie),回包的 ACK-1 必须等于
// 该 cookie 才认定是对我们 SYN 的应答 —— 因此无需维护未决探测表。
//
// 需要:Npcap 运行时 + 管理员权限(注入)+ gopacket 依赖。用 `-tags npcap` 构建。
// gopacket 不在引擎 go.mod;启用前先 `go get github.com/google/gopacket`。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func synAvailable() bool { return true }

const synSrcPort = 54321 // 固定源端口,便于 BPF 过滤回包

// synScan 执行一次 SYN 扫描。hosts 为目标(域名/IP),ports 为端口列表。
func (m *Module) synScan(ctx context.Context, hosts []string, ports []int, opt scanOptions, timeout time.Duration) error {
	// 解析目标为 IPv4,并保留「IP→原始标签」映射用于结果展示。
	var ips []net.IP
	label := map[string]string{}
	for _, h := range hosts {
		ipa, err := net.ResolveIPAddr("ip4", h)
		if err != nil || ipa.IP.To4() == nil {
			continue
		}
		ip := ipa.IP.To4()
		ips = append(ips, ip)
		label[ip.String()] = h
	}
	if len(ips) == 0 {
		return errors.New("无可解析的 IPv4 目标")
	}

	eg, err := egressFor(ips[0])
	if err != nil {
		return err
	}
	m.log.Info("synscan egress", "dev", eg.device, "srcIP", eg.srcIP, "srcMAC", eg.srcMAC, "gw", eg.gwIP)

	handle, err := pcap.OpenLive(eg.device, 65536, false, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("打开网卡失败(SYN 扫描需管理员权限运行后端): %w", err)
	}
	defer handle.Close()

	// 解析下一跳 MAC:有网关走网关,否则按目标逐个 ARP(同网段)。
	_ = handle.SetBPFFilter("arp")
	hopMAC := map[string]net.HardwareAddr{}
	resolveHopFor := func(dst net.IP) net.HardwareAddr {
		hop := dst
		if eg.gwIP != nil {
			hop = eg.gwIP
		}
		key := hop.String()
		if mac, ok := hopMAC[key]; ok {
			return mac
		}
		mac, err := arpResolve(handle, eg.srcIP, eg.srcMAC, hop, 1500*time.Millisecond)
		if err != nil {
			m.log.Warn("synscan ARP failed", "hop", key, "err", err)
			hopMAC[key] = nil
			return nil
		}
		hopMAC[key] = mac
		return mac
	}
	if eg.gwIP != nil {
		if resolveHopFor(ips[0]) == nil {
			return errors.New("解析网关 MAC 失败")
		}
	} else {
		for _, ip := range ips {
			resolveHopFor(ip)
		}
	}

	// 切换到只抓「发往本机源端口的 TCP」回包。
	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and dst host %s and dst port %d", eg.srcIP, synSrcPort)); err != nil {
		return fmt.Errorf("设置抓包过滤失败: %w", err)
	}

	secret := uint64(time.Now().UnixNano())
	lim := newRateLimiter(opt.Rate)

	// RX:独立 goroutine 持续解析回包,直到 done。
	// seen 去重:开放端口会重传 SYN-ACK(我们不完成握手),每个 (ip:port) 只计一次。
	done := make(chan struct{})
	seen := map[string]bool{}
	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		pkts := src.Packets()
		for {
			select {
			case <-done:
				return
			case pkt, ok := <-pkts:
				if !ok {
					return
				}
				m.handleSynReply(pkt, secret, label, seen)
			}
		}
	}()

	// TX:按 BlackRock 随机顺序遍历 目标×端口,注入 SYN。
	total := len(ips) * len(ports)
	np := uint64(len(ports))
	perm := newPermutation(uint64(total), secret)
	buf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

tx:
	for i := uint64(0); i < uint64(total); i++ {
		if ctx.Err() != nil {
			break
		}
		idx := perm.at(i)
		dst := ips[idx/np]
		port := ports[idx%np]
		mac := hopMAC[hopKey(eg, dst)]
		if mac == nil {
			m.store.incProbed()
			continue
		}
		if lim.wait(ctx) != nil {
			break tx
		}
		eth := &layers.Ethernet{SrcMAC: eg.srcMAC, DstMAC: mac, EthernetType: layers.EthernetTypeIPv4}
		ip4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: eg.srcIP, DstIP: dst}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(synSrcPort), DstPort: layers.TCPPort(port),
			Seq: synCookie(dst, port, secret), SYN: true, Window: 1024,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip4)
		if err := gopacket.SerializeLayers(buf, sopts, eth, ip4, tcp); err != nil {
			m.store.incProbed()
			continue
		}
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			m.log.Warn("synscan write failed", "err", err)
		}
		m.store.incProbed()
	}

	// 等待迟到的回包(stragglers),再停 RX。
	select {
	case <-time.After(timeout + 500*time.Millisecond):
	case <-ctx.Done():
	}
	handle.Close() // 关闭 pcap handle 使 pkts channel 关闭，RX goroutine 自然退出
	close(done)    // 兜底信号：确保 goroutine 即使未读到 pkts 关闭也能退出

	// 无 SYN-ACK 也无 RST 的 = 被过滤。
	st := m.store.status()
	if f := st.Probed - st.Found - st.Closed; f > 0 {
		m.store.setFiltered(f)
	}

	// 发现后服务识别:对开放端口二次 connect 抓 banner(SYN 本身无 banner)。
	if opt.Banner && ctx.Err() == nil {
		open := m.store.list()
		if len(open) > 0 {
			m.store.setPhase("服务识别")
			m.log.Info("synscan banner enrichment", "open", len(open))
			m.enrichBanners(ctx, open, opt, timeout)
		}
	}
	return nil
}

func hopKey(eg *egress, dst net.IP) string {
	if eg.gwIP != nil {
		return eg.gwIP.String()
	}
	return dst.String()
}

// handleSynReply 解析一个回包:SYN-ACK→开放,RST→关闭(均校验 SYN cookie 并按 ip:port 去重)。
func (m *Module) handleSynReply(pkt gopacket.Packet, secret uint64, label map[string]string, seen map[string]bool) {
	ipl := pkt.Layer(layers.LayerTypeIPv4)
	tl := pkt.Layer(layers.LayerTypeTCP)
	if ipl == nil || tl == nil {
		return
	}
	ip4 := ipl.(*layers.IPv4)
	tcp := tl.(*layers.TCP)
	port := int(tcp.SrcPort)
	// 校验:回包 ACK-1 必须等于我们对 (srcIP, srcPort) 发出的 SYN cookie。
	if tcp.Ack-1 != synCookie(ip4.SrcIP.To4(), port, secret) {
		return
	}
	key := ip4.SrcIP.String() + ":" + strconv.Itoa(port)
	if seen[key] { // 同一端口的重传回包只计一次
		return
	}
	if tcp.SYN && tcp.ACK {
		seen[key] = true
		host := label[ip4.SrcIP.String()]
		if host == "" {
			host = ip4.SrcIP.String()
		}
		m.store.addPort(Port{Host: host, Port: port, Proto: "tcp", Service: serviceName(port), Banner: ""})
	} else if tcp.RST {
		seen[key] = true
		m.store.incClosed()
	}
}

// arpResolve 通过 ARP 请求解析 target 的 MAC。
func arpResolve(handle *pcap.Handle, srcIP net.IP, srcMAC net.HardwareAddr, target net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	eth := &layers.Ethernet{
		SrcMAC: srcMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: srcMAC, SourceProtAddress: srcIP.To4(),
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: target.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, sopts, eth, arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if al := pkt.Layer(layers.LayerTypeARP); al != nil {
			a := al.(*layers.ARP)
			if a.Operation == layers.ARPReply && net.IP(a.SourceProtAddress).Equal(target) {
				return net.HardwareAddr(a.SourceHwAddress), nil
			}
		}
	}
	return nil, errors.New("ARP 超时")
}
