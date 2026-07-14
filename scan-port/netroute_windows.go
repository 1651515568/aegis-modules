//go:build npcap

package portscan

// netroute_windows.go —— 出口接口 / 源 IP·MAC / 网关 发现(用于 SYN 扫描的二层封装)。
// 通过 iphlpapi 的 GetAdaptersAddresses 读取适配器信息,避免解析 route print 文本。

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	gaaFlagIncludeGateways = 0x0080
)

type adapterInfo struct {
	guid string // 适配器 GUID(用于拼 pcap 设备名)
	mac  net.HardwareAddr
	ips  []net.IP
	gw   net.IP
}

// egress 描述到达某目标应使用的出口参数。
type egress struct {
	device string // pcap 设备名:\Device\NPF_{GUID}
	srcIP  net.IP
	srcMAC net.HardwareAddr
	gwIP   net.IP
}

// listAdapters 枚举本机 IPv4 适配器(含 MAC、单播地址、网关)。
func listAdapters() ([]adapterInfo, error) {
	size := uint32(15000)
	var buf []byte
	for i := 0; i < 5; i++ {
		buf = make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, gaaFlagIncludeGateways, 0, aa, &size)
		if err == nil {
			break
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return nil, err
	}
	var out []adapterInfo
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		info := adapterInfo{guid: windows.BytePtrToString(aa.AdapterName)}
		if aa.PhysicalAddressLength > 0 {
			info.mac = net.HardwareAddr(aa.PhysicalAddress[:aa.PhysicalAddressLength])
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := sockaddrIP(ua.Address); ip != nil {
				info.ips = append(info.ips, ip)
			}
		}
		for ga := aa.FirstGatewayAddress; ga != nil; ga = ga.Next {
			if ip := sockaddrIP(ga.Address); ip != nil {
				info.gw = ip
				break
			}
		}
		out = append(out, info)
	}
	return out, nil
}

func sockaddrIP(sa windows.SocketAddress) net.IP {
	if sa.Sockaddr == nil {
		return nil
	}
	rsa := (*windows.RawSockaddrAny)(unsafe.Pointer(sa.Sockaddr))
	if rsa.Addr.Family == windows.AF_INET {
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(rsa))
		ip := make(net.IP, 4)
		copy(ip, p.Addr[:])
		return ip
	}
	return nil
}

// egressFor 计算到达 target 的出口接口/源地址/网关。
func egressFor(target net.IP) (*egress, error) {
	// 内核会替我们选好源 IP:对目标做一次 UDP "连接"(不实际发包)取本地地址。
	conn, err := net.Dial("udp", net.JoinHostPort(target.String(), "80"))
	if err != nil {
		return nil, fmt.Errorf("确定出口源地址失败: %w", err)
	}
	srcIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()
	srcIP = srcIP.To4()
	if srcIP == nil {
		return nil, errors.New("仅支持 IPv4 SYN 扫描")
	}

	adapters, err := listAdapters()
	if err != nil {
		return nil, err
	}
	for _, a := range adapters {
		for _, ip := range a.ips {
			if ip.Equal(srcIP) {
				if a.mac == nil {
					return nil, errors.New("出口接口无 MAC(可能是隧道/虚拟接口,SYN 扫描不支持)")
				}
				return &egress{
					device: `\Device\NPF_` + a.guid,
					srcIP:  srcIP,
					srcMAC: a.mac,
					gwIP:   a.gw, // 可能为 nil(目标在同网段);调用方据此决定 ARP 谁
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("未找到源 IP %s 对应的网卡", srcIP)
}
