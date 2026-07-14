package portscan

// udp.go —— UDP 端口扫描(纯 Go,免提权)。
//
// 原理:对「已连接」的 UDP socket(net.Dial("udp"))写入探针后读取:
//   * 读到应用层应答      → 端口开放(高置信)
//   * 读到 ECONNREFUSED   → 端口关闭(操作系统把目标回的 ICMP port-unreachable 投递为该错误)
//   * 读超时(无任何响应) → open|filtered(无法确证),按被过滤计,绝不误报为开放
//
// 因此无需原始套接字 / 管理员:OS 替我们处理了 ICMP。仅对带已知探针的端口
// (DNS/NTP/SNMP/SSDP)能确证「开放」;其余端口仍可确证「关闭」。

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// udpProbe 对单个 host:port 做 UDP 探测;开放则记录,关闭/过滤计数。
func (m *Module) udpProbe(ctx context.Context, host string, port int, timeout time.Duration, opt scanOptions) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	payload := udpPayload(port)
	var resp []byte
	refused := false

	for attempt := 0; attempt <= opt.Retries; attempt++ {
		if ctx.Err() != nil {
			return
		}
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			return // 无法建立 socket(极少见)
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write(payload)
		buf := make([]byte, 2048)
		n, rerr := conn.Read(buf)
		_ = conn.Close()
		if n > 0 {
			resp = buf[:n]
			break
		}
		if hostUpFromDialErr(rerr) { // ICMP port-unreachable → 关闭
			refused = true
			break
		}
		// 超时 → 重试(若还有次数)
	}

	if resp != nil {
		banner := ""
		if opt.Banner {
			banner = clip(sanitize(string(resp)), 140)
		}
		if banner == "" {
			banner = fmt.Sprintf("应答 %d 字节", len(resp))
		}
		m.store.addPort(Port{Host: host, Port: port, Proto: "udp", Service: udpServiceName(port), Banner: banner})
		return
	}
	if ctx.Err() == nil {
		if refused {
			m.store.incClosed()
		} else {
			m.store.incFiltered() // open|filtered:无响应,不确证开放
		}
	}
}

// udpServiceName 返回 UDP 端口的服务名(在 TCP 映射基础上补 UDP 专属服务)。
func udpServiceName(port int) string {
	switch port {
	case 19:
		return "chargen"
	case 69:
		return "tftp"
	case 111:
		return "rpcbind"
	case 137:
		return "netbios-ns"
	case 138:
		return "netbios-dgm"
	case 500:
		return "isakmp"
	case 514:
		return "syslog"
	case 1194:
		return "openvpn"
	case 1900:
		return "ssdp"
	case 4500:
		return "ipsec-nat"
	case 5060:
		return "sip"
	case 5353:
		return "mdns"
	case 5355:
		return "llmnr"
	case 47808:
		return "bacnet"
	case 51820:
		return "wireguard"
	}
	return serviceName(port)
}

// udpPayload 返回端口对应的探针;无专属探针时回退到单字节(仍可确证「关闭」)。
func udpPayload(port int) []byte {
	switch port {
	case 53:
		return dnsProbe
	case 69:
		return tftpProbe
	case 111:
		return rpcProbe
	case 123:
		return ntpProbe
	case 137:
		return netbiosProbe
	case 161:
		return snmpProbe
	case 500:
		return isakmpProbe
	case 1194:
		return openVPNProbe
	case 1900:
		return ssdpProbe
	case 5060:
		return sipProbe
	case 5353:
		return mdnsProbe
	case 47808:
		return bacnetProbe
	}
	return []byte{0x00}
}

// DNS 标准查询 A google.com(任意 DNS 服务都会应答 → 判定开放)。
var dnsProbe = []byte{
	0x13, 0x37, // ID
	0x01, 0x00, // flags: 标准查询, RD=1
	0x00, 0x01, // QDCOUNT=1
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR=0
	0x06, 'g', 'o', 'o', 'g', 'l', 'e',
	0x03, 'c', 'o', 'm', 0x00,
	0x00, 0x01, // QTYPE=A
	0x00, 0x01, // QCLASS=IN
}

// NTP v3 client 请求(48 字节,首字节 LI=0/VN=3/Mode=3)。
var ntpProbe = func() []byte {
	b := make([]byte, 48)
	b[0] = 0x1b
	return b
}()

// SNMPv1 GetRequest,community "public",OID sysDescr.0 (1.3.6.1.2.1.1.1.0)。
var snmpProbe = []byte{
	0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
	0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

// SSDP M-SEARCH(UPnP 设备发现)。
var ssdpProbe = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST:239.255.255.250:1900\r\n" +
	"MAN:\"ssdp:discover\"\r\n" +
	"MX:1\r\n" +
	"ST:ssdp:all\r\n\r\n")

// TFTP 读请求（RFC 1350 RRQ）：读取 /etc/passwd，仅用于探测服务存在；多数服务器会回 Error。
var tftpProbe = []byte{
	0x00, 0x01, // opcode: RRQ
	'/', 'e', 't', 'c', '/', 'p', 'a', 's', 's', 'w', 'd', 0x00,
	'o', 'c', 't', 'e', 't', 0x00,
}

// NetBIOS Name Service 节点状态查询（RFC 1002），询问 *<00>。
var netbiosProbe = []byte{
	0xde, 0xad, // transaction ID
	0x00, 0x00, // flags: query
	0x00, 0x01, // question count = 1
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20,                                           // label length = 32
	// encoded "*" (NBNS wildcard) = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x00,                   // end of name
	0x00, 0x21,             // QTYPE = NBSTAT (33)
	0x00, 0x01,             // QCLASS = IN
}

// RPC portmapper GETPORT call（RFC 1057）：查询 TCP portmapper 自身端口（程序 100000）。
var rpcProbe = []byte{
	0x72, 0xfe, 0x1d, 0x13, // XID
	0x00, 0x00, 0x00, 0x00, // direction: call
	0x00, 0x00, 0x00, 0x02, // RPC version = 2
	0x00, 0x01, 0x86, 0xa0, // program = 100000 (portmap)
	0x00, 0x00, 0x00, 0x02, // program version = 2
	0x00, 0x00, 0x00, 0x03, // procedure = 3 (GETPORT)
	0x00, 0x00, 0x00, 0x00, // auth_flavor = NONE
	0x00, 0x00, 0x00, 0x00, // auth_len = 0
	0x00, 0x00, 0x00, 0x00, // verf_flavor = NONE
	0x00, 0x00, 0x00, 0x00, // verf_len = 0
	// args: prog=100000, vers=2, proto=17(UDP), port=0
	0x00, 0x01, 0x86, 0xa0,
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x11,
	0x00, 0x00, 0x00, 0x00,
}

// SIP OPTIONS 请求（RFC 3261），探测 SIP 服务存在性。
var sipProbe = []byte("OPTIONS sip:localhost SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKAEGIS\r\n" +
	"From: <sip:aegis@127.0.0.1>;tag=aegis\r\n" +
	"To: <sip:localhost>\r\n" +
	"Call-ID: aegis-probe@127.0.0.1\r\n" +
	"CSeq: 1 OPTIONS\r\n" +
	"Content-Length: 0\r\n\r\n")

// mDNS 查询（RFC 6762），问询 _services._dns-sd._udp.local。
var mdnsProbe = []byte{
	0x00, 0x00, // transaction ID = 0 (mDNS)
	0x00, 0x00, // flags: standard query
	0x00, 0x01, // QDCOUNT = 1
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// _services._dns-sd._udp.local
	0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	0x07, '_', 'd', 'n', 's', '-', 's', 'd',
	0x04, '_', 'u', 'd', 'p',
	0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
	0x00, 0x0c, // QTYPE = PTR
	0x00, 0x01, // QCLASS = IN
}

// ISAKMP IKEv1 Main Mode SA 提案，探测 VPN 网关。
var isakmpProbe = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // initiator SPI
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder SPI
	0x01,       // next payload = SA
	0x10,       // version = 1.0
	0x02,       // exchange type = Identity Protection (Main Mode)
	0x00,       // flags
	0x00, 0x00, 0x00, 0x00, // message ID
	0x00, 0x00, 0x00, 0x14, // length = 20
}

// OpenVPN 硬重置客户端 v2，探测 OpenVPN 服务存在性。
var openVPNProbe = []byte{
	0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
}

// BACnet Who-Is 广播（ASHRAE 135），探测楼控/工控设备。
var bacnetProbe = []byte{
	0x81, 0x0b, // BVLC type + function (Original-Unicast-NPDU)
	0x00, 0x0c, // BVLC length = 12
	0x01, 0x20, 0xff, 0xff, 0x00, 0xff, // NPDU
	0x10, 0x08, // APDU: Unconfirmed-Service-Request, Who-Is
}
