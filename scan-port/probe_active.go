package portscan

// probe_active.go —— 主动服务探针（类 nmap NSE service detection）。
//
// 对于不主动发送问候 banner 的服务（Redis/Memcached/PostgreSQL/MongoDB 等），
// readGreeting 会空手而归；本文件按端口发送协议特定探测载荷，解析回包识别服务版本。
//
// 所有探针仅做「服务识别」，不利用漏洞，不修改数据。

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// activeProbe 对给定连接执行主动探测，返回可读 banner；无法识别时返回空串。
// 由 banner.go 的 grabBanner() 按端口路由调用。
func activeProbe(conn net.Conn, port int, timeout time.Duration) string {
	switch port {
	case 6379, 6380, 6381, 16379:
		return probeRedis(conn, timeout)
	case 11211:
		return probeMemcached(conn, timeout)
	case 5432, 5433:
		return probePostgres(conn, timeout)
	case 27017, 27018, 27019:
		return probeMongoDB(conn, timeout)
	case 3389:
		return probeRDP(conn, timeout)
	case 5900, 5901, 5902:
		return probeVNC(conn, timeout)
	case 9092, 9093:
		return probeKafka(conn, timeout)
	case 2181, 2182:
		return probeZookeeper(conn, timeout)
	case 1433:
		return probeMSSQL(conn, timeout)
	case 1521, 1522:
		return probeOracle(conn, timeout)
	case 3306, 3307, 13306:
		return probeMySQL(conn, timeout)
	}
	return ""
}

// probeRedis 发送 PING，期望 +PONG 或 -NOAUTH。
func probeRedis(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "*1\r\n$4\r\nPING\r\n"); err != nil {
		return ""
	}
	resp := readN(conn, 128)
	switch {
	case strings.HasPrefix(resp, "+PONG"):
		return "redis (无认证)"
	case strings.HasPrefix(resp, "-NOAUTH"), strings.Contains(resp, "operation not permitted"):
		return "redis (需认证)"
	case strings.HasPrefix(resp, "-"):
		return "redis (" + clip(firstLine(resp[1:]), 60) + ")"
	}
	return ""
}

// probeMemcached 发送 version 命令。
func probeMemcached(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "version\r\n"); err != nil {
		return ""
	}
	resp := readN(conn, 128)
	if strings.HasPrefix(resp, "VERSION ") {
		ver := strings.TrimSpace(strings.TrimPrefix(resp, "VERSION "))
		return "memcached " + clip(firstLine(ver), 30)
	}
	return ""
}

// probePostgres 发送 PostgreSQL StartupMessage（协议 3.0），根据响应首字节判断。
func probePostgres(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	params := "user\x00postgres\x00\x00"
	msgLen := uint32(8 + len(params))
	msg := make([]byte, msgLen)
	binary.BigEndian.PutUint32(msg[0:4], msgLen)
	binary.BigEndian.PutUint32(msg[4:8], 0x00030000) // 协议 3.0
	copy(msg[8:], params)
	if _, err := conn.Write(msg); err != nil {
		return ""
	}
	resp := readN(conn, 256)
	if len(resp) == 0 {
		return ""
	}
	switch resp[0] {
	case 'R':
		return "postgresql (需认证)"
	case 'K', 'Z':
		return "postgresql (已连接)"
	case 'E':
		return "postgresql (" + extractPGError(resp) + ")"
	case 'N':
		return "postgresql"
	}
	return ""
}

func extractPGError(data string) string {
	if len(data) < 5 {
		return "error"
	}
	i := 5
	for i < len(data) {
		ft := data[i]
		i++
		j := strings.IndexByte(data[i:], 0)
		if j < 0 {
			break
		}
		val := data[i : i+j]
		i += j + 1
		if ft == 'M' {
			return clip(val, 60)
		}
	}
	return "error"
}

// probeMongoDB 发送 OP_QUERY isMaster，检测 MongoDB。
func probeMongoDB(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	bsonDoc := []byte{
		0x13, 0x00, 0x00, 0x00,
		0x10,
		'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00,
	}
	coll := []byte("admin.$cmd\x00")
	msgLen := 16 + 4 + len(coll) + 4 + 4 + len(bsonDoc)
	msg := make([]byte, 0, msgLen)
	putLE32 := func(v uint32) { msg = append(msg, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	putLE32(uint32(msgLen))
	putLE32(1)
	putLE32(0)
	putLE32(2004) // OP_QUERY
	putLE32(0)    // flags
	msg = append(msg, coll...)
	putLE32(0) // numberToSkip
	putLE32(1) // numberToReturn
	msg = append(msg, bsonDoc...)
	if _, err := conn.Write(msg); err != nil {
		return ""
	}
	resp := readN(conn, 512)
	if len(resp) < 16 {
		return ""
	}
	opCode := binary.LittleEndian.Uint32([]byte(resp[12:16]))
	if opCode == 1 { // OP_REPLY
		return "mongodb"
	}
	return ""
}

// probeRDP 发送 TPKT + COTP 连接请求，检测 RDP 服务及协议版本。
func probeRDP(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	rdpNeg := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version=3, length=19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // COTP Connection Request
		0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ, flags=0, length=8
		0x03, 0x00, 0x00, 0x00, // requestedProtocols: TLS|NLA
	}
	if _, err := conn.Write(rdpNeg); err != nil {
		return ""
	}
	resp := readN(conn, 32)
	if len(resp) >= 4 && resp[0] == 0x03 && resp[1] == 0x00 {
		if len(resp) >= 19 && resp[11] == 0x02 { // RDP_NEG_RSP
			proto := binary.LittleEndian.Uint32([]byte(resp[15:19]))
			switch proto {
			case 1:
				return "rdp (TLS)"
			case 3:
				return "rdp (TLS+NLA)"
			case 11:
				return "rdp (TLS+NLA+早期用户)"
			default:
				return "rdp (proto=" + strconv.Itoa(int(proto)) + ")"
			}
		}
		return "rdp"
	}
	return ""
}

// probeVNC 读取 RFB 协议版本字符串（服务器主动发送，12 字节）。
func probeVNC(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	resp := readN(conn, 16)
	if strings.HasPrefix(resp, "RFB ") {
		return "vnc (RFB " + clip(strings.TrimSpace(resp[4:12]), 10) + ")"
	}
	return ""
}

// probeKafka 发送 ApiVersions 请求（Kafka 0.10+），检测 Kafka broker。
func probeKafka(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// ApiVersions v0: msgLen(4)+apiKey(2=18)+apiVer(2=0)+corrId(4)+clientIdLen(2=-1)
	msg := []byte{
		0x00, 0x00, 0x00, 0x0a,
		0x00, 0x12,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0xff, 0xff,
	}
	if _, err := conn.Write(msg); err != nil {
		return ""
	}
	resp := readN(conn, 64)
	if len(resp) >= 8 {
		corrID := binary.BigEndian.Uint32([]byte(resp[4:8]))
		if corrID == 1 {
			return "kafka"
		}
	}
	return ""
}

// probeZookeeper 发送四字母命令 stat，检测 ZooKeeper。
func probeZookeeper(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "stat"); err != nil {
		return ""
	}
	resp := readN(conn, 256)
	low := strings.ToLower(resp)
	if strings.Contains(low, "zookeeper") || strings.Contains(low, "mode:") {
		for _, line := range strings.Split(resp, "\n") {
			if strings.Contains(strings.ToLower(line), "version") {
				return "zookeeper " + clip(strings.TrimSpace(line), 60)
			}
		}
		return "zookeeper"
	}
	return ""
}

// probeMSSQL 发送 TDS Pre-Login 报文，检测 Microsoft SQL Server。
func probeMSSQL(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tds := []byte{
		0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, // TDS header
		0x00, 0x00, 0x15, 0x06, // VERSION option
		0x01, 0x00, 0x1b, 0x01, // ENCRYPTION option
		0xff,                                             // TERMINATOR
		0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,              // VERSION data: 14.0.0.0
		0x02,                                             // ENCRYPTION: NOT_SUPPORTED
	}
	if _, err := conn.Write(tds); err != nil {
		return ""
	}
	resp := readN(conn, 64)
	if len(resp) > 8 && resp[0] == 0x12 {
		// Pre-Login Response: try to extract version
		if len(resp) >= 27 {
			major := resp[21]
			minor := resp[22]
			return "mssql " + strconv.Itoa(int(major)) + "." + strconv.Itoa(int(minor))
		}
		return "mssql"
	}
	return ""
}

// probeMySQL 解析 MySQL/MariaDB 服务端握手包（协议 v10），提取版本字符串。
// MySQL 在连接建立后立即发送握手包，无需客户端先发送数据。
func probeMySQL(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// Packet header: 3-byte payload length (LE) + 1-byte sequence number.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return ""
	}
	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if payloadLen < 5 || payloadLen > 2048 {
		return ""
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return ""
	}
	// Protocol version byte must be 0x0a (10) for modern MySQL/MariaDB.
	if payload[0] != 0x0a {
		return ""
	}
	// Null-terminated version string starts at offset 1.
	nullIdx := bytes.IndexByte(payload[1:], 0)
	if nullIdx < 0 {
		return ""
	}
	version := string(payload[1 : 1+nullIdx])
	if strings.Contains(version, "MariaDB") || strings.Contains(strings.ToLower(version), "mariadb") {
		return "mariadb " + version
	}
	return "mysql " + version
}

// probeOracle 发送简化 TNS Connect 报文，检测 Oracle 监听器。
func probeOracle(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// Minimal TNS Connect packet
	tns := []byte{
		0x00, 0x3a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // header
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x14, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// connect data (truncated)
		0x28, 0x44, 0x45, 0x53, 0x43, 0x52, 0x49, 0x50,
		0x54, 0x49, 0x4f, 0x4e, 0x3d, 0x28,
	}
	if _, err := conn.Write(tns); err != nil {
		return ""
	}
	resp := readN(conn, 64)
	if len(resp) > 4 {
		pktType := resp[4]
		switch pktType {
		case 0x02: // ACCEPT
			return "oracle (接受连接)"
		case 0x04: // REFUSE
			return "oracle (监听器已拒绝)"
		case 0x05: // REDIRECT
			return "oracle (重定向)"
		}
	}
	return ""
}
