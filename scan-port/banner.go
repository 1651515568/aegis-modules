package portscan

// banner.go —— banner / 服务指纹抓取。
//
// 三种策略,按端口选择:
//   * TLS 端口(443/8443/993…):做 TLS 握手,取证书 CN + 协议版本;对 HTTPS 应用端口
//     再在 TLS 之上发一个 HTTP 请求拿 Server 头与 <title>。
//   * 明文 HTTP 端口(80/8080…):发 GET / 拿状态行 + Server 头 + <title>。
//   * 其它端口:被动读取服务问候 banner(SSH/FTP/SMTP/MySQL/Redis 等会主动吐 banner)。
//
// 仅读取响应用于识别,不做任何利用动作。

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"
)

// grabBanner 抓取一条单行可读 banner;失败返回空串。
//
// 优先级：
//   1. TLS 端口 → TLS 握手 + 证书 CN + 可选 HTTP
//   2. HTTP 端口 → GET / + 状态行/Server/title
//   3. 主动探针端口 → 协议特定载荷（Redis/Memcached/Postgres/MongoDB 等）
//   4. 其他 → 被动读取服务问候行（SSH/FTP/SMTP/MySQL 等主动吐 banner）
func grabBanner(conn net.Conn, host string, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	switch {
	case isTLSPort(port):
		return tlsBanner(conn, host, port, timeout)
	case isHTTPPort(port):
		return httpBanner(conn, host)
	default:
		// 先尝试主动探针（对不主动吐 banner 的服务）
		if b := activeProbe(conn, port, timeout); b != "" {
			return b
		}
		return readGreeting(conn)
	}
}

// tlsBanner 在原始连接上做 TLS 握手,提取证书 CN 与协议版本;HTTPS 应用端口再取 HTTP 信息。
func tlsBanner(raw net.Conn, host string, port int, timeout time.Duration) string {
	sni := host
	if net.ParseIP(host) != nil {
		sni = "" // IP 目标不发 SNI
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: sni}) // 仅指纹识别,不校验证书
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		return ""
	}
	var parts []string
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		cn := cert.Subject.CommonName
		if cn == "" && len(cert.DNSNames) > 0 {
			cn = cert.DNSNames[0]
		}
		if cn != "" {
			parts = append(parts, "CN="+cn)
		}
	}
	parts = append(parts, tlsVersionName(cs.Version))
	if isHTTPSAppPort(port) {
		if b := httpBanner(tc, host); b != "" {
			parts = append(parts, b)
		}
	}
	return clip(strings.Join(parts, " · "), 180)
}

// httpBanner 发 GET / 并从响应提取状态行 / Server 头 / <title>。conn 可为明文或 TLS 连接。
func httpBanner(conn net.Conn, host string) string {
	if host == "" {
		host = "scan"
	}
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: AEGIS-Portscan\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return ""
	}
	return summarizeHTTP(readN(conn, 16*1024))
}

func summarizeHTTP(s string) string {
	if s == "" {
		return ""
	}
	var parts []string
	if i := strings.IndexAny(s, "\r\n"); i > 0 {
		if line := sanitize(s[:i]); strings.HasPrefix(line, "HTTP/") {
			parts = append(parts, line)
		}
	}
	if v := headerVal(s, "Server"); v != "" {
		parts = append(parts, "Server: "+v)
	}
	if t := htmlTitle(s); t != "" {
		parts = append(parts, "title: "+t)
	}
	if len(parts) == 0 {
		return firstLine(s)
	}
	return clip(strings.Join(parts, " · "), 180)
}

// readGreeting 被动读取服务主动下发的问候 banner(取首行)。
func readGreeting(conn net.Conn) string {
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return firstLine(string(buf[:n]))
}

// guessFromBanner 从 banner 粗略推断服务名(端口映射缺失时兜底)。
// 同时尝试 OS 指纹推断并回填 OsGuess。
func guessFromBanner(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(b, "ssh-"):
		return "ssh"
	case strings.Contains(b, "cn="): // TLS 握手成功(证书 CN)→ https
		return "https"
	case strings.Contains(b, "http/"), strings.Contains(b, "server:"), strings.Contains(b, "title:"):
		return "http"
	case strings.HasPrefix(b, "220") && strings.Contains(b, "ftp"):
		return "ftp"
	case strings.HasPrefix(b, "220") && (strings.Contains(b, "smtp") || strings.Contains(b, "esmtp")):
		return "smtp"
	case strings.Contains(b, "mysql") || strings.Contains(b, "mariadb"):
		return "mysql"
	case strings.Contains(b, "-redis") || strings.HasPrefix(b, "+pong") || strings.HasPrefix(b, "-noauth"):
		return "redis"
	case strings.HasPrefix(b, "redis"):
		return "redis"
	case strings.HasPrefix(b, "memcached"):
		return "memcached"
	case strings.HasPrefix(b, "postgresql"):
		return "postgresql"
	case strings.HasPrefix(b, "mongodb"):
		return "mongodb"
	case strings.HasPrefix(b, "rdp"):
		return "rdp"
	case strings.HasPrefix(b, "vnc"):
		return "vnc"
	case strings.HasPrefix(b, "kafka"):
		return "kafka"
	case strings.HasPrefix(b, "zookeeper"):
		return "zookeeper"
	case strings.HasPrefix(b, "mssql"):
		return "mssql"
	case strings.HasPrefix(b, "oracle"):
		return "oracle"
	}
	return ""
}

// ───────────── 纯函数工具 ─────────────

// readN 从 r 读取至多 n 字节(直到 EOF 或截止时间)。
func readN(r io.Reader, n int) string {
	buf := make([]byte, n)
	total := 0
	for total < n {
		m, err := r.Read(buf[total:])
		total += m
		if err != nil {
			break
		}
	}
	return string(buf[:total])
}

// headerVal 在 HTTP 响应头部分大小写不敏感地取某个头的值。
func headerVal(resp, name string) string {
	head := resp
	if i := strings.Index(resp, "\r\n\r\n"); i >= 0 {
		head = resp[:i]
	}
	target := strings.ToLower(name) + ":"
	for _, line := range strings.Split(head, "\n") {
		l := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(l), target) {
			return sanitize(strings.TrimSpace(l[len(target):]))
		}
	}
	return ""
}

// htmlTitle 提取 HTML <title> 文本(单行、折叠空白)。
func htmlTitle(s string) string {
	low := strings.ToLower(s)
	i := strings.Index(low, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.Index(low[i:], ">")
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(low[start:], "</title>")
	if end < 0 {
		return ""
	}
	return clip(sanitize(collapseWS(s[start:start+end])), 80)
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if v := sanitize(strings.TrimSpace(line)); v != "" {
			return clip(v, 160)
		}
	}
	return ""
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// sanitize 丢弃控制字符与无效 UTF-8,保留可打印 ASCII 与 Unicode(如中文标题)。
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '�' || r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func clip(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n]) + "…"
	}
	return s
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	}
	return "TLS"
}

// isHTTPPort 是常见的明文 HTTP 端口。
func isHTTPPort(port int) bool {
	switch port {
	case
		// 标准/通用
		80, 81, 88, 591, 2080, 2480,
		// 代理
		3128, 3333, 8118,
		// 框架/微服务
		3000, 3001, 4567, 5000, 5104,
		// 中间件 (Weblogic/JBoss/Tomcat/Spring)
		7001, 7002, 7070, 8080, 8008, 8081, 8082, 8088, 8090, 8091,
		// 通用高位
		8000, 8001, 8888, 9000, 9001, 9080, 9090, 9999, 10000,
		// Elasticsearch/Kibana
		9200, 9300, 5601,
		// Consul/Nacos/etcd
		8500, 8848, 2379, 2380,
		// Docker API (明文)
		2375,
		// Prometheus/Grafana
		9091, 3002,
		// GitLab/Gitea
		8929,
		// Zabbix/Icinga
		10051:
		return true
	}
	return false
}

// isTLSPort 是常见的 TLS 包裹端口(需先做 TLS 握手)。
func isTLSPort(port int) bool {
	switch port {
	case
		// 标准 TLS 服务
		443, 465, 636, 989, 990, 993, 995,
		// 应用 TLS
		8443, 9443, 9444, 5800,
		// Kubernetes API / etcd TLS
		6443, 2376,
		// Elasticsearch TLS / OpenSearch
		9243:
		return true
	}
	return false
}

// isHTTPSAppPort 是「HTTP over TLS」端口(TLS 之上还能拿 HTTP 信息)。
func isHTTPSAppPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 9444, 6443:
		return true
	}
	return false
}
