package sslaudit

// scanner.go —— SSL/TLS 检测核心逻辑。
//
// 对每个目标依次执行：
//   1. TLS 连接（先带主机名验证，失败再跳过验证取证书）
//   2. 证书解析：有效期、自签名、主机名匹配、密钥强度、签名算法
//   3. 协议版本探测：向服务器强制 TLS 1.0 / TLS 1.1 握手
//   4. 协商密码套件检测：对照弱套件表
//   5. HSTS 响应头检测
//
// 注意：使用 InsecureSkipVerify=true 属有意设计——红队工具须能获取自签名/过期证书
// 的详细信息；生产用途下应关闭 TLS 验证绕过。

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── 常量 ──────────────────────────────────────────────────────────────────────

const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"

	CatCert     = "证书"
	CatProtocol = "协议"
	CatCipher   = "密码套件"
	CatHeader   = "HTTP 头"
)

// ── 弱密码套件表 ──────────────────────────────────────────────────────────────

type cipherInfo struct {
	Severity string
	Reason   string
}

// 仅检查已协商的套件；不主动枚举（避免大量握手带来的探测噪声）。
var weakCiphers = map[uint16]cipherInfo{
	tls.TLS_RSA_WITH_RC4_128_SHA:          {SevCritical, "RC4 流密码存在统计偏差，已证明不安全"},
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   {SevCritical, "ECDHE-RC4 组合，RC4 不安全"},
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: {SevCritical, "ECDHE-ECDSA-RC4 组合，RC4 不安全"},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    {SevHigh, "3DES 存在 SWEET32 生日攻击（CVE-2016-2183），64 位块密码"},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:     {SevLow, "RSA 密钥交换无前向保密（PFS），历史会话可被事后破解"},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:     {SevLow, "RSA 密钥交换无前向保密（PFS）"},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:  {SevLow, "RSA 密钥交换无前向保密（PFS）"},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:  {SevLow, "RSA 密钥交换无前向保密（PFS）"},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:  {SevLow, "RSA 密钥交换无前向保密（PFS）"},
}

// ── 数据结构 ──────────────────────────────────────────────────────────────────

// ScanTarget 解析后的目标。
type ScanTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// CertDetail 一台主机的证书摘要。
type CertDetail struct {
	ID         string    `json:"id"`
	TaskID     string    `json:"taskId"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	DaysLeft   int       `json:"daysLeft"`
	KeyType    string    `json:"keyType"`
	KeyBits    int       `json:"keyBits"`
	SigAlgo    string    `json:"sigAlgo"`
	SANs       []string  `json:"sans"`
	TLSVersion string    `json:"tlsVersion"`
	Cipher     string    `json:"cipher"`
	HSTS       string    `json:"hsts"`
	SelfSigned bool      `json:"selfSigned"`
	ScanErr    string    `json:"scanErr,omitempty"`
	FoundAt    time.Time `json:"foundAt"`
}

// Finding 一条具体的安全发现。
type Finding struct {
	ID       string    `json:"id"`
	TaskID   string    `json:"taskId"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Severity string    `json:"severity"`
	Category string    `json:"category"`
	Label    string    `json:"label"`
	Detail   string    `json:"detail"`
	Evidence string    `json:"evidence"`
	FoundAt  time.Time `json:"foundAt"`
}

// HostResult 一台主机的全部检测结果。
type HostResult struct {
	Target   ScanTarget  `json:"target"`
	Cert     *CertDetail `json:"cert"`
	Findings []*Finding  `json:"findings"`
	ScanErr  string      `json:"scanErr,omitempty"`
}

// scanState 当前运行中扫描的内存态（供 /status 和 /results 使用）。
type scanState struct {
	mu      sync.RWMutex
	total   int
	probed  int
	found   int
	done    bool
	err     string
	results []*HostResult
	startAt time.Time
	endAt   time.Time
}

func (s *scanState) addResult(r *HostResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probed++
	s.found += len(r.Findings)
	s.results = append(s.results, r)
}

func (s *scanState) snapshot() (total, probed, found int, done bool, errStr string, startAt, endAt time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total, s.probed, s.found, s.done, s.err, s.startAt, s.endAt
}

func (s *scanState) allResults() []*HostResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*HostResult, len(s.results))
	copy(out, s.results)
	return out
}

// ── 目标解析 ──────────────────────────────────────────────────────────────────

func parseTarget(raw string) (ScanTarget, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if idx := strings.IndexByte(raw, '/'); idx >= 0 {
		raw = raw[:idx]
	}
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ScanTarget{}, false
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return ScanTarget{Host: raw, Port: 443}, true
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 || port > 65535 {
		port = 443
	}
	return ScanTarget{Host: host, Port: port}, true
}

func dedupTargets(targets []ScanTarget) []ScanTarget {
	seen := make(map[string]bool)
	var out []ScanTarget
	for _, t := range targets {
		key := fmt.Sprintf("%s:%d", t.Host, t.Port)
		if !seen[key] {
			seen[key] = true
			out = append(out, t)
		}
	}
	return out
}

// ── TLS 连接辅助 ──────────────────────────────────────────────────────────────

func dialTLS(ctx context.Context, host string, port int, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err = tc.Handshake(); err != nil {
		tc.Close() // Close tls.Conn (not raw) to release TLS buffers and send close_notify
		return nil, err
	}
	return tc, nil
}

// ── 核心扫描 ──────────────────────────────────────────────────────────────────

func scanHost(ctx context.Context, target ScanTarget, timeout time.Duration) *HostResult {
	now := time.Now()
	res := &HostResult{Target: target, Findings: []*Finding{}}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	// 限制单台主机总扫描时间，防止 5 次子操作各耗满 timeout 导致实际耗时 5× 配置值。
	hostCtx, hostCancel := context.WithTimeout(ctx, timeout)
	defer hostCancel()

	// 1) 正常 TLS 连接（带主机名验证）——判断是否有证书错误
	strictConn, strictErr := dialTLS(hostCtx, target.Host, target.Port, &tls.Config{
		ServerName: target.Host,
		MinVersion: tls.VersionTLS10,
	}, timeout)
	if strictConn != nil {
		strictConn.Close()
	}

	// 2) InsecureSkipVerify 连接，无论如何取到完整证书/协商状态
	insecureConn, insecureErr := dialTLS(hostCtx, target.Host, target.Port, &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true, //nolint:gosec — 红队工具有意跳过验证以获取问题证书详情
		MinVersion:         tls.VersionTLS10,
	}, timeout)
	if insecureErr != nil {
		res.ScanErr = fmt.Sprintf("连接失败: %v", insecureErr)
		return res
	}
	state := insecureConn.ConnectionState()
	insecureConn.Close()

	certs := state.PeerCertificates
	if len(certs) == 0 {
		res.ScanErr = "未收到服务器证书"
		return res
	}
	leaf := certs[0]
	kt, kb := keyInfo(leaf)

	cd := &CertDetail{
		ID:         randHex(8),
		Host:       target.Host,
		Port:       target.Port,
		Subject:    leaf.Subject.CommonName,
		Issuer:     leaf.Issuer.CommonName,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		DaysLeft:   int(time.Until(leaf.NotAfter).Hours() / 24),
		KeyType:    kt,
		KeyBits:    kb,
		SigAlgo:    leaf.SignatureAlgorithm.String(),
		SANs:       buildSANs(leaf),
		TLSVersion: tlsVerName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		SelfSigned: isSelfSigned(leaf),
		FoundAt:    now,
	}
	res.Cert = cd

	// 3) 证书验证失败
	if strictErr != nil {
		res.Findings = append(res.Findings, newFinding(target, SevCritical, CatCert,
			"证书验证失败",
			fmt.Sprintf("标准 TLS 握手失败，浏览器/客户端将弹出安全警告或拒绝连接。原因：%v", strictErr),
			strictErr.Error(), now))
	}

	// 4) 证书过期 / 即将过期
	if now.After(leaf.NotAfter) {
		res.Findings = append(res.Findings, newFinding(target, SevCritical, CatCert,
			"证书已过期",
			fmt.Sprintf("证书于 %s 过期，已超期 %d 天", leaf.NotAfter.Format("2006-01-02"), -cd.DaysLeft),
			fmt.Sprintf("NotAfter: %s", leaf.NotAfter.Format(time.RFC3339)), now))
	} else if cd.DaysLeft <= 7 {
		res.Findings = append(res.Findings, newFinding(target, SevCritical, CatCert,
			"证书 7 天内过期",
			fmt.Sprintf("证书将于 %s 过期，剩余 %d 天，需立即续期", leaf.NotAfter.Format("2006-01-02"), cd.DaysLeft),
			fmt.Sprintf("NotAfter: %s", leaf.NotAfter.Format(time.RFC3339)), now))
	} else if cd.DaysLeft <= 30 {
		res.Findings = append(res.Findings, newFinding(target, SevHigh, CatCert,
			"证书 30 天内过期",
			fmt.Sprintf("证书将于 %s 过期，剩余 %d 天", leaf.NotAfter.Format("2006-01-02"), cd.DaysLeft),
			fmt.Sprintf("NotAfter: %s", leaf.NotAfter.Format(time.RFC3339)), now))
	} else if cd.DaysLeft <= 90 {
		res.Findings = append(res.Findings, newFinding(target, SevMedium, CatCert,
			"证书 90 天内过期",
			fmt.Sprintf("证书将于 %s 过期，剩余 %d 天", leaf.NotAfter.Format("2006-01-02"), cd.DaysLeft),
			fmt.Sprintf("NotAfter: %s", leaf.NotAfter.Format(time.RFC3339)), now))
	}

	// 5) 自签名
	if cd.SelfSigned {
		res.Findings = append(res.Findings, newFinding(target, SevHigh, CatCert,
			"自签名证书",
			"证书由自身签发，无权威 CA 背书。浏览器将弹出安全警告，可能导致用户拒绝访问或遭受中间人攻击。",
			fmt.Sprintf("Subject=%s  Issuer=%s", leaf.Subject.CommonName, leaf.Issuer.CommonName), now))
	}

	// 6) 主机名不匹配（已通过验证就不会触发此处，仅 strictErr 为 nil 时额外检查边界情况）
	if strictErr == nil {
		if verr := leaf.VerifyHostname(target.Host); verr != nil {
			res.Findings = append(res.Findings, newFinding(target, SevCritical, CatCert,
				"主机名与证书不匹配",
				fmt.Sprintf("证书 CN/SAN 与请求主机名 %q 不符，攻击者可仿冒此服务。", target.Host),
				verr.Error(), now))
		}
	}

	// 7) 密钥强度
	switch cd.KeyType {
	case "RSA":
		if cd.KeyBits < 1024 {
			res.Findings = append(res.Findings, newFinding(target, SevCritical, CatCert,
				fmt.Sprintf("RSA 密钥极弱（%d 位）", cd.KeyBits),
				"低于 1024 位的 RSA 密钥可被暴力因式分解，应立即替换证书。",
				fmt.Sprintf("PublicKey: RSA %d bits", cd.KeyBits), now))
		} else if cd.KeyBits < 2048 {
			res.Findings = append(res.Findings, newFinding(target, SevHigh, CatCert,
				fmt.Sprintf("RSA 密钥不足 2048 位（%d 位）", cd.KeyBits),
				"NIST SP 800-131A 要求 RSA 密钥至少 2048 位，1024 位已被认定不安全。",
				fmt.Sprintf("PublicKey: RSA %d bits", cd.KeyBits), now))
		}
	case "ECDSA":
		if cd.KeyBits < 224 {
			res.Findings = append(res.Findings, newFinding(target, SevHigh, CatCert,
				fmt.Sprintf("EC 密钥不足 224 位（%d 位）", cd.KeyBits),
				"ECDSA 密钥推荐至少 P-256（256 位）。",
				fmt.Sprintf("PublicKey: ECDSA %d bits", cd.KeyBits), now))
		}
	}

	// 8) 签名算法
	algoLow := strings.ToLower(cd.SigAlgo)
	if strings.Contains(algoLow, "md5") || strings.Contains(algoLow, "md2") {
		res.Findings = append(res.Findings, newFinding(target, SevHigh, CatCert,
			"使用 MD5/MD2 签名算法",
			"MD5 已被碰撞攻击攻破（Flame 恶意软件即利用此伪造微软证书）。应迁移至 SHA-256 或更高。",
			fmt.Sprintf("SignatureAlgorithm: %s", cd.SigAlgo), now))
	} else if strings.Contains(algoLow, "sha1") {
		res.Findings = append(res.Findings, newFinding(target, SevMedium, CatCert,
			"使用 SHA-1 签名算法",
			"SHA-1 碰撞已被证实（SHAttered, 2017），主流 CA 已停发 SHA-1 证书，应迁移至 SHA-256+。",
			fmt.Sprintf("SignatureAlgorithm: %s", cd.SigAlgo), now))
	}

	// 9) 协议版本探测
	select {
	case <-ctx.Done():
		return res
	default:
	}

	halfTO := timeout / 2
	if halfTO < 3*time.Second {
		halfTO = 3 * time.Second
	}

	if c, err := dialTLS(hostCtx, target.Host, target.Port, &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	}, halfTO); err == nil {
		c.Close()
		res.Findings = append(res.Findings, newFinding(target, SevHigh, CatProtocol,
			"支持已弃用的 TLS 1.0",
			"TLS 1.0 存在 BEAST、POODLE 等已知攻击，RFC 8996（2021）正式弃用，PCI DSS 3.2+ 要求禁用。",
			"TLS 1.0 握手成功（MaxVersion=TLS1.0）", now))
	}

	select {
	case <-hostCtx.Done():
		return res
	default:
	}

	if c, err := dialTLS(hostCtx, target.Host, target.Port, &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
	}, halfTO); err == nil {
		c.Close()
		res.Findings = append(res.Findings, newFinding(target, SevMedium, CatProtocol,
			"支持已弃用的 TLS 1.1",
			"TLS 1.1 于 RFC 8996（2021）正式弃用，应仅保留 TLS 1.2 和 TLS 1.3。",
			"TLS 1.1 握手成功（MaxVersion=TLS1.1）", now))
	}

	// 10) 协商密码套件
	if wi, ok := weakCiphers[state.CipherSuite]; ok {
		res.Findings = append(res.Findings, newFinding(target, wi.Severity, CatCipher,
			fmt.Sprintf("协商到弱密码套件：%s", tls.CipherSuiteName(state.CipherSuite)),
			wi.Reason,
			fmt.Sprintf("CipherSuite: 0x%04X (%s)", state.CipherSuite, tls.CipherSuiteName(state.CipherSuite)), now))
	}

	// 11) HSTS 检测
	select {
	case <-hostCtx.Done():
		return res
	default:
	}
	checkHSTS(hostCtx, target, timeout, cd, res, now)

	return res
}

// checkHSTS 发一个 HTTPS GET 检查 Strict-Transport-Security 响应头。
func checkHSTS(ctx context.Context, target ScanTarget, timeout time.Duration, cd *CertDetail, res *HostResult, now time.Time) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec — 目标证书可能有问题，仍需检查 HSTS 头
			ServerName:         target.Host,
		},
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		tr.CloseIdleConnections()
		return
	}
	resp, err := client.Do(req)
	defer tr.CloseIdleConnections() // 释放 Transport 内部 goroutine 和 TCP 连接
	if err != nil {
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body) // 排空 body 确保 TCP 连接可复用
		resp.Body.Close()
	}()

	hsts := resp.Header.Get("Strict-Transport-Security")
	cd.HSTS = hsts

	if hsts == "" {
		res.Findings = append(res.Findings, newFinding(target, SevMedium, CatHeader,
			"缺少 HSTS 响应头",
			"未配置 Strict-Transport-Security，首次访问或 max-age 到期后可被 SSL Strip 降级到 HTTP。"+
				"建议：Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			fmt.Sprintf("GET %s → HTTP %d，缺少 Strict-Transport-Security 头", url, resp.StatusCode), now))
	} else {
		maxAge := parseHSTSMaxAge(hsts)
		const minAge = 15552000 // 180天
		if maxAge > 0 && maxAge < minAge {
			res.Findings = append(res.Findings, newFinding(target, SevLow, CatHeader,
				fmt.Sprintf("HSTS max-age 过短（%d 秒 / %d 天）", maxAge, maxAge/86400),
				fmt.Sprintf("max-age=%d 低于推荐最小值 180 天（15552000 秒）。Google Preload 列表要求至少 1 年。", maxAge),
				fmt.Sprintf("Strict-Transport-Security: %s", hsts), now))
		}
		if !strings.Contains(strings.ToLower(hsts), "includesubdomains") {
			res.Findings = append(res.Findings, newFinding(target, SevInfo, CatHeader,
				"HSTS 未包含 includeSubDomains",
				"子域名未受 HSTS 保护，可能被利用做 cookie 注入或中间人降级攻击。",
				fmt.Sprintf("Strict-Transport-Security: %s", hsts), now))
		}
	}
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

func newFinding(t ScanTarget, sev, cat, label, detail, evidence string, at time.Time) *Finding {
	return &Finding{
		ID:       randHex(8),
		Host:     t.Host,
		Port:     t.Port,
		Severity: sev,
		Category: cat,
		Label:    label,
		Detail:   detail,
		Evidence: evidence,
		FoundAt:  at,
	}
}

func tlsVerName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func isSelfSigned(c *x509.Certificate) bool {
	// 比较 DER 编码的 RawSubject / RawIssuer 字节，符合 X.509 规范，
	// 比 String() 字符串比较更精确且性能更好。
	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

func buildSANs(c *x509.Certificate) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range c.DNSNames {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, ip := range c.IPAddresses {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "Unknown", 0
}

func parseHSTSMaxAge(hsts string) int {
	for _, part := range strings.Split(hsts, ";") {
		p := strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(p, "max-age=") {
			n, _ := strconv.Atoi(strings.TrimPrefix(p, "max-age="))
			return n
		}
	}
	return 0
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
