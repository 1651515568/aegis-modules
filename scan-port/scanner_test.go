package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"redops/core"
)

type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

func fmtWrap(err error) error { return fmt.Errorf("dial tcp: %w", err) }

func TestHostUpFromDialErr(t *testing.T) {
	if !hostUpFromDialErr(nil) {
		t.Errorf("nil(连通)应判活")
	}
	if !hostUpFromDialErr(syscall.ECONNREFUSED) {
		t.Errorf("连接被拒绝应判活(主机可达)")
	}
	if !hostUpFromDialErr(fmtWrap(syscall.ECONNREFUSED)) {
		t.Errorf("包裹的连接被拒绝(%%w)应被 errors.Is 命中而判活")
	}
	if !hostUpFromDialErr(errors.New("dial tcp 1.2.3.4:80: connectex: No connection could be made because the target machine actively refused it.")) {
		t.Errorf("Windows 'actively refused' 文案应判活")
	}
	if !hostUpFromDialErr(errors.New("read tcp: An existing connection was forcibly closed by the remote host.")) {
		t.Errorf("Windows 'forcibly closed' 文案应判活")
	}
	if hostUpFromDialErr(fakeTimeoutErr{}) {
		t.Errorf("超时不应判活")
	}
	if hostUpFromDialErr(errors.New("no route to host")) {
		t.Errorf("不可达不应判活")
	}
}

func TestParsePorts(t *testing.T) {
	cases := []struct {
		spec string
		want []int
	}{
		{"22,80,443", []int{22, 80, 443}},
		{"443,80,22,80", []int{22, 80, 443}},              // 去重 + 升序
		{"8000-8003", []int{8000, 8001, 8002, 8003}},      // 区间
		{"443-440", []int{440, 441, 442, 443}},            // 反向区间自动纠正
		{"22, 80 , 8000-8001", []int{22, 80, 8000, 8001}}, // 空白容忍
		{"0,70000,-5,abc,443", []int{443}},                // 非法端口/非数字丢弃
		{"top100", top100Ports},
		{"top500", top500Ports},
	}
	for _, c := range cases {
		got := parsePorts(c.spec)
		want := c.want
		if c.spec == "top100" {
			// top100 解析应去重升序;长度等于去重后集合
			seen := map[int]bool{}
			for _, p := range top100Ports {
				seen[p] = true
			}
			if len(got) != len(top100Ports) {
				t.Errorf("parsePorts(top100) len=%d, top100Ports len=%d", len(got), len(top100Ports))
			}
			continue
		}
		if c.spec == "top500" {
			if len(got) != len(top500Ports) {
				t.Errorf("parsePorts(top500) len=%d, top500Ports len=%d", len(got), len(top500Ports))
			}
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parsePorts(%q) = %v, want %v", c.spec, got, want)
		}
	}
}

func TestParsePortsAll(t *testing.T) {
	got := parsePorts("all")
	if len(got) != 65535 || got[0] != 1 || got[65534] != 65535 {
		t.Errorf("parsePorts(all) 应为 1..65535, 得到 len=%d first=%d last=%d", len(got), got[0], got[len(got)-1])
	}
}

func TestTop1000Sorted(t *testing.T) {
	p := top1000Ports()
	for i := 1; i < len(p); i++ {
		if p[i] <= p[i-1] {
			t.Fatalf("top1000Ports 非严格升序: %d <= %d (idx %d)", p[i], p[i-1], i)
		}
	}
	if len(p) < 1000 {
		t.Errorf("top1000Ports 长度 %d, 期望 >= 1000", len(p))
	}
}

func TestParseTargets(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"203.0.113.5"}, []string{"203.0.113.5"}},
		{[]string{"https://example.com/some/path"}, []string{"example.com"}}, // 剥 scheme + path
		{[]string{"http://oa.test:8443/login"}, []string{"oa.test"}},         // 剥端口
		{[]string{"example.com:8080"}, []string{"example.com"}},              // host:port → host
		{[]string{"example.com/admin"}, []string{"example.com"}},             // 裸路径
		{[]string{" a.com , a.com ", "b.com"}, []string{"a.com", "b.com"}},   // 去重 + trim
		{[]string{"", "  "}, nil},                                            // 空白丢弃
		// IPv6
		{[]string{"::1"}, []string{"::1"}},
		{[]string{"2001:db8::1"}, []string{"2001:db8::1"}},
		{[]string{"[::1]:8080"}, []string{"::1"}},      // 带端口方括号 → 剥掉
		{[]string{"[2001:db8::1]"}, []string{"2001:db8::1"}}, // 裸方括号无端口 → 剥掉
	}
	for _, c := range cases {
		got := parseTargets(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseTargets(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	got := expandCIDR("192.168.10.0/30", 100)
	want := []string{"192.168.10.0", "192.168.10.1", "192.168.10.2", "192.168.10.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expandCIDR(/30) = %v, want %v", got, want)
	}
	// cap 生效
	capped := expandCIDR("10.0.0.0/16", 50)
	if len(capped) != 50 {
		t.Errorf("expandCIDR cap=50 得到 %d", len(capped))
	}
	// 非法 CIDR
	if expandCIDR("not-a-cidr", 10) != nil {
		t.Errorf("非法 CIDR 应返回 nil")
	}
	// IPv6 /128 单主机
	gotV6 := expandCIDR("::1/128", 10)
	if len(gotV6) != 1 || gotV6[0] != "::1" {
		t.Errorf("expandCIDR(::1/128) = %v, want [::1]", gotV6)
	}
	// IPv6 /127 两主机
	gotV6b := expandCIDR("2001:db8::/127", 10)
	if len(gotV6b) != 2 {
		t.Errorf("expandCIDR(2001:db8::/127) len=%d, want 2", len(gotV6b))
	}
}

func TestParseTargetsCIDR(t *testing.T) {
	got := parseTargets([]string{"192.168.0.0/30"})
	if len(got) != 4 || got[0] != "192.168.0.0" || got[3] != "192.168.0.3" {
		t.Errorf("parseTargets CIDR = %v", got)
	}
}

func TestServiceName(t *testing.T) {
	cases := map[int]string{22: "ssh", 80: "http", 443: "https", 3306: "mysql", 6379: "redis"}
	for port, want := range cases {
		if got := serviceName(port); got != want {
			t.Errorf("serviceName(%d) = %q, want %q", port, got, want)
		}
	}
	if serviceName(54321) != "unknown" {
		t.Errorf("未知端口应返回 unknown")
	}
}

func TestSummarizeHTTP(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\nContent-Type: text/html\r\n\r\n<html><head><title>  银行  门户 </title></head>"
	got := summarizeHTTP(resp)
	if !contains(got, "HTTP/1.1 200 OK") || !contains(got, "Server: nginx/1.20.1") || !contains(got, "title: 银行 门户") {
		t.Errorf("summarizeHTTP 缺字段: %q", got)
	}
}

func TestHeaderVal(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nSERVER: Apache\r\nX-Foo: bar\r\n\r\nbody"
	if v := headerVal(resp, "Server"); v != "Apache" {
		t.Errorf("headerVal Server = %q, want Apache", v)
	}
	if v := headerVal(resp, "Missing"); v != "" {
		t.Errorf("缺失头应为空, 得到 %q", v)
	}
}

func TestHTMLTitle(t *testing.T) {
	if got := htmlTitle(`<HTML><Title lang="x">  Hello   World </Title>`); got != "Hello World" {
		t.Errorf("htmlTitle = %q, want 'Hello World'", got)
	}
	if got := htmlTitle("no title here"); got != "" {
		t.Errorf("无 title 应为空, 得到 %q", got)
	}
}

func TestGuessFromBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.9":        "ssh",
		"HTTP/1.1 200 OK":            "http",
		"CN=*.example.com · TLSv1.3": "https",
		"220 ProFTPD FTP server":     "ftp",
	}
	for banner, want := range cases {
		if got := guessFromBanner(banner); got != want {
			t.Errorf("guessFromBanner(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestSanitizeClip(t *testing.T) {
	if sanitize("ab\x00c\tde\n") != "abcde" {
		t.Errorf("sanitize 未清除控制字符: %q", sanitize("ab\x00c\tde\n"))
	}
	if clip("abcdef", 3) != "abc…" {
		t.Errorf("clip 截断错误: %q", clip("abcdef", 3))
	}
	if clip("ab", 5) != "ab" {
		t.Errorf("clip 不应截断短串")
	}
}

func TestRateLimiterInterval(t *testing.T) {
	// rate=0 不限速:wait 立即返回
	l0 := newRateLimiter(0)
	start := time.Now()
	_ = l0.wait(context.Background())
	if time.Since(start) > 5*time.Millisecond {
		t.Errorf("rate=0 不应阻塞")
	}
	// rate=100 → 间隔 10ms;连续 3 次至少耗时 ~20ms(第1次不等待)
	l := newRateLimiter(100)
	start = time.Now()
	for i := 0; i < 3; i++ {
		_ = l.wait(context.Background())
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("rate=100 连续3次耗时 %v, 期望 >= ~20ms", elapsed)
	}
}

func TestRateLimiterCancel(t *testing.T) {
	l := newRateLimiter(1) // 间隔 1s
	_ = l.wait(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.wait(ctx); err == nil {
		t.Errorf("已取消的 ctx 应返回错误")
	}
}

func TestStoreCountersAndElapsed(t *testing.T) {
	s := newStore("") // 空路径=不落盘
	s.beginScan("id1", "test", nil, scanOptions{})
	s.addPort(Port{Host: "h", Port: 80})
	s.addPort(Port{Host: "h", Port: 443})
	s.incClosed()
	s.incClosed()
	s.incFiltered()
	st := s.status()
	if st.Found != 2 || st.Closed != 2 || st.Filtered != 1 {
		t.Errorf("计数错误: found=%d closed=%d filtered=%d", st.Found, st.Closed, st.Filtered)
	}
	if !st.Running || st.ElapsedMs < 0 {
		t.Errorf("运行态/耗时异常: running=%v elapsed=%d", st.Running, st.ElapsedMs)
	}
	s.finishScan("")
	st2 := s.status()
	if st2.Running {
		t.Errorf("finishScan 后应非运行态")
	}
	if st2.ElapsedMs < 0 {
		t.Errorf("结束后耗时应 >= 0")
	}
}

func TestPersistAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.json")
	s := newStore(path)
	s.beginScan("id1", "t", []string{"h1", "h2"}, scanOptions{})
	s.addPort(Port{Host: "h1", Port: 80, Service: "http"})
	s.addPort(Port{Host: "h2", Port: 443, Service: "https"})
	s.incClosed()
	s.incFiltered()
	s.finishScan("")
	s.persist()

	s2 := newStore(path)
	if !s2.load() {
		t.Fatal("load 应成功")
	}
	got := s2.list()
	if len(got) != 2 || got[0].Port != 80 || got[1].Port != 443 {
		t.Errorf("端口未正确还原: %+v", got)
	}
	st := s2.status()
	if st.Running {
		t.Errorf("加载后应为非运行态")
	}
	if st.Found != 2 || st.Closed != 1 || st.Filtered != 1 {
		t.Errorf("计数未还原: found=%d closed=%d filtered=%d", st.Found, st.Closed, st.Filtered)
	}
}

func TestLoadMissingFile(t *testing.T) {
	s := newStore(filepath.Join(t.TempDir(), "nope.json"))
	if s.load() {
		t.Errorf("不存在的文件 load 应返回 false")
	}
}

func TestSynCookie(t *testing.T) {
	ip := net.ParseIP("203.0.113.5")
	const secret = 0xDEADBEEF
	// 确定性:同输入同输出
	if synCookie(ip, 80, secret) != synCookie(ip, 80, secret) {
		t.Errorf("synCookie 应确定性")
	}
	// 区分性:不同端口/IP/secret 应(极大概率)不同
	if synCookie(ip, 80, secret) == synCookie(ip, 443, secret) {
		t.Errorf("不同端口 cookie 不应相同")
	}
	if synCookie(ip, 80, secret) == synCookie(net.ParseIP("203.0.113.6"), 80, secret) {
		t.Errorf("不同 IP cookie 不应相同")
	}
	if synCookie(ip, 80, secret) == synCookie(ip, 80, secret+1) {
		t.Errorf("不同 secret cookie 不应相同")
	}
	if synCookie(net.ParseIP("::1"), 80, secret) != 0 {
		t.Errorf("非 IPv4 应返回 0")
	}
}

func TestProtoList(t *testing.T) {
	cases := map[string][]string{
		"":     {"tcp"},
		"tcp":  {"tcp"},
		"udp":  {"udp"},
		"both": {"tcp", "udp"},
		"UDP ": {"udp"},
	}
	for in, want := range cases {
		if got := protoList(in); !reflect.DeepEqual(got, want) {
			t.Errorf("protoList(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUDPPayloads(t *testing.T) {
	// 已知探针端口应有非空 payload;未知端口回退单字节(仍可探关闭)。
	for _, p := range []int{53, 123, 161, 1900} {
		if len(udpPayload(p)) < 4 {
			t.Errorf("端口 %d 探针过短: %d 字节", p, len(udpPayload(p)))
		}
	}
	if len(udpPayload(40000)) != 1 {
		t.Errorf("未知端口应回退单字节")
	}
	if len(ntpProbe) != 48 || ntpProbe[0] != 0x1b {
		t.Errorf("NTP 探针格式错误")
	}
}

// TestMasscanPortArg 校验 masscan -p 参数构造(TCP 直列,UDP 加 U: 前缀)。
func TestMasscanPortArg(t *testing.T) {
	if got := masscanPortArg("tcp", []int{80, 443}); got != "80,443" {
		t.Errorf("tcp = %q", got)
	}
	if got := masscanPortArg("udp", []int{53, 123}); got != "U:53,U:123" {
		t.Errorf("udp = %q", got)
	}
	if got := masscanPortArg("both", []int{80}); got != "80,U:80" {
		t.Errorf("both = %q", got)
	}
}

// TestParseMasscanLine 校验 grepable 输出解析。
func TestParseMasscanLine(t *testing.T) {
	label := map[string]string{"1.2.3.4": "host.example"}
	p, ok := parseMasscanLine("open tcp 80 1.2.3.4 1700000000", label)
	if !ok || p.Port != 80 || p.Proto != "tcp" || p.Host != "host.example" || p.Service != "http" {
		t.Errorf("open 行解析错误: %+v ok=%v", p, ok)
	}
	if _, ok := parseMasscanLine("# masscan", label); ok {
		t.Errorf("注释行不应解析为命中")
	}
	if _, ok := parseMasscanLine("", label); ok {
		t.Errorf("空行不应解析为命中")
	}
	// 无标签时回退用 IP 作 host。
	if p, ok := parseMasscanLine("open udp 53 8.8.8.8 1", nil); !ok || p.Host != "8.8.8.8" || p.Service != "dns" {
		t.Errorf("无标签回退错误: %+v ok=%v", p, ok)
	}
}

// TestConnectScanIntegration 启动若干真实 TCP 监听端口，用 connect 引擎扫描 localhost，
// 验证开放端口全部被发现、未监听端口不被误报。
func TestConnectScanIntegration(t *testing.T) {
	// 开 3 个随机端口
	openPorts := make([]int, 3)
	listeners := make([]net.Listener, 3)
	for i := range listeners {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		listeners[i] = ln
		openPorts[i] = ln.Addr().(*net.TCPAddr).Port
		// 接受连接但不发数据（模拟真实服务只建连不响应）
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}(ln)
	}

	// 找一个确定未占用的端口（关闭即释放）
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()

	// 构造仅扫描这几个端口的规格
	portSpec := fmt.Sprintf("%d,%d,%d,%d",
		openPorts[0], openPorts[1], openPorts[2], closedPort)

	st := newStore("")
	m := &Module{log: noopLogger{}, store: st}
	opt := scanOptions{
		Targets:     []string{"127.0.0.1"},
		Ports:       portSpec,
		Mode:        "connect",
		Concurrency: 16,
		Timeout:     800,
		Banner:      false,
	}
	st.beginScan("integ1", "tcp-integration", opt.Targets, opt)
	m.runScan(context.Background(), opt)

	found := map[int]bool{}
	for _, p := range st.list() {
		found[p.Port] = true
	}

	for _, p := range openPorts {
		if !found[p] {
			t.Errorf("开放端口 %d 未被发现", p)
		}
	}
	if found[closedPort] {
		t.Errorf("已关闭端口 %d 不应被报告为开放", closedPort)
	}
}

// noopLogger 满足 core.Logger 接口，测试内使用避免 nil panic。
type noopLogger struct{}

func (noopLogger) Info(string, ...any)        {}
func (noopLogger) Warn(string, ...any)        {}
func (noopLogger) Error(string, ...any)       {}
func (noopLogger) With(...any) core.Logger    { return noopLogger{} }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ───────────── OS 指纹推断测试 ─────────────

func TestGuessOSFromTTLWindow(t *testing.T) {
	cases := []struct {
		ttl     uint8
		win     uint16
		wantSub string
	}{
		{64, 29200, "Linux"},
		{64, 5840, "Linux"},
		{63, 65535, "Linux"},
		{60, 14600, "Linux"},
		{128, 65535, "Windows"},
		{128, 8192, "Windows"},
		{127, 0, "Windows"},
		{200, 0, "Cisco"},
		{255, 0, "Cisco"},
	}
	for _, c := range cases {
		got := guessOSFromTTLWindow(c.ttl, c.win)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("guessOSFromTTLWindow(%d,%d) = %q, 期望含 %q", c.ttl, c.win, got, c.wantSub)
		}
	}
	if got := guessOSFromTTLWindow(0, 0); got != "" {
		t.Errorf("TTL=0 应返回空串, got %q", got)
	}
}

func TestGuessOSFromBanner(t *testing.T) {
	cases := []struct {
		banner  string
		wantSub string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "Ubuntu"},
		{"SSH-2.0-OpenSSH_8.4p1 Debian-2+deb11u2", "Debian"},
		{"SSH-2.0-OpenSSH_7.4 CentOS stream", "CentOS"},
		{"SSH-2.0-OpenSSH_8.0 Fedora-36", "Fedora"},
		{"SSH-2.0-OpenSSH_8.1 Alpine-3.16", "Alpine"},
		{"SSH-2.0-OpenSSH_9.0 OpenSSH generic", "Linux"},
		{"Microsoft FTP Service version 7.0", "Windows"},
		{"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "Windows"},
		{"Cisco IOS Software, Version 15.4", "Cisco"},
		{"Juniper Networks", "Juniper"},
		{"Huawei VRP Software", "Huawei"},
		{"MikroTik RouterOS 6.49.8", "MikroTik"},
		{"FortiGate-100F v7.0", "Fortinet"},
	}
	for _, c := range cases {
		got := guessOSFromBanner(c.banner)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("guessOSFromBanner(%q) = %q, 期望含 %q", c.banner, got, c.wantSub)
		}
	}
	if got := guessOSFromBanner("some random unknown banner text"); got != "" {
		t.Errorf("未知 banner 应返回空串, got %q", got)
	}
}

// ───────────── 主动探针测试 ─────────────

// mockTCPServer 在随机端口起一个 TCP 服务，每条连接交由 handler 处理后关闭。
func mockTCPServer(t *testing.T, handler func(net.Conn)) (port int, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mockTCPServer: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handler(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func dialActive(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	return conn
}

func TestActiveProbeRedisPong(t *testing.T) {
	srv, cleanup := mockTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "+PONG\r\n")
	})
	defer cleanup()
	conn := dialActive(t, srv)
	defer conn.Close()
	got := activeProbe(conn, 6379, time.Second)
	if !strings.Contains(got, "redis") || !strings.Contains(got, "无认证") {
		t.Errorf("Redis PONG 探针 = %q", got)
	}
}

func TestActiveProbeRedisNoAuth(t *testing.T) {
	srv, cleanup := mockTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "-NOAUTH Authentication required\r\n")
	})
	defer cleanup()
	conn := dialActive(t, srv)
	defer conn.Close()
	got := activeProbe(conn, 6379, time.Second)
	if !strings.Contains(got, "需认证") {
		t.Errorf("Redis NOAUTH 探针 = %q", got)
	}
}

func TestActiveProbeMemcached(t *testing.T) {
	srv, cleanup := mockTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "VERSION 1.6.20\r\n")
	})
	defer cleanup()
	conn := dialActive(t, srv)
	defer conn.Close()
	got := activeProbe(conn, 11211, time.Second)
	if !strings.Contains(got, "memcached") {
		t.Errorf("Memcached 探针 = %q", got)
	}
	if !strings.Contains(got, "1.6.20") {
		t.Errorf("Memcached 探针未含版本号: %q", got)
	}
}

func TestActiveProbeVNC(t *testing.T) {
	srv, cleanup := mockTCPServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "RFB 003.008\n")
	})
	defer cleanup()
	conn := dialActive(t, srv)
	defer conn.Close()
	got := activeProbe(conn, 5900, time.Second)
	if !strings.Contains(got, "vnc") {
		t.Errorf("VNC 探针 = %q", got)
	}
}

func TestActiveProbeZookeeper(t *testing.T) {
	srv, cleanup := mockTCPServer(t, func(c net.Conn) {
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "Zookeeper version: 3.8.1-2024\nMode: leader\nNode count: 1\n")
	})
	defer cleanup()
	conn := dialActive(t, srv)
	defer conn.Close()
	got := activeProbe(conn, 2181, time.Second)
	if !strings.Contains(got, "zookeeper") {
		t.Errorf("ZooKeeper 探针 = %q", got)
	}
}

func TestActiveProbeUnknownPort(t *testing.T) {
	srv, cleanup := mockTCPServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "hello world\r\n")
	})
	defer cleanup()
	conn := dialActive(t, srv)
	defer conn.Close()
	if got := activeProbe(conn, 12345, time.Second); got != "" {
		t.Errorf("未知端口探针应返回空串, got %q", got)
	}
}

// ───────────── 新增 UDP 探针载荷校验 ─────────────

func TestNewUDPProbePayloads(t *testing.T) {
	cases := []struct {
		port   int
		minLen int
		desc   string
	}{
		{69, 10, "TFTP RRQ"},
		{111, 40, "RPC portmapper"},
		{137, 40, "NetBIOS NBSTAT"},
		{500, 20, "ISAKMP IKEv1"},
		{1194, 16, "OpenVPN"},
		{5060, 40, "SIP OPTIONS"},
		{5353, 20, "mDNS"},
		{47808, 8, "BACnet Who-Is"},
	}
	for _, tc := range cases {
		p := udpPayload(tc.port)
		if len(p) < tc.minLen {
			t.Errorf("端口 %d (%s) 探针长 %d < 期望最小 %d", tc.port, tc.desc, len(p), tc.minLen)
		}
	}
}

func TestUDPServiceNames(t *testing.T) {
	cases := map[int]string{
		69:    "tftp",
		111:   "rpcbind",
		137:   "netbios-ns",
		138:   "netbios-dgm",
		500:   "isakmp",
		514:   "syslog",
		1194:  "openvpn",
		4500:  "ipsec-nat",
		5060:  "sip",
		5353:  "mdns",
		47808: "bacnet",
		51820: "wireguard",
	}
	for port, want := range cases {
		if got := udpServiceName(port); got != want {
			t.Errorf("udpServiceName(%d) = %q, want %q", port, got, want)
		}
	}
}
