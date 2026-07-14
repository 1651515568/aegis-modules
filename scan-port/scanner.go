package portscan

// scanner.go —— 端口扫描引擎调度 + 纯 Go connect 扫描。
//
// runScan 是一次扫描的总入口,按 opt.Mode 选择引擎:
//   * "masscan"(默认):调用内嵌的 masscan 二进制(masscan.go),失败回退 connect。
//   * "syn":masscan 式 SYN 半开扫描(需 -tags npcap + Npcap + 管理员;见 synscan.go)。
//   * "connect"(及其它):纯 Go TCP connect 探测(本文件),免提权、跨平台。
//
// connect 引擎:对每个 (host, port) 做一次 TCP connect(三次握手成功 = 端口开放),
// 失败/超时 = 关闭或被过滤。并发由 worker 池控制,全局每秒请求数由最小间隔限速器收敛,
// 支持随时通过 context 取消。可选服务识别(知名端口映射)与 banner 抓取。
//
// 仅做 connect 探测,绝不发送 payload(banner 抓取仅对 HTTP 端口发一个 HEAD)。
// 请仅对已授权目标使用。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// scanOptions 是一次端口扫描的参数(来自 POST /scan 或 /invoke 的 params)。
type scanOptions struct {
	Name           string   `json:"name"`           // 任务名称(展示用)
	Targets        []string `json:"targets"`        // IP / 域名 / CIDR / host:port / URL
	Ports          string   `json:"ports"`          // "top100"|"top500"|"top1000"|"all"|"custom"|"22,80,443,8000-8100"
	PortsCustom    string   `json:"portsCustom"`    // 仅 ports="custom" 时生效的自定义端口规格
	Rate           int      `json:"rate"`           // 全局每秒连接数上限,0=不限速(masscan 下为发包速率)
	Timeout        int      `json:"timeout"`        // 单次连接超时(毫秒)
	Concurrency    int      `json:"concurrency"`    // 并发 worker 数,0=默认
	Retries        int      `json:"retries"`        // 超时重试次数(默认 1);仅对超时重试,拒绝连接不重试
	Discovery      bool     `json:"discovery"`      // 端口扫描前先做主机存活探测,跳过死主机
	DiscoveryPorts string   `json:"discoveryPorts"` // 存活探测端口(逗号/区间),空=默认
	Proto          string   `json:"proto"`          // tcp(默认)/ udp / both
	Mode           string   `json:"mode"`           // masscan(默认)/ connect / syn
	Adaptive       bool     `json:"adaptive"`       // 自适应速率(AIMD:按超时比例自动增减,仅 connect)
	Svc            bool     `json:"svc"`            // 服务识别(知名端口映射)
	Banner         bool     `json:"banner"`         // 抓取 banner
}

// defaultDiscoveryPorts 是存活探测默认使用的常见端口(任一可达即判定主机存活)。
var defaultDiscoveryPorts = []int{80, 443, 22, 3389, 445}

const (
	defaultTimeout     = 1500 * time.Millisecond
	defaultConcurrency = 256
	maxConcurrency     = 1024
	defaultRetries     = 1         // 默认对超时重试 1 次,降低丢包漏报
	maxRetries         = 5         // 重试次数上限
	maxCIDRHosts       = 1024      // 单个 CIDR 最多展开的主机数
	maxHosts           = 4096      // 解析后的目标主机总数上限
	maxProbes          = 2_000_000 // 目标×端口 组合上限,超过则拒绝

	adaptiveStartRate = 500  // 自适应起始速率(未设 rate 时)
	adaptiveMaxRate   = 5000 // 自适应速率上限(未设 rate 时)
	adaptiveMinRate   = 50   // 自适应速率下限
)

type probeJob struct {
	host  string
	port  int
	proto string // "tcp" | "udp"
}

// runScan 执行一次端口扫描(在独立 goroutine 中运行,结束时落定状态)。
func (m *Module) runScan(ctx context.Context, opt scanOptions) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Error("portscan panic", "recover", r)
			m.store.finishScan(fmt.Sprintf("内部错误: %v", r))
		}
	}()

	hosts := parseTargets(opt.Targets)
	ports := parsePorts(opt.Ports)
	if len(hosts) == 0 {
		m.store.finishScan("未解析到有效目标")
		return
	}
	if len(ports) == 0 {
		m.store.finishScan("未解析到有效端口")
		return
	}
	if len(hosts) > maxHosts {
		m.store.finishScan(fmt.Sprintf("目标主机过多(%d),请缩小范围(上限 %d)", len(hosts), maxHosts))
		return
	}

	timeout := time.Duration(opt.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	concurrency := opt.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	if concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}
	retries := opt.Retries
	if retries < 0 {
		retries = defaultRetries
	}
	if retries > maxRetries {
		retries = maxRetries
	}
	opt.Retries = retries

	lim := newRateLimiter(opt.Rate)

	// ── 阶段一:主机存活探测(多主机时,跳过死主机)──
	if opt.Discovery && len(hosts) > 1 {
		dports := defaultDiscoveryPorts
		if strings.TrimSpace(opt.DiscoveryPorts) != "" {
			if pp := parsePorts(opt.DiscoveryPorts); len(pp) > 0 {
				dports = pp
			}
		}
		m.store.setPhase("存活探测")
		m.log.Info("portscan discovery started", "hosts", len(hosts), "ports", len(dports))
		hosts = m.discoverHosts(ctx, hosts, timeout, concurrency, lim, dports)
		m.store.setAlive(len(hosts))
		m.log.Info("portscan discovery done", "alive", len(hosts))
		if ctx.Err() != nil {
			m.store.finishScan("已停止")
			return
		}
		if len(hosts) == 0 {
			m.store.finishScan("存活探测未发现可达主机(可关闭存活探测强制扫描)")
			return
		}
	} else {
		m.store.setAlive(len(hosts))
	}

	// ── masscan 引擎(默认):内嵌二进制子进程扫描,失败回退 connect ──
	if masscanMode(opt.Mode) {
		err := m.masscanRun(ctx, hosts, ports, opt, timeout)
		if err == nil {
			return // masscanRun 已落定状态并持久化
		}
		if ctx.Err() != nil {
			m.store.finishScan("已停止")
			m.store.persist()
			return
		}
		// 二进制缺失 / 无权限 / 无 Npcap-libpcap → 回退 connect 扫描,体验不中断。
		m.log.Warn("masscan 不可用,回退 connect 扫描", "err", err)
		opt.Mode = "connect"
	}

	// ── SYN 模式(masscan 式半开扫描):需 -tags npcap 编译 + Npcap + 管理员 ──
	if strings.EqualFold(opt.Mode, "syn") {
		if !synAvailable() {
			// 非 Linux / 非 npcap 环境：自动降级到 connect 扫描
			m.log.Warn("SYN 扫描不可用(未以 -tags npcap 编译,或非 Linux),自动降级到 connect 模式")
			opt.Mode = "connect"
		} else {
			total := len(hosts) * len(ports)
			if total > maxProbes {
				m.store.finishScan(fmt.Sprintf("目标×端口 组合过大(%d),请缩小范围(上限 %d)", total, maxProbes))
				return
			}
			m.store.setEngine("syn")
			m.store.setPhase("端口扫描")
			m.store.setTarget(fmt.Sprintf("%d 主机 × %d 端口 · SYN", len(hosts), len(ports)))
			m.store.setTotal(total)
			m.log.Info("portscan SYN started", "hosts", len(hosts), "ports", len(ports), "rate", opt.Rate)
			err := m.synScan(ctx, hosts, ports, opt, timeout)
			if err != nil && (strings.Contains(err.Error(), "permission") ||
				strings.Contains(err.Error(), "EPERM") ||
				strings.Contains(err.Error(), "CAP_NET_RAW") ||
				strings.Contains(err.Error(), "raw socket")) {
				// 权限不足：自动降级到 connect 扫描，体验不中断
				m.log.Warn("SYN 扫描权限不足，自动降级到 connect 模式", "err", err)
				opt.Mode = "connect"
			} else {
				errMsg := ""
				if ctx.Err() != nil {
					errMsg = "已停止"
				} else if err != nil {
					errMsg = err.Error()
				}
				m.store.finishScan(errMsg)
				m.store.persist()
				m.log.Info("portscan SYN finished", "err", errMsg)
				return
			}
		}
	}

	// ── connect / udp 引擎(纯 Go,免提权) ──
	protos := protoList(opt.Proto)
	total := len(hosts) * len(ports) * len(protos)
	if total > maxProbes {
		m.store.finishScan(fmt.Sprintf("目标×端口 组合过大(%d),请缩小范围(上限 %d)", total, maxProbes))
		return
	}
	m.store.setEngine("connect")
	m.store.setPhase("端口扫描")
	label := fmt.Sprintf("%d 主机 × %d 端口 × %s", len(hosts), len(ports), strings.Join(protos, "+"))
	m.store.setTarget(label)
	m.store.setTotal(total)
	m.log.Info("portscan started", "hosts", len(hosts), "ports", len(ports), "protos", protos, "concurrency", concurrency, "rate", opt.Rate, "adaptive", opt.Adaptive)

	// 自适应速率控制器(AIMD):按超时比例自动增减速率。
	ctrlDone := make(chan struct{})
	if opt.Adaptive {
		m.startRateController(ctx, lim, opt, ctrlDone)
	} else {
		m.store.setRate(opt.Rate)
	}

	jobs := make(chan probeJob, concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() == nil && lim.wait(ctx) == nil {
					if j.proto == "udp" {
						m.udpProbe(ctx, j.host, j.port, timeout, opt)
					} else {
						m.probe(ctx, j.host, j.port, timeout, opt)
					}
				}
				m.store.incProbed()
			}
		}()
	}

	// 借鉴 masscan:按伪随机置换遍历整个 主机×端口×协议 空间,打散对单一目标的压力。
	np := uint64(len(ports))
	npr := uint64(len(protos))
	perm := newPermutation(uint64(total), uint64(time.Now().UnixNano()))
feed:
	for i := uint64(0); i < uint64(total); i++ {
		select {
		case <-ctx.Done():
			break feed
		default:
		}
		idx := perm.at(i)
		hi := idx / (np * npr)
		rem := idx % (np * npr)
		pi := rem / npr
		pri := rem % npr
		select {
		case <-ctx.Done():
			break feed
		case jobs <- probeJob{host: hosts[hi], port: ports[pi], proto: protos[pri]}:
		}
	}
	close(jobs)
	wg.Wait()
	close(ctrlDone) // 停止自适应控制器

	errMsg := ""
	if ctx.Err() != nil {
		errMsg = "已停止"
	}
	st := m.store.status()
	m.store.finishScan(errMsg)
	m.store.persist() // 落盘,供后端重启后还原本地视图
	m.log.Info("portscan finished", "found", st.Found, "probed", st.Probed, "canceled", ctx.Err() != nil)
}

// masscanMode 判定是否走 masscan 引擎(默认引擎)。空 mode 视为 masscan。
func masscanMode(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	return m == "" || m == "masscan"
}

// startRateController 按 AIMD 调整速率:
//   - 超时(filtered)比例高 → 乘性降速(疑似限流/拥塞)
//   - 比例低 → 加性升速,直到 max
//
// 速率夹在 [adaptiveMinRate, max];max = opt.Rate(未设则 adaptiveMaxRate)。
func (m *Module) startRateController(ctx context.Context, lim *rateLimiter, opt scanOptions, done <-chan struct{}) {
	cur := opt.Rate
	if cur <= 0 {
		cur = adaptiveStartRate
	}
	maxRate := opt.Rate
	if maxRate <= 0 {
		maxRate = adaptiveMaxRate
	}
	lim.setRate(cur)
	m.store.setRate(cur)
	go func() {
		t := time.NewTicker(400 * time.Millisecond)
		defer t.Stop()
		lastProbed, lastFiltered := 0, 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				st := m.store.status()
				dp := st.Probed - lastProbed
				df := st.Filtered - lastFiltered
				lastProbed, lastFiltered = st.Probed, st.Filtered
				if dp < 5 { // 样本太少,不调
					continue
				}
				ratio := float64(df) / float64(dp)
				switch {
				case ratio > 0.4:
					cur = cur * 7 / 10 // 乘性降速
				case ratio < 0.1:
					cur += 200 // 加性升速
				}
				if cur < adaptiveMinRate {
					cur = adaptiveMinRate
				}
				if cur > maxRate {
					cur = maxRate
				}
				lim.setRate(cur)
				m.store.setRate(cur)
			}
		}
	}()
}

// probe 对单个 host:port 做 TCP connect 探测;开放则记录结果。
// 仅对「超时」重试(可能是丢包),对「连接被拒绝」(端口关闭)不重试。
func (m *Module) probe(ctx context.Context, host string, port int, timeout time.Duration, opt scanOptions) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.Conn
	var lastErr error
	for attempt := 0; attempt <= opt.Retries; attempt++ {
		if ctx.Err() != nil {
			return
		}
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn = c
			break
		}
		lastErr = err
		// 连接被拒绝 = 端口确实关闭(收到 RST),无需重试。
		var ne net.Error
		if !(errors.As(err, &ne) && ne.Timeout()) {
			break
		}
		// 超时 → 可能丢包,继续重试(若还有次数)。
	}
	if conn == nil {
		// 分类:RST=关闭(主机可达),其余(超时/不可达)=被过滤。
		if ctx.Err() == nil {
			if hostUpFromDialErr(lastErr) {
				m.store.incClosed()
			} else {
				m.store.incFiltered()
			}
		}
		return
	}
	defer conn.Close()

	svc := serviceName(port)
	banner := ""
	if opt.Banner {
		banner = grabBanner(conn, host, port, timeout)
		if opt.Svc {
			if g := guessFromBanner(banner); g != "" {
				svc = g
			}
		}
	}
	m.store.addPort(Port{Host: host, Port: port, Proto: "tcp", Service: svc, Banner: banner})
}

// ───────────── 主机存活探测 ─────────────

// discoverHosts 对每个主机依次试探常见端口,任一「连得上」或「被拒绝(RST)」即判活,
// 全部超时则视为死/被过滤而跳过。返回按原顺序排列的存活主机列表。
func (m *Module) discoverHosts(ctx context.Context, hosts []string, timeout time.Duration, concurrency int, lim *rateLimiter, ports []int) []string {
	// 存活探测用较短超时(判活只需一次握手),最长 1s。
	dtimeout := timeout
	if dtimeout > time.Second {
		dtimeout = time.Second
	}
	if concurrency > len(hosts) {
		concurrency = len(hosts)
	}

	in := make(chan string, concurrency*2)
	var mu sync.Mutex
	upset := make(map[string]bool, len(hosts))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range in {
				if ctx.Err() != nil {
					continue
				}
				if m.hostAlive(ctx, h, dtimeout, lim, ports) {
					mu.Lock()
					upset[h] = true
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			break feed
		case in <- h:
		}
	}
	close(in)
	wg.Wait()

	out := make([]string, 0, len(upset))
	for _, h := range hosts { // 保持原顺序
		if upset[h] {
			out = append(out, h)
		}
	}
	return out
}

// hostAlive 依次探测存活端口,任一可达(连通或被拒绝)即返回 true。
func (m *Module) hostAlive(ctx context.Context, host string, timeout time.Duration, lim *rateLimiter, ports []int) bool {
	for _, pp := range ports {
		if ctx.Err() != nil {
			return false
		}
		if lim.wait(ctx) != nil {
			return false
		}
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(pp)))
		if err == nil {
			_ = c.Close()
			return true
		}
		if hostUpFromDialErr(err) {
			return true
		}
	}
	return false
}

// hostUpFromDialErr 判断一次 dial 错误是否仍能证明主机存活。
// 连接被拒绝 / 被重置 = 主机可达(端口关闭);超时 / 不可达 = 无法判定存活。
//
// 三层兜底策略：
//  1. 标准 POSIX errno（*nix 上直接命中）
//  2. Windows WSAE errno 数值（WSAECONNREFUSED=10061 / WSAECONNRESET=10054），
//     Go 在 Windows 上把 WSAE 错误包装为 syscall.Errno，但数值与 POSIX 不同，
//     errors.Is(syscall.ECONNREFUSED) 不能可靠匹配，故显式检测数值。
//  3. 跨平台错误文案（兜底）
func hostUpFromDialErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// Windows: WSAECONNREFUSED(10061) / WSAECONNRESET(10054)
	if errors.Is(err, syscall.Errno(10061)) || errors.Is(err, syscall.Errno(10054)) {
		return true
	}
	msg := strings.ToLower(err.Error())
	// *nix: "connection refused"/"connection reset";Windows: "actively refused"/"forcibly closed"
	return strings.Contains(msg, "refused") ||
		strings.Contains(msg, "reset") ||
		strings.Contains(msg, "forcibly closed")
}

// ───────────── 目标解析 ─────────────

// parseTargets 把原始目标(IP / 域名 / CIDR / host:port / URL)展开为去重的主机列表。
func parseTargets(in []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, raw0 := range in {
		// 单个元素内仍可能含逗号/空白(前端通常已拆,这里自防一层)
		for _, raw := range strings.FieldsFunc(raw0, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			processTarget(raw, add)
		}
	}
	return out
}

// processTarget 解析单个目标 token,展开后通过 add 收集。
func processTarget(raw string, add func(string)) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	// 去掉 scheme(http(s)://…)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	// CIDR(优先于按 "/" 截路径判断)
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			for _, ip := range expandCIDR(raw, maxCIDRHosts) {
				add(ip)
			}
			return
		}
		// 非 CIDR 的 "/" 视为路径,截断
		raw = raw[:strings.Index(raw, "/")]
	}
	// host:port → 取 host(端口由 ports 参数统一控制)
	if h, _, err := net.SplitHostPort(raw); err == nil && h != "" {
		raw = h
	}
	// 裸 IPv6 方括号格式 [::1]（无端口）→ 剥掉方括号，否则 JoinHostPort 会双重加括号
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}
	add(raw)
}

// expandCIDR 把 CIDR 展开为主机 IP 列表(最多 cap 个)。
func expandCIDR(cidr string, cap int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var out []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	for cur := cloneIP(ip); ipnet.Contains(cur); incIP(cur) {
		out = append(out, cur.String())
		if len(out) >= cap {
			break
		}
	}
	// /31、/32 等小网段保留全部;较大网段去掉网络号(可选,简化:保留)
	return out
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ───────────── 端口解析 ─────────────

// parsePorts 解析端口规格为去重升序的端口列表。
func parsePorts(spec string) []int {
	spec = strings.TrimSpace(spec)
	switch spec {
	case "", "top1000":
		return top1000Ports()
	case "top100":
		return append([]int(nil), top100Ports...)
	case "top500":
		return append([]int(nil), top500Ports...)
	case "all":
		return rangePorts(1, 65535)
	}
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			a, e1 := strconv.Atoi(strings.TrimSpace(ab[0]))
			b, e2 := strconv.Atoi(strings.TrimSpace(ab[1]))
			if e1 != nil || e2 != nil {
				continue
			}
			if a > b {
				a, b = b, a
			}
			for p := a; p <= b; p++ {
				if validPort(p) {
					set[p] = true
				}
			}
		} else if p, err := strconv.Atoi(part); err == nil && validPort(p) {
			set[p] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// protoList 把 proto 选项规整为待扫描协议列表(默认 tcp)。
func protoList(proto string) []string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "udp":
		return []string{"udp"}
	case "both", "tcp+udp", "tcp,udp":
		return []string{"tcp", "udp"}
	default:
		return []string{"tcp"}
	}
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func rangePorts(a, b int) []int {
	out := make([]int, 0, b-a+1)
	for p := a; p <= b; p++ {
		out = append(out, p)
	}
	return out
}

// top1000Ports = 标准端口 1-1000 ∪ 常见高位端口(去重升序)。
// 注意:此函数名为 top1000 但实现是「1-1000 顺序枚举 + commonHighPorts 补充」,
// 并非 nmap 统计意义上的「最常被扫到开放的前 1000 个端口」,
// 包含大量几乎从不开放的低号端口(2/3/4…)。实战中推荐优先使用 top100Ports。
func top1000Ports() []int {
	set := map[int]bool{}
	for p := 1; p <= 1000; p++ {
		set[p] = true
	}
	for _, p := range commonHighPorts {
		set[p] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ───────────── 限速器(最小间隔,等效 1/rate req/s) ─────────────

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(ratePerSec int) *rateLimiter {
	return &rateLimiter{interval: rateInterval(ratePerSec)}
}

func rateInterval(ratePerSec int) time.Duration {
	if ratePerSec > 0 {
		return time.Duration(float64(time.Second) / float64(ratePerSec))
	}
	return 0
}

// setRate 动态调整速率(自适应控制器调用)。
func (l *rateLimiter) setRate(ratePerSec int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.interval = rateInterval(ratePerSec)
}

func (l *rateLimiter) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
