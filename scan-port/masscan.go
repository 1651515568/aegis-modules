package portscan

// masscan.go —— 内嵌 masscan 二进制的端口扫描引擎(默认引擎)。
//
// 思路:用 //go:embed 把各平台 masscan 可执行文件打包进引擎二进制;运行时按
// GOOS/GOARCH 选对应文件、释放到 engine/data/scan-port/bin/ 下,作为子进程调用,
// 以 `-oL -`(grepable 列表,仅开放端口)流式输出,逐行解析喂进 store。
// masscan 只确认端口开放(无 banner),故扫描后可选地对开放端口二次 connect 抓 banner
// (复用 enrich.go)。任何「无法运行」(二进制缺失 / 无管理员 / 无 libpcap/Npcap)都返回
// 错误,由 scanner.go 回退到纯 Go connect 扫描,体验不中断。
//
// 安全:masscan 是高速发包器,这里强制要求 -p 与 --rate、对速率设硬上限、对目标×端口
// 组合设上限;targets 仅为本模块解析后的 IPv4(域名先解析,不把域名交给 masscan)。
// 仅对已授权目标使用。
//
// 二进制不在仓库内(AGPL 许可 + 体积),需手工放入 bin/ 后重新 `go build`,命名约定见
// bin/README.md 与 HANDOFF.md。缺二进制时本引擎自动让位给 connect 引擎。

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed bin
var masscanBins embed.FS

const (
	// masscanRunDir 是运行期释放二进制的位置(相对 cwd=engine/;data/ 在 .gitignore)。
	masscanRunDir = "data/scan-port/bin"
	// defaultMasscanRate 是未指定 rate 时的发包速率(masscan 必须有 --rate)。
	defaultMasscanRate = 1000
	// maxMasscanRate 是发包速率硬上限,避免误填打爆链路。
	maxMasscanRate = 100000
	// masscanWaitSec 是发包结束后等待迟到响应的秒数。
	masscanWaitSec = 3
)

// 解析 masscan 进度行里的 "12.34% done"。
var masscanPercentRe = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)% done`)

// masscanBinName 返回当前平台应使用的内嵌二进制文件名(约定:masscan-<os>-<arch>[.exe])。
func masscanBinName() string {
	name := "masscan-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// ensureMasscan 把当前平台的内嵌二进制释放到 masscanRunDir 并返回其路径。
// 二进制缺失时返回错误(触发上层回退 connect)。
func ensureMasscan() (string, error) {
	name := masscanBinName()
	data, err := masscanBins.ReadFile("bin/" + name)
	if err != nil {
		return "", fmt.Errorf("未内嵌当前平台的 masscan 二进制(缺 bin/%s)", name)
	}
	if len(data) < 1024 {
		// 占位文件(如 README 误命中)不当作可执行二进制。
		return "", fmt.Errorf("内嵌的 bin/%s 体积异常,疑似占位文件", name)
	}
	if !isValidExecutableMagic(data) {
		return "", fmt.Errorf("内嵌的 bin/%s 不是有效可执行文件(ELF/PE 魔数校验失败)", name)
	}
	if err := os.MkdirAll(masscanRunDir, 0o755); err != nil {
		return "", fmt.Errorf("创建运行目录失败: %w", err)
	}
	dest := filepath.Join(masscanRunDir, name)
	// 大小+SHA-256 双重校验：大小一致但内容不同（截断写入/存储位错）时能正确检测到并重新释放。
	wantSum := sha256.Sum256(data)
	if fi, err := os.Stat(dest); err == nil && fi.Size() == int64(len(data)) {
		if existing, err2 := os.ReadFile(dest); err2 == nil && sha256.Sum256(existing) == wantSum {
			return dest, nil
		}
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		return "", fmt.Errorf("释放 masscan 二进制失败: %w", err)
	}
	return dest, nil
}

// masscanRun 用内嵌 masscan 对 hosts×ports 做扫描。返回非 nil 错误表示「无法运行」,
// 调用方据此回退 connect;返回 nil 表示已完成(含被取消),状态已落定并持久化。
func (m *Module) masscanRun(ctx context.Context, hosts []string, ports []int, opt scanOptions, timeout time.Duration) error {
	// masscan 不做 DNS:先把域名解析成 IPv4,并保留 IP→原始标签 映射用于展示。
	var ips []string
	label := map[string]string{}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ips = append(ips, v4.String())
				label[v4.String()] = h
			}
			continue
		}
		ipa, err := net.ResolveIPAddr("ip4", h)
		if err != nil || ipa.IP.To4() == nil {
			continue
		}
		s := ipa.IP.To4().String()
		ips = append(ips, s)
		if label[s] == "" {
			label[s] = h
		}
	}
	if len(ips) == 0 {
		return fmt.Errorf("masscan 无可解析的 IPv4 目标")
	}

	total := len(ips) * len(ports)
	if total > maxProbes {
		// 组合过大属用户输入问题,直接落定失败(回退 connect 也会同样拒绝)。
		m.store.finishScan(fmt.Sprintf("目标×端口 组合过大(%d),请缩小范围(上限 %d)", total, maxProbes))
		return nil
	}

	exe, err := ensureMasscan()
	if err != nil {
		return err // 触发回退 connect
	}

	rate := opt.Rate
	if rate <= 0 {
		rate = defaultMasscanRate
	}
	if rate > maxMasscanRate {
		rate = maxMasscanRate
	}

	args := append([]string{}, ips...)
	args = append(args,
		"-p", masscanPortArg(opt.Proto, ports),
		"--rate", strconv.Itoa(rate),
		"--wait", strconv.Itoa(masscanWaitSec),
		"-oL", "-", // grepable 列表输出到 stdout,仅开放端口
	)

	m.store.setEngine("masscan")
	m.store.setPhase("端口扫描")
	m.store.setTarget(fmt.Sprintf("%d 主机 × %d 端口 · masscan", len(ips), len(ports)))
	m.store.setTotal(total)
	m.store.setRate(rate)
	m.log.Info("masscan started", "exe", exe, "ips", len(ips), "ports", len(ports), "rate", rate)

	cmd := exec.CommandContext(ctx, exe, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("masscan stdout 管道失败: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("masscan stderr 管道失败: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 masscan 失败: %w", err)
	}

	// stderr:解析进度百分比 + 收集尾部用于诊断。
	var sawProgress bool
	var stderrTail bytes.Buffer
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		sc := bufio.NewScanner(stderr)
		sc.Split(scanCRorLF)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if mt := masscanPercentRe.FindStringSubmatch(line); mt != nil {
				if pct, e := strconv.ParseFloat(mt[1], 64); e == nil {
					sawProgress = true
					m.store.setProbed(int(pct / 100 * float64(total)))
				}
			}
			if stderrTail.Len() < 4096 {
				stderrTail.WriteString(strings.TrimSpace(line))
				stderrTail.WriteByte('\n')
			}
		}
	}()

	// stdout:逐行解析开放端口。
	found := 0
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if p, ok := parseMasscanLine(sc.Text(), label); ok {
			m.store.addPort(p)
			found++
		}
	}
	<-stderrDone
	waitErr := cmd.Wait()

	// 被取消:交回上层按「已停止」落定。
	if ctx.Err() != nil {
		return nil
	}

	// 完全跑不起来(无输出、无进度、退出报错)→ 回退 connect。
	if waitErr != nil && found == 0 && !sawProgress {
		tail := strings.TrimSpace(stderrTail.String())
		if len(tail) > 300 {
			tail = tail[len(tail)-300:]
		}
		return fmt.Errorf("masscan 运行失败(可能缺管理员权限或 libpcap/Npcap): %v; %s", waitErr, tail)
	}

	m.store.setProbed(total)

	// 发现后服务识别:对开放端口二次 connect 抓 banner(masscan 本身无 banner)。
	if opt.Banner && found > 0 && ctx.Err() == nil {
		open := m.store.list()
		m.store.setPhase("服务识别")
		m.log.Info("masscan banner enrichment", "open", len(open))
		m.enrichBanners(ctx, open, opt, timeout)
	}

	errMsg := ""
	if waitErr != nil && found == 0 {
		errMsg = "masscan 未发现开放端口或异常退出"
	}
	m.store.finishScan(errMsg)
	m.store.persist()
	m.log.Info("masscan finished", "found", found, "err", waitErr)
	return nil
}

// masscanPortArg 构造 masscan 的 -p 参数:TCP 直接列,UDP 加 "U:" 前缀。
func masscanPortArg(proto string, ports []int) string {
	protos := protoList(proto)
	hasTCP, hasUDP := false, false
	for _, p := range protos {
		switch p {
		case "tcp":
			hasTCP = true
		case "udp":
			hasUDP = true
		}
	}
	var parts []string
	if hasTCP {
		parts = append(parts, joinPorts(ports, ""))
	}
	if hasUDP {
		parts = append(parts, joinPorts(ports, "U:"))
	}
	return strings.Join(parts, ",")
}

// joinPorts 把端口列表拼成逗号串,每项可加前缀(如 "U:")。
func joinPorts(ports []int, prefix string) string {
	var b strings.Builder
	for i, p := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(prefix)
		b.WriteString(strconv.Itoa(p))
	}
	return b.String()
}

// parseMasscanLine 解析一行 masscan grepable 输出:
//
//	open tcp 80 1.2.3.4 1700000000
//
// 返回开放端口;非开放行(注释/空行/closed)返回 false。
func parseMasscanLine(line string, label map[string]string) (Port, bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 4 || f[0] != "open" {
		return Port{}, false
	}
	proto := f[1]
	port, err := strconv.Atoi(f[2])
	if err != nil || !validPort(port) {
		return Port{}, false
	}
	ip := f[3]
	host := label[ip]
	if host == "" {
		host = ip
	}
	svc := serviceName(port)
	if proto == "udp" {
		svc = udpServiceName(port)
	}
	return Port{Host: host, Port: port, Proto: proto, Service: svc}, true
}

// isValidExecutableMagic 校验字节切片是否为合法的 ELF（Linux）或 PE（Windows）可执行文件。
func isValidExecutableMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ELF magic: 0x7f 'E' 'L' 'F'
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}
	// PE magic: 'M' 'Z'
	if data[0] == 'M' && data[1] == 'Z' {
		return true
	}
	return false
}

// scanCRorLF 是按 \r 或 \n 断行的 bufio.SplitFunc —— masscan 进度行用 \r 刷新。
func scanCRorLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
