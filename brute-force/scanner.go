package bruteforce

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BruteResult is the outcome record for a single credential probe attempt.
type BruteResult struct {
	Protocol string `json:"protocol"`
	Target   string `json:"target"` // host:port
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
	ErrMsg   string `json:"errMsg,omitempty"`
	FoundAt  string `json:"foundAt"`
}

// ProtoDict holds the resolved (after preset merge) username/password lists for one protocol.
type ProtoDict struct {
	Usernames []string
	Passwords []string
}

// bruteOptions configures the brute-force scan.
type bruteOptions struct {
	Targets   []string // raw targets: IPs, hostnames, CIDRs, host:port
	Protocols []string // protocol names
	// Global fallback dict (used when a protocol has no entry in ProtoDicts)
	Usernames      []string
	Passwords      []string
	UsernamePreset string
	PasswordPreset string
	// Per-protocol dict (takes priority over global when present)
	ProtoDicts      map[string]ProtoDict
	Threads         int
	HostConcurrency int            // max concurrent connections per host:port (default 3)
	TimeoutMs       int
	StopOnFirst     bool           // stop per (proto, host:port) once a cred succeeds
	PortOverrides   map[string]int // e.g. {"ssh": 2222, "mysql": 3307}
	// HTTP Form specific
	HTTPFormURL         string
	HTTPFormUserField   string
	HTTPFormPassField   string
	HTTPFormSuccessCode int
	HTTPFormFailText    string
}

// job is a single unit of work: try one (proto, host, port, user, pass) combination.
type job struct {
	proto    string
	host     string
	port     int
	username string
	password string
}

// bruteScanner holds no state between calls; options are passed to run().
type bruteScanner struct{}

func newBruteScanner() *bruteScanner { return &bruteScanner{} }

// run executes the brute-force scan and returns all results (successes AND notable failures).
// progressFn(completed, total, found) is called periodically.
func (s *bruteScanner) run(
	ctx context.Context,
	opts bruteOptions,
	progressFn func(completed, total, found int),
) ([]BruteResult, error) {
	// ── 1. Resolve global fallback username/password lists ────────────────────
	globalUsers := resolveList(opts.Usernames, opts.UsernamePreset, BuiltinUsernames)
	globalPasses := resolveList(opts.Passwords, opts.PasswordPreset, BuiltinPasswords)
	if len(globalUsers) == 0 {
		globalUsers = []string{"admin", "root"}
	}
	if len(globalPasses) == 0 {
		globalPasses = []string{""}
	}

	// ── 2. Expand targets ─────────────────────────────────────────────────────
	hosts, err := expandTargets(opts.Targets)
	if err != nil {
		return nil, fmt.Errorf("expanding targets: %w", err)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no valid targets provided")
	}

	protocols := opts.Protocols
	if len(protocols) == 0 {
		protocols = []string{"ssh"}
	}

	// ── 3. Build HTTP Form prober if needed ───────────────────────────────────
	var httpFormProber Prober
	for _, proto := range protocols {
		if proto == "http-form" {
			httpFormProber = &HTTPFormProber{
				Opts: HTTPFormOptions{
					URL:         opts.HTTPFormURL,
					UserField:   opts.HTTPFormUserField,
					PassField:   opts.HTTPFormPassField,
					SuccessCode: opts.HTTPFormSuccessCode,
					FailText:    opts.HTTPFormFailText,
				},
			}
			break
		}
	}

	// ── 4. Build job list ─────────────────────────────────────────────────────
	// For each host × protocol, look up the per-protocol dict (or fall back to global).
	var jobs []job
	for _, rawHost := range hosts {
		for _, proto := range protocols {
			prober := Probers[proto]
			if prober == nil && proto == "http-form" {
				prober = httpFormProber
			}
			if prober == nil {
				continue
			}

			// Per-protocol dict takes priority over global
			users := globalUsers
			passes := globalPasses
			if pd, ok := opts.ProtoDicts[proto]; ok {
				if len(pd.Usernames) > 0 {
					users = pd.Usernames
				}
				if len(pd.Passwords) > 0 {
					passes = pd.Passwords
				}
			}

			host, port := parseHostPort(rawHost, prober, opts.PortOverrides)
			for _, user := range users {
				for _, pass := range passes {
					jobs = append(jobs, job{
						proto:    proto,
						host:     host,
						port:     port,
						username: user,
						password: pass,
					})
				}
			}
		}
	}

	total := len(jobs)
	if total == 0 {
		return nil, fmt.Errorf("no jobs generated (check targets and protocols)")
	}

	// ── 5. Worker pool ────────────────────────────────────────────────────────
	threads := opts.Threads
	if threads <= 0 {
		threads = 20
	}
	if threads > 500 {
		threads = 500
	}
	hostConcurrency := opts.HostConcurrency
	if hostConcurrency <= 0 {
		hostConcurrency = 3
	}
	if hostConcurrency > threads {
		hostConcurrency = threads
	}

	// hostSems 为每个 host:port 预建带缓冲信号量，限制单目标最大并发连接数，
	// 避免触发 max_connections 错误或账户锁定机制。预建避免并发 map 写入竞争。
	hostSems := make(map[string]chan struct{}, len(jobs))
	for _, j := range jobs {
		hp := fmt.Sprintf("%s:%d", j.host, j.port)
		if _, ok := hostSems[hp]; !ok {
			hostSems[hp] = make(chan struct{}, hostConcurrency)
		}
	}

	var (
		mu         sync.Mutex
		results    []BruteResult
		succeeded  = make(map[string]bool) // "proto:host:port" → true
		failCounts = make(map[string]int)  // "proto:host:port" → 连续认证失败次数
		locked     = make(map[string]bool) // "proto:host:port" → 疑似账户锁定，跳过后续
		completed  int64
		found      int64
	)

	// Queue jobs into a channel
	jobCh := make(chan job, threads*2)
	go func() {
		defer close(jobCh)
		for _, j := range jobs {
			select {
			case <-ctx.Done():
				return
			case jobCh <- j:
			}
		}
	}()

	// Progress ticker
	ticker := time.NewTicker(500 * time.Millisecond)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c := int(atomic.LoadInt64(&completed))
				f := int(atomic.LoadInt64(&found))
				if progressFn != nil {
					progressFn(c, total, f)
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobCh:
					if !ok {
						return
					}

					key := fmt.Sprintf("%s:%s:%d", j.proto, j.host, j.port)

					// 检查是否已被标记为疑似账户锁定，锁定后跳过该目标所有后续任务
					mu.Lock()
					isLocked := locked[key]
					mu.Unlock()
					if isLocked {
						atomic.AddInt64(&completed, 1)
						continue
					}

					// Check StopOnFirst: skip if this (proto:host:port) already has a win
					if opts.StopOnFirst {
						mu.Lock()
						skip := succeeded[key]
						mu.Unlock()
						if skip {
							atomic.AddInt64(&completed, 1)
							continue
						}
					}

					// Select prober
					prober := Probers[j.proto]
					if prober == nil && j.proto == "http-form" {
						prober = httpFormProber
					}
					if prober == nil {
						atomic.AddInt64(&completed, 1)
						continue
					}

					// 获取 per-host 信号量 slot，限制单目标并发连接数
					hp := fmt.Sprintf("%s:%d", j.host, j.port)
					sem := hostSems[hp]
					select {
					case <-ctx.Done():
						return
					case sem <- struct{}{}:
					}
					result := prober.Probe(ctx, j.host, j.port, j.username, j.password, opts.TimeoutMs)
					<-sem // 释放 slot
					atomic.AddInt64(&completed, 1)

					if result.Success {
						atomic.AddInt64(&found, 1)
						now := time.Now().Format("2006-01-02 15:04:05")
						r := BruteResult{
							Protocol: j.proto,
							Target:   fmt.Sprintf("%s:%d", j.host, j.port),
							Username: j.username,
							Password: j.password,
							Success:  true,
							FoundAt:  now,
						}
						mu.Lock()
						results = append(results, r)
						if opts.StopOnFirst {
							succeeded[key] = true
						}
						// 登录成功则重置该目标的失败计数
						failCounts[key] = 0
						mu.Unlock()
					} else if result.AuthFail {
						// 认证失败：累计连续失败次数，达到阈值则标记锁定
						mu.Lock()
						failCounts[key]++
						cnt := failCounts[key]
						mu.Unlock()

						if cnt >= 3 {
							// 退避 2 秒，避免继续触发服务端保护机制；select 保证 ctx 取消时立即退出
							select {
							case <-time.After(2 * time.Second):
							case <-ctx.Done():
								return
							}

							mu.Lock()
							alreadyLocked := locked[key]
							if !alreadyLocked {
								locked[key] = true
								// 在结果里记录一条疑似账户锁定的警告
								results = append(results, BruteResult{
									Protocol: j.proto,
									Target:   fmt.Sprintf("%s:%d", j.host, j.port),
									Username: j.username,
									Password: j.password,
									Success:  false,
									ErrMsg:   "疑似账户锁定，已暂停该目标",
									FoundAt:  time.Now().Format("2006-01-02 15:04:05"),
								})
							}
							mu.Unlock()
						}
					}
					// We only persist successful results to keep DB lean.
					// Errors are not stored unless we want verbose mode.
				}
			}
		}()
	}

	wg.Wait()

	// Final progress update
	if progressFn != nil {
		progressFn(total, total, int(atomic.LoadInt64(&found)))
	}

	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// resolveList merges an explicit list with a named preset from a preset map.
func resolveList(explicit []string, preset string, presets map[string][]string) []string {
	seen := make(map[string]bool)
	var out []string

	addItem := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	if preset != "" {
		for _, v := range presets[preset] {
			addItem(v)
		}
	}
	for _, v := range explicit {
		v = strings.TrimSpace(v)
		if v != "" {
			addItem(v)
		}
	}
	return out
}

// expandTargets expands a list of raw target strings (IPs, hostnames, CIDRs, host:port)
// into individual host strings (possibly with port embedded if the user specified one).
func expandTargets(rawTargets []string) ([]string, error) {
	seen := make(map[string]bool)
	var hosts []string

	addHost := func(h string) {
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	for _, raw := range rawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		// Check if it's a CIDR
		if strings.Contains(raw, "/") && !strings.Contains(raw, ":") {
			ips, err := expandCIDR(raw)
			if err != nil {
				// Might be a hostname with path, skip
				continue
			}
			for _, ip := range ips {
				addHost(ip)
			}
			continue
		}

		// Check if it has a port specified (host:port)
		// Be careful with IPv6 addresses [::1]:port
		if strings.HasPrefix(raw, "[") {
			// IPv6 with brackets
			addHost(raw)
			continue
		}

		colonCount := strings.Count(raw, ":")
		if colonCount == 1 {
			// host:port format — keep as-is; parseHostPort will split it
			addHost(raw)
			continue
		} else if colonCount > 1 {
			// IPv6 without brackets
			addHost(raw)
			continue
		}

		// Plain hostname or IP
		addHost(raw)
	}
	return hosts, nil
}

// expandCIDR expands a CIDR block into individual IP strings.
// Skips network and broadcast addresses for /31 and larger blocks.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Count hosts
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR %s too large (>65536 hosts), refusing expansion", cidr)
	}

	var ips []string
	ip = ip.Mask(ipNet.Mask) // start at network address

	for ipNet.Contains(ip) {
		// Skip network and broadcast for IPv4 /24 and larger
		if bits == 32 && hostBits > 1 {
			// Skip network address
			if isNetworkAddr(ip, ipNet) || isBroadcastAddr(ip, ipNet) {
				ip = nextIP(ip)
				continue
			}
		}
		ips = append(ips, ip.String())
		ip = nextIP(ip)
	}
	return ips, nil
}

func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	n := binary.BigEndian.Uint32(ip)
	n++
	next := make(net.IP, 4)
	binary.BigEndian.PutUint32(next, n)
	return next
}

func isNetworkAddr(ip net.IP, ipNet *net.IPNet) bool {
	return ip.Equal(ipNet.IP)
}

func isBroadcastAddr(ip net.IP, ipNet *net.IPNet) bool {
	broadcast := make(net.IP, len(ipNet.IP))
	for i := range broadcast {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return ip.Equal(broadcast)
}

// parseHostPort splits a raw host string (which might be "host:port" or just "host")
// and determines the port using protocol default and overrides.
func parseHostPort(rawHost string, prober Prober, overrides map[string]int) (host string, port int) {
	// Try to split host:port
	if strings.HasPrefix(rawHost, "[") {
		// IPv6: [::1]:port or [::1]
		h, p, err := net.SplitHostPort(rawHost)
		if err == nil {
			pn, _ := strconv.Atoi(p)
			return h, pn
		}
		// No port, strip brackets
		host = strings.Trim(rawHost, "[]")
	} else {
		colonCount := strings.Count(rawHost, ":")
		if colonCount == 1 {
			h, p, err := net.SplitHostPort(rawHost)
			if err == nil {
				pn, _ := strconv.Atoi(p)
				return h, pn
			}
		}
		host = rawHost
	}

	// Apply port override or use protocol default
	if overrides != nil {
		if p, ok := overrides[prober.Name()]; ok {
			return host, p
		}
	}
	return host, prober.DefaultPort()
}
