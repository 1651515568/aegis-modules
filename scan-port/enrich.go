package portscan

// enrich.go —— 对已发现的开放端口做二次 connect 抓 banner(SYN/masscan 发现后的服务识别阶段)。
// SYN 半开 / masscan 只确认端口开放、不建立完整连接,故无 banner;这里对开放端口逐个轻量
// connect + grabBanner(复用 banner.go 的 TLS 证书 / HTTP 标题逻辑),回填服务名与 banner。

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// enrichBanners 并发地为 ports 抓取 banner 并回填到 store。
func (m *Module) enrichBanners(ctx context.Context, ports []Port, opt scanOptions, timeout time.Duration) {
	conc := opt.Concurrency
	if conc <= 0 {
		conc = 64 // 默认值
	}
	if conc > len(ports) {
		conc = len(ports)
	}
	if conc < 1 {
		return
	}
	lim := newRateLimiter(opt.Rate)
	jobs := make(chan Port, conc)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() != nil {
					return // ctx 已取消，直接退出，不再消费剩余 jobs
				}
				if lim.wait(ctx) != nil {
					return
				}
				m.grabPortBanner(ctx, p, timeout, opt)
			}
		}()
	}
	for _, p := range ports {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
}

func (m *Module) grabPortBanner(ctx context.Context, p Port, timeout time.Duration, opt scanOptions) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return // 端口可能已不可达,保留发现阶段结果
	}
	defer conn.Close()
	banner := grabBanner(conn, p.Host, p.Port, timeout)
	svc := ""
	if opt.Svc {
		if g := guessFromBanner(banner); g != "" {
			svc = g
		}
	}
	// 从 banner 推断 OS（仅在 SYN 扫描未提供 OsGuess 时补充）
	osGuess := guessOSFromBanner(banner)
	m.store.updatePort(p.Host, p.Port, svc, banner, osGuess)
}
