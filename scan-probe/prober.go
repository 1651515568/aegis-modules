package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"redops/core"
)

// ProbeResult is the output record for a single HTTP fingerprint probe.
type ProbeResult struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	CMS         string   `json:"cms"`
	Framework   string   `json:"framework"`
	WAF         string   `json:"waf"`
	Server      string   `json:"server"`
	Title       string   `json:"title"`
	StatusCode  int      `json:"statusCode"`
	OS          string   `json:"os"`
	FaviconHash int32    `json:"faviconHash,omitempty"`
	Components  []string `json:"components,omitempty"` // all matched tech-stack items
}

// scanOptions mirrors the frontend form parameters.
type scanOptions struct {
	Targets   []string `json:"targets"`
	Threads   int      `json:"threads"`
	TimeoutMs int      `json:"timeoutMs"`
	DetectWAF bool     `json:"detectWaf"`
	DetectCMS bool     `json:"detectCms"`
}

type prober struct {
	log core.Logger
}

func newProber(log core.Logger) *prober { return &prober{log: log} }

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]{0,256})</title>`)

func (p *prober) run(ctx context.Context, opts scanOptions, progressFn func(done, total int)) ([]ProbeResult, error) {
	if len(opts.Targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	threads := opts.Threads
	if threads <= 0 {
		threads = 20
	}
	if threads > 200 {
		threads = 200
	}
	timeoutMs := opts.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(timeoutMs/2) * time.Millisecond,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var (
		mu      sync.Mutex
		results []ProbeResult
		done    int
	)
	total := len(opts.Targets)
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, t := range opts.Targets {
		// 将发送信号量与 ctx 取消合并为一个 select，确保停止信号能立即退出循环
		select {
		case <-ctx.Done():
			wg.Wait()
			return results, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(target string) {
			defer func() { <-sem; wg.Done() }()
			r := p.probeOne(ctx, client, target, opts)
			mu.Lock()
			// StatusCode=0 表示所有 scheme 均连接失败，不写入结果切片，
			// 避免空白占位数据污染进度统计和后续 saveFindings。
			if r.StatusCode > 0 {
				results = append(results, r)
			}
			done++
			if progressFn != nil {
				progressFn(done, total)
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func (p *prober) probeOne(ctx context.Context, client *http.Client, target string, opts scanOptions) ProbeResult {
	// Normalise target: if no scheme, try http first, fall back to https.
	schemes := []string{}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		schemes = []string{target}
	} else {
		// Heuristic: port 443 in the raw string → try https first.
		if strings.Contains(target, ":443") {
			schemes = []string{"https://" + target, "http://" + target}
		} else {
			schemes = []string{"http://" + target, "https://" + target}
		}
	}

	blank := ProbeResult{CMS: "—", Framework: "—", WAF: "无", OS: "—"}

	for _, rawURL := range schemes {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := u.Hostname()
		port := 80
		if ps := u.Port(); ps != "" {
			fmt.Sscanf(ps, "%d", &port) //nolint:errcheck
		} else if u.Scheme == "https" {
			port = 443
		}

		result := ProbeResult{
			Host: host, Port: port, Protocol: u.Scheme,
			CMS: "—", Framework: "—", WAF: "无", OS: "—",
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			p.log.Warn("probe failed", "target", rawURL, "err", err)
			continue // try next scheme
		}
		result.StatusCode = resp.StatusCode
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		bodyStr := string(body)

		if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			result.Title = strings.TrimSpace(m[1])
		}

		fp := runFingerprint(resp.Header, bodyStr, opts.DetectCMS, opts.DetectWAF)
		result.Server = fp.server
		result.OS = fp.os
		result.Framework = fp.framework
		result.WAF = fp.waf
		result.CMS = fp.cms

		// Favicon hash fingerprinting — only run when CMS not already identified.
		if opts.DetectCMS && result.CMS == "—" {
			baseURL := u.Scheme + "://" + u.Host
			faviconTimeout := opts.TimeoutMs / 2
			if faviconTimeout < 1000 {
				faviconTimeout = 1000
			}
			// 用 context timeout 限制 favicon 请求时间，复用已有 client，避免重复建连接池。
			faviconCtx, faviconCancel := context.WithTimeout(ctx, time.Duration(faviconTimeout)*time.Millisecond)
			h, product := probeFavicon(faviconCtx, client, baseURL)
			faviconCancel()
			if product != "" {
				result.CMS = product
				result.FaviconHash = h
			}
		}

		// Build Components: all matched products + framework (deduplicated).
		if opts.DetectCMS {
			seen := make(map[string]bool)
			for _, p := range fp.products {
				if !seen[p] {
					seen[p] = true
					result.Components = append(result.Components, p)
				}
			}
			// If favicon matched a product that's not already in products list, add it.
			if result.CMS != "—" && !seen[result.CMS] {
				seen[result.CMS] = true
				result.Components = append(result.Components, result.CMS)
			}
			if fp.framework != "—" && !seen[fp.framework] {
				result.Components = append(result.Components, fp.framework)
			}
		}

		// Multi-path probing: probe login pages, admin panels, API docs, etc. to
		// surface products that only expose fingerprints at specific paths.
		// Also runs active probes (Shiro cookie injection, Actuator JSON check, etc.)
		if opts.DetectCMS {
			multiPathProbe(ctx, client, u.Scheme+"://"+u.Host, &result, opts)
		}

		return result
	}
	// All schemes failed.
	blank.Host = target
	return blank
}
