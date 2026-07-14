package backup

// extdict.go —— 外部字典加载：内嵌优先，自定义 URL 回退网络下载+磁盘缓存。
//
// 优先级:
//   1. embeddedPreset(name) — 内嵌二进制（raft-medium-files、raft-medium-dirs），离线可用
//   2. 磁盘缓存              — data/backup/dicts/<url-sha256前8字节>.txt
//   3. HTTP 下载            — 仅自定义 URL / 未内嵌的预设名；下载成功后写盘缓存
//
// 安全上限：单文件 20 MB（约 100 万行），超限截断；下载超时 90s。

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	extDictCacheDir = "data/backup/dicts"
	extDictTimeout  = 90 * time.Second
	extDictMaxBytes = 20 * 1024 * 1024 // 20 MB
)

// presetWordlists 预置「需网络下载」的字典 URL。
// 已内嵌二进制的预设（raft-medium-files、raft-medium-dirs）不在此表，
// LoadExternalDict 会优先走 embeddedPreset()，无需下载。
var presetWordlists = map[string]string{
	"raft-large-files":        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt",
	"raft-medium-directories": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
	"raft-large-directories":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
	"dirsearch":               "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dirsearch.txt",
}

// PresetWordlistKeys 返回所有预置名，供 functions.go ParamSelect 选项构建。
func PresetWordlistKeys() []string {
	keys := make([]string, 0, len(presetWordlists))
	for k := range presetWordlists {
		keys = append(keys, k)
	}
	return keys
}

// resolveWordlistURL 将预设名解析为 URL；若已是 http(s):// 则原样返回。
func resolveWordlistURL(nameOrURL string) string {
	nameOrURL = strings.TrimSpace(nameOrURL)
	if nameOrURL == "" {
		return ""
	}
	if u, ok := presetWordlists[nameOrURL]; ok {
		return u
	}
	if strings.HasPrefix(nameOrURL, "http://") || strings.HasPrefix(nameOrURL, "https://") {
		return nameOrURL
	}
	return "" // 无效输入
}

// cachePathFor 按 URL 的 sha256 前 8 字节生成缓存文件路径。
func cachePathFor(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return filepath.Join(extDictCacheDir, fmt.Sprintf("%x.txt", h[:8]))
}

// makeExtDictClient 为外部字典下载构造独立 HTTP 客户端，支持代理和自签证书。
// 与扫描器的 buildClient 隔离，避免共用超时/CheckRedirect 等扫描专属配置。
func makeExtDictClient(proxy string) *http.Client {
	proxyFn := http.ProxyFromEnvironment
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil && pu.Host != "" {
			proxyFn = http.ProxyURL(pu)
		}
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           proxyFn,
	}
	return &http.Client{Timeout: extDictTimeout, Transport: tr}
}

// LoadExternalDict 加载外部字典。
//
//   - nameOrURL：预置名（raft-medium-files / raft-medium-dirs）或完整 https:// URL
//   - proxy：上游代理地址（空串 = 使用系统环境变量代理）
//   - log：用于打印进度；可传 nil（静默）
//
// 优先级：内嵌 → 磁盘缓存 → 网络下载（成功后写盘）。
// 返回去注释后的词条列表；失败返回 nil + error（调用方决定是否致命）。
func LoadExternalDict(ctx context.Context, nameOrURL string, proxy string, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) ([]string, error) {
	nameOrURL = strings.TrimSpace(nameOrURL)
	if nameOrURL == "" {
		return nil, fmt.Errorf("extdict: 空字典名或 URL")
	}

	// ── 1. 内嵌预置（离线可用，无需下载）──
	if lines, ok := embeddedPreset(nameOrURL); ok {
		if log != nil {
			log.Info("extdict loaded from embedded", "preset", nameOrURL, "entries", len(lines))
		}
		return lines, nil
	}

	// ── 2. 解析预置名 → URL ──
	rawURL := resolveWordlistURL(nameOrURL)
	if rawURL == "" {
		return nil, fmt.Errorf("extdict: 无法识别的字典名或 URL: %q", nameOrURL)
	}

	cachePath := cachePathFor(rawURL)

	// ── 3. 磁盘缓存 ──
	if data, err := os.ReadFile(cachePath); err == nil {
		lines := parseList(string(data))
		if log != nil {
			log.Info("extdict loaded from cache", "url", rawURL, "entries", len(lines), "cache", cachePath)
		}
		return lines, nil
	}

	// ── 4. 网络下载 ──
	if log != nil {
		log.Info("extdict downloading", "url", rawURL)
	}
	// 用独立的 context.Background() 派生下载 ctx，使字典下载不受扫描总时长限制影响。
	// 若使用扫描 ctx，MaxDurationSec 到期会提前截断字典下载，导致字典被静默跳过、漏报。
	dlCtx, cancel := context.WithTimeout(context.Background(), extDictTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("extdict build request: %w", err)
	}
	req.Header.Set("User-Agent", scanUserAgent)

	dlClient := makeExtDictClient(proxy)
	resp, err := dlClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("extdict download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("extdict download HTTP %d: %s", resp.StatusCode, rawURL)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, extDictMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("extdict read body: %w", err)
	}

	// ── 5. 写磁盘缓存（失败不致命）──
	if mkErr := os.MkdirAll(extDictCacheDir, 0o755); mkErr == nil {
		if wErr := os.WriteFile(cachePath, data, 0o644); wErr == nil && log != nil {
			log.Info("extdict cached", "url", rawURL, "bytes", len(data), "cache", cachePath)
		}
	}

	lines := parseList(string(data))
	if log != nil {
		log.Info("extdict downloaded", "url", rawURL, "entries", len(lines))
	}
	return lines, nil
}
