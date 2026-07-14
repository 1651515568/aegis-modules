package vulnscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── 运行时 favicon 学习 ────────────────────────────────────────────────────────
// 当引擎通过 body/header/title 匹配识别产品后，异步抓取 /favicon.ico 计算 hash。
// 结果写入 data/learned_favicons.json，下次引擎启动时自动合并进规则，
// 使指纹库随扫描积累持续丰富（无需重新编译）。

var (
	learnedMu    sync.Mutex
	learnedMap   = map[string][]string{}
	learnedDirty bool
)

func learnedFilePath() string {
	return filepath.Join("data", "learned_favicons.json")
}

// loadLearnedFavicons 在 loadFPRules 的 sync.Once 内调用，把磁盘学习数据合并进规则切片。
func loadLearnedFavicons(rules []fpRule) {
	data, err := os.ReadFile(learnedFilePath())
	if err != nil {
		return
	}
	var m map[string][]string
	if json.Unmarshal(data, &m) != nil {
		return
	}

	// 建产品名 → 规则下标索引（小写）
	idx := make(map[string]int, len(rules))
	for i, r := range rules {
		idx[strings.ToLower(r.Name)] = i
	}

	for name, hashes := range m {
		ri, ok := idx[strings.ToLower(name)]
		if !ok {
			continue
		}
		// 收集已有 favicon hash，避免重复
		existing := map[string]bool{}
		for _, p := range rules[ri].Probes {
			for _, mat := range p.Matchers {
				if mat.Type == "favicon" {
					for _, h := range mat.Favicon {
						existing[h] = true
					}
				}
			}
		}
		var fresh []string
		for _, h := range hashes {
			if !existing[h] {
				fresh = append(fresh, h)
				existing[h] = true
			}
		}
		if len(fresh) > 0 {
			rules[ri].Probes = append(rules[ri].Probes, fpProbe{
				Path:   "/favicon.ico",
				Method: "GET",
				Matchers: []fpMatcher{
					{Type: "favicon", Favicon: fresh},
				},
			})
		}
	}

	learnedMu.Lock()
	learnedMap = m
	learnedMu.Unlock()
}

// learnFavicons 异步：对本次扫描中通过 body/header/title 匹配到的产品，
// 额外抓 /favicon.ico，计算 murmur3 hash 并记录，供下次启动合并。
func learnFavicons(ctx context.Context, client *http.Client, baseURL string, products []fpProduct) {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx2, "GET", baseURL+"/favicon.ico", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if len(body) < 64 {
		return
	}

	hashStr := computeFaviconHash(body)

	learnedMu.Lock()
	changed := false
	for _, prod := range products {
		existing := learnedMap[prod.Name]
		found := false
		for _, h := range existing {
			if h == hashStr {
				found = true
				break
			}
		}
		if !found {
			learnedMap[prod.Name] = append(learnedMap[prod.Name], hashStr)
			changed = true
		}
	}
	if changed {
		learnedDirty = true
	}
	learnedMu.Unlock()

	if changed {
		flushLearnedFavicons()
	}
}

// flushLearnedFavicons 将 learnedMap 写入 data/learned_favicons.json。
func flushLearnedFavicons() {
	learnedMu.Lock()
	if !learnedDirty {
		learnedMu.Unlock()
		return
	}
	snapshot := make(map[string][]string, len(learnedMap))
	for k, v := range learnedMap {
		cp := make([]string, len(v))
		copy(cp, v)
		snapshot[k] = cp
	}
	learnedDirty = false
	learnedMu.Unlock()

	p := learnedFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, data, 0o644)
}
