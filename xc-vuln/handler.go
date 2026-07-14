package xcvuln

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"redops/core"
)

// Routes 声明业务 HTTP 路由，框架自动挂载到 /api/m/xc-vuln/...
func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET",  Path: "/templates", Handler: m.listTemplates, Permission: "xcvuln:view"},
		{Method: "GET",  Path: "/stats",     Handler: m.getStats,      Permission: "xcvuln:view"},
		{Method: "POST", Path: "/verify",    Handler: m.verify,        Permission: "xcvuln:view"},
		{Method: "POST", Path: "/reload",    Handler: m.reloadCache,   Permission: "xcvuln:view"},
	}
}

// nuclei 候选路径
var nucleiBins = []string{
	"data/vuln-scan/bin/nuclei-linux-amd64", // vuln-scan 模块释放的内嵌 nuclei
	"/home/sshuser/.local/bin/nuclei",
	"/usr/local/bin/nuclei",
	"/usr/bin/nuclei",
	"nuclei",
}

func findNuclei() (string, error) {
	for _, p := range nucleiBins {
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("nuclei 未找到，请先安装或启用漏洞扫描模块")
}

// ── 数据模型 ─────────────────────────────────────────────────────────────────

type nucleiInfo struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Tags        string `yaml:"tags"`
}

type nucleiTpl struct {
	ID   string     `yaml:"id"`
	Info nucleiInfo `yaml:"info"`
}

type TemplateItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      string   `json:"author"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Category    string   `json:"category"`
	SubCategory string   `json:"subCategory"`
	File        string   `json:"file"`
}

type verifyReq struct {
	Target       string `json:"target"`
	TemplateFile string `json:"templateFile"`
}

type nucleiHit struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	Request   string `json:"request"`
	Response  string `json:"response"`
	CurlCmd   string `json:"curl-command"`
}

type verifyResult struct {
	Found    bool   `json:"found"`
	Output   string `json:"output"`
	Request  string `json:"request"`
	Response string `json:"response"`
	CurlCmd  string `json:"curlCmd"`
	ErrMsg   string `json:"error,omitempty"`
}

// ── 核心逻辑 ─────────────────────────────────────────────────────────────────

// resolveTemplateDir 优先返回模块目录内的路径，不存在则回退到 home 目录。
func resolveTemplateDir(modRel, homeName string) string {
	if info, err := os.Stat(modRel); err == nil && info.IsDir() {
		return modRel
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, homeName)
	}
	return homeName
}

// loadTemplates 遍历模板目录，解析所有 yaml 文件（结果由缓存层持有，勿直接调用）。
func (m *Module) loadTemplates() []TemplateItem {
	root := resolveTemplateDir("modules/xc-vuln/xinchuang-templates", "xinchuang-templates")
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}

	var items []TemplateItem
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var tpl nucleiTpl
		if err := yaml.Unmarshal(data, &tpl); err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		cat, sub := "", ""
		if len(parts) >= 1 {
			cat = parts[0]
		}
		if len(parts) >= 2 {
			sub = parts[1]
		}
		var tags []string
		for _, t := range strings.Split(tpl.Info.Tags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
		name := tpl.Info.Name
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(path), ".yaml")
		}
		items = append(items, TemplateItem{
			ID: tpl.ID, Name: name, Author: tpl.Info.Author,
			Severity:    strings.ToLower(tpl.Info.Severity),
			Description: tpl.Info.Description,
			Tags: tags, Category: cat, SubCategory: sub,
			File: filepath.ToSlash(rel),
		})
		return nil
	})
	if items == nil {
		items = []TemplateItem{}
	}
	return items
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// catStat 用于 /stats 返回的分类树（含子分类计数）。
type catStat struct {
	Total int            `json:"total"`
	Subs  map[string]int `json:"subs"`
}

func (m *Module) listTemplates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("pageSize"))
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 50
	}
	if page < 0 {
		page = 0
	}

	category    := q.Get("category")
	subCategory := q.Get("subCategory")
	severity    := q.Get("severity")
	search      := strings.ToLower(strings.TrimSpace(q.Get("search")))

	all := m.getTemplates()

	// 按条件过滤（全部在内存缓存中完成，无磁盘 IO）
	filtered := make([]TemplateItem, 0, len(all))
	for _, t := range all {
		if category != "" && t.Category != category {
			continue
		}
		if subCategory != "" && t.SubCategory != subCategory {
			continue
		}
		if severity != "" && t.Severity != severity {
			continue
		}
		if search != "" {
			hit := strings.Contains(strings.ToLower(t.Name), search) ||
				strings.Contains(strings.ToLower(t.ID), search) ||
				strings.Contains(strings.ToLower(t.Description), search)
			if !hit {
				for _, tag := range t.Tags {
					if strings.Contains(strings.ToLower(tag), search) {
						hit = true
						break
					}
				}
			}
			if !hit {
				continue
			}
		}
		filtered = append(filtered, t)
	}

	total := len(filtered)
	start := page * pageSize
	if start >= total {
		start = 0
		page = 0
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"templates": filtered[start:end],
		"total":     total,
		"page":      page,
		"pageSize":  pageSize,
	})
}

func (m *Module) getStats(w http.ResponseWriter, _ *http.Request) {
	items := m.getTemplates()
	cats := map[string]*catStat{}
	sevs := map[string]int{}
	for _, t := range items {
		if _, ok := cats[t.Category]; !ok {
			cats[t.Category] = &catStat{Subs: map[string]int{}}
		}
		cats[t.Category].Total++
		cats[t.Category].Subs[t.SubCategory]++
		sevs[t.Severity]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": len(items), "categories": cats, "severities": sevs,
	})
}

// reloadCache 强制重建模板缓存（POST /reload）。
func (m *Module) reloadCache(w http.ResponseWriter, _ *http.Request) {
	go m.rebuildCache()
	writeJSON(w, http.StatusOK, map[string]any{"message": "缓存重建已启动，稍后刷新页面即可"})
}

func (m *Module) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求解析失败: " + err.Error()})
		return
	}
	if req.Target == "" || req.TemplateFile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target 和 templateFile 不能为空"})
		return
	}

	bin, err := findNuclei()
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResult{ErrMsg: err.Error()})
		return
	}

	// 用 resolveTemplateDir 查找模板，兼容模块目录和 home 目录
	tplRoot := resolveTemplateDir("modules/xc-vuln/xinchuang-templates", "xinchuang-templates")
	tplPath := filepath.Join(tplRoot, filepath.FromSlash(req.TemplateFile))
	if _, err := os.Stat(tplPath); err != nil {
		writeJSON(w, http.StatusOK, verifyResult{ErrMsg: "模板文件不存在: " + req.TemplateFile})
		return
	}

	tmpf, err := os.CreateTemp("", "xcvuln-*.txt")
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResult{ErrMsg: "临时文件失败: " + err.Error()})
		return
	}
	fmt.Fprintln(tmpf, req.Target)
	tmpf.Close()
	defer os.Remove(tmpf.Name())

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	args := []string{
		"-list", tmpf.Name(),
		"-t", tplPath,
		"-jsonl", "-silent", "-no-color",
		"-timeout", "15", "-retries", "1",
		"-rate-limit", "50",
	}

	m.log.Info("xc-vuln verify", "target", req.Target, "template", req.TemplateFile)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"))
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusOK, verifyResult{ErrMsg: "启动 nuclei 失败: " + err.Error()})
		return
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var hits []nucleiHit
	for sc.Scan() {
		var h nucleiHit
		if json.Unmarshal(sc.Bytes(), &h) == nil {
			hits = append(hits, h)
		}
	}
	_ = cmd.Wait()

	result := verifyResult{}
	if len(hits) > 0 {
		h := hits[0]
		result.Found = true
		result.Output = fmt.Sprintf("[%s] %s ⇒ %s", strings.ToUpper(h.Info.Severity), h.Info.Name, h.MatchedAt)
		result.CurlCmd = h.CurlCmd
		if len(h.Request) > 4096 {
			result.Request = h.Request[:4096] + "…"
		} else {
			result.Request = h.Request
		}
		if len(h.Response) > 4096 {
			result.Response = h.Response[:4096] + "…"
		} else {
			result.Response = h.Response
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
