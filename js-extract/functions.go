package jsextract

// functions.go — 可调用功能描述 + invoke/stop/getTask 路由实现。
//
// 对外契约（经 AEGIS 后端 /api/v1/engine/m/js-extract/* 代理）：
//   GET  /functions        列出可调用功能及参数 schema
//   POST /invoke           {taskId, function, params}：发起扫描
//   POST /stop             停止当前运行中的扫描
//   GET  /tasks/<taskId>   轮询任务进度/结果

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"

	"redops/core"
)

// 参数硬上限
const (
	maxTargets   = 20
	maxDepthHard = 3
	minTimeoutMs = 1000
	maxTimeoutMs = 60000
)

func fptr(f float64) *float64 { return &f }

var commonJSParams = []core.ParamSpec{
	{
		Name:        "targets",
		Label:       "目标 URL",
		Type:        core.ParamStringList,
		Required:    true,
		Placeholder: "每行一个目标，如 https://example.com",
		Help:        "目标 Web 应用首页或入口 URL，每行一个，最多 20 个",
	},
	{
		Name:    "maxDepth",
		Label:   "爬取深度",
		Type:    core.ParamInt,
		Default: 1,
		Min:     fptr(0),
		Max:     fptr(3),
		Help:    "0=仅爬当前页，1=跟进一级同源链接，最大 3",
	},
	{
		Name:    "timeoutMs",
		Label:   "超时 (ms)",
		Type:    core.ParamInt,
		Default: 10000,
		Min:     fptr(1000),
		Max:     fptr(60000),
		Help:    "单次 HTTP 请求超时",
	},
	{
		Name:        "cookie",
		Label:       "Cookie",
		Type:        core.ParamString,
		Placeholder: "session=abc123; token=xyz",
		Help:        "目标需要登录时填写",
	},
	{
		Name:        "auth",
		Label:       "Authorization",
		Type:        core.ParamString,
		Placeholder: "Bearer eyJhbGci...",
		Help:        "HTTP Authorization 头，支持 Bearer / Basic",
	},
}

func scanFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "scan",
			Name:        "JS 信息提取",
			Description: "爬取目标页面的 JS 文件，静态分析提取 API 端点、密钥凭据、内网地址、云存储 URL、Source Map 等敏感信息。",
			Params:      commonJSParams,
		},
		{
			ID:          "download",
			Name:        "JS 文件批量下载",
			Description: "爬取目标页面发现的所有 JS 文件，打包为 ZIP 压缩包供下载。开启全站模式可递归爬取整个域名/IP 的所有页面，收集全量 JS。",
			Params: append(commonJSParams,
				core.ParamSpec{
					Name:    "fullSite",
					Label:   "全站模式",
					Type:    core.ParamBool,
					Default: false,
					Help:    "开启后忽略爬取深度，递归遍历整个域名/IP 的所有同源页面，按最大页数封顶",
				},
				core.ParamSpec{
					Name:    "maxPages",
					Label:   "最大页数（全站模式）",
					Type:    core.ParamInt,
					Default: 200,
					Min:     fptr(10),
					Max:     fptr(2000),
					Help:    "全站模式下最多爬取的页面数，防止大型站点无限递归",
				},
			),
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": scanFunctions()})
}

type invokeRequest struct {
	TaskID   string          `json:"taskId"`
	Function string          `json:"function"`
	Params   json.RawMessage `json:"params"`
}

type scanParams struct {
	Targets   []string `json:"targets"`
	MaxDepth  int      `json:"maxDepth"`
	TimeoutMs int      `json:"timeoutMs"`
	Cookie    string   `json:"cookie"`
	Auth      string   `json:"auth"`
	FullSite  bool     `json:"fullSite"`  // 全站模式（仅 download 使用）
	MaxPages  int      `json:"maxPages"`  // 全站模式最大爬取页数
}

func fallbackTaskID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "eng-" + hex.EncodeToString(b)
}

func (m *Module) invokeFunction(w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	// 限制请求体 1 MiB，防止超大 payload 撑爆内存
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	switch req.Function {
	case "scan":
		m.invokeScan(w, req)
	case "download":
		m.invokeDownload(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

func (m *Module) invokeScan(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}

	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描任务在运行，请先停止"})
		return
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	m.cancel = cancelFn
	m.mu.Unlock()

	var params scanParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			m.mu.Lock(); m.cancel = nil; m.mu.Unlock()
			cancelFn()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}

	// ── 参数边界校验 ──────────────────────────────────────────────────
	if len(params.Targets) == 0 {
		m.mu.Lock(); m.cancel = nil; m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}
	if len(params.Targets) > maxTargets {
		params.Targets = params.Targets[:maxTargets]
	}
	if params.MaxDepth < 0 {
		params.MaxDepth = 0
	}
	if params.MaxDepth > maxDepthHard {
		params.MaxDepth = maxDepthHard
	}
	if params.TimeoutMs < minTimeoutMs {
		params.TimeoutMs = 10000
	}
	if params.TimeoutMs > maxTimeoutMs {
		params.TimeoutMs = maxTimeoutMs
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	if err := m.runs.Start(taskID, "scan"); err != nil {
		m.mu.Lock(); m.cancel = nil; m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	go func() {
		// allFindings 须在 defer 之前声明，确保 panic recover 能访问已收集的结果。
		var allFindings []Finding

		defer cancelFn() // 扫描结束时释放 ctx 资源，防止 context goroutine 泄漏
		// panic 兜底：防止 goroutine panic 导致引擎进程崩溃。
		// recover 后将已收集的 findings 落库，避免部分结果丢失。
		defer func() {
			if r := recover(); r != nil {
				m.log.Warn("scan goroutine panicked", "task", taskID, "err", r)
				if len(allFindings) > 0 {
					m.saveFindings(taskID, allFindings)
				}
				_ = m.runs.Fail(taskID, fmt.Sprintf("内部错误: %v", r))
			}
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		opts := crawlOpts{
			Targets:   params.Targets,
			MaxDepth:  params.MaxDepth,
			TimeoutMs: params.TimeoutMs,
			Cookie:    params.Cookie,
			Auth:      params.Auth,
		}

		if err := m.runs.Progress(taskID, 5, "正在爬取 JS 文件…"); err != nil {
			m.log.Warn("progress update failed", "task", taskID, "err", err)
		}

		var crawlSteps int32
		jsFiles := Crawl(ctx, opts, m.log, func(msg string) {
			n := atomic.AddInt32(&crawlSteps, 1)
			pct := 5 + int(n)*2
			if pct > 50 {
				pct = 50
			}
			_ = m.runs.Progress(taskID, pct, msg)
		})

		if ctx.Err() != nil {
			_ = m.runs.Cancel(taskID, "用户手动停止（JS 爬取阶段）")
			return
		}

		// 从 Source Map JSON 还原原始源码，扩充分析队列。
		// .map 文件的 sourcesContent 包含混淆前的 TS/JS，提取质量远高于扫混淆 bundle。
		var smExtras []JSFile
		for _, jf := range jsFiles {
			if jf.IsMap {
				smExtras = append(smExtras, ParseSourceMapContent(jf)...)
			}
		}
		if len(smExtras) > 0 {
			m.log.Info("sourcemap content extracted", "task", taskID, "files", len(smExtras))
			jsFiles = append(jsFiles, smExtras...)
		}

		_ = m.runs.Progress(taskID, 55, fmt.Sprintf("发现 %d 个 JS 文件，正在静态分析…", len(jsFiles)))

		total := len(jsFiles)
		for i, jf := range jsFiles {
			select {
			case <-ctx.Done():
				m.saveFindings(taskID, allFindings)
				_ = m.runs.Cancel(taskID, fmt.Sprintf("用户手动停止，已保存 %d 条", len(allFindings)))
				return
			default:
			}
			findings := Extract(jf, taskID)
			allFindings = append(allFindings, findings...)
			denom := total
			if denom < 1 {
				denom = 1
			}
			pct := 55 + (i+1)*40/denom
			if pct > 95 {
				pct = 95
			}
			_ = m.runs.Progress(taskID, pct, fmt.Sprintf("分析 %d/%d，发现 %d 条", i+1, total, len(allFindings)))
		}

		// 全局跨文件去重（同一 category+value 组合只保留首条），
		// 避免同一密钥/端点在 main.js 和 vendor.js 中重复命中产生冗余条目。
		// 使用独立底层数组（非 allFindings[:0]），防止 in-place 覆盖导致后半段读到已覆写的数据。
		{
			globalSeen := make(map[string]struct{}, len(allFindings))
			deduped := make([]Finding, 0, len(allFindings))
			for _, f := range allFindings {
				k := f.Category + "|" + f.Value
				if _, dup := globalSeen[k]; dup {
					continue
				}
				globalSeen[k] = struct{}{}
				deduped = append(deduped, f)
			}
			allFindings = deduped
		}

		m.saveFindings(taskID, allFindings)
		_ = m.runs.Progress(taskID, 100, fmt.Sprintf("提取完成，发现 %d 条", len(allFindings)))
		if err := m.runs.Succeed(taskID, map[string]any{
			"jsFiles":  len(jsFiles),
			"findings": len(allFindings),
		}); err != nil {
			m.log.Warn("succeed update failed", "task", taskID, "err", err)
		}
		m.log.Info("js-extract done", "task", taskID, "jsFiles", len(jsFiles), "findings", len(allFindings))
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

// invokeDownload 爬取目标所有 JS 文件并打包为 ZIP，供后续 GET /files/<taskId> 下载。
func (m *Module) invokeDownload(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}

	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有任务在运行，请先停止"})
		return
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	m.cancel = cancelFn
	m.mu.Unlock()

	var params scanParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			m.mu.Lock(); m.cancel = nil; m.mu.Unlock()
			cancelFn()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}
	if len(params.Targets) == 0 {
		m.mu.Lock(); m.cancel = nil; m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}
	if len(params.Targets) > maxTargets {
		params.Targets = params.Targets[:maxTargets]
	}
	if params.MaxDepth < 0 { params.MaxDepth = 0 }
	if params.MaxDepth > maxDepthHard { params.MaxDepth = maxDepthHard }
	if params.TimeoutMs < minTimeoutMs { params.TimeoutMs = 10000 }
	if params.TimeoutMs > maxTimeoutMs { params.TimeoutMs = maxTimeoutMs }

	taskID := req.TaskID
	if taskID == "" { taskID = fallbackTaskID() }
	if err := m.runs.Start(taskID, "download"); err != nil {
		m.mu.Lock(); m.cancel = nil; m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	go func() {
		defer cancelFn()
		defer func() {
			if r := recover(); r != nil {
				m.log.Warn("download goroutine panicked", "task", taskID, "err", r)
				_ = m.runs.Fail(taskID, fmt.Sprintf("内部错误: %v", r))
			}
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
			_ = m.runs.Fail(taskID, "创建数据目录失败: "+err.Error())
			return
		}

		_ = m.runs.Progress(taskID, 5, "正在爬取 JS 文件…")

		opts := crawlOpts{
			Targets:   params.Targets,
			MaxDepth:  params.MaxDepth,
			TimeoutMs: params.TimeoutMs,
			Cookie:    params.Cookie,
			Auth:      params.Auth,
			FullSite:  params.FullSite,
			MaxPages:  params.MaxPages,
		}

		var crawlSteps int32
		jsFiles := Crawl(ctx, opts, m.log, func(msg string) {
			n := atomic.AddInt32(&crawlSteps, 1)
			pct := 5 + int(n)*2
			if pct > 70 { pct = 70 }
			_ = m.runs.Progress(taskID, pct, msg)
		})

		if ctx.Err() != nil {
			_ = m.runs.Cancel(taskID, "用户手动停止")
			return
		}

		total := len(jsFiles)
		_ = m.runs.Progress(taskID, 72, fmt.Sprintf("发现 %d 个 JS 文件，正在打包…", total))

		zipPath := filepath.Join(m.dataDir, taskID+".zip")
		f, err := os.Create(zipPath)
		if err != nil {
			_ = m.runs.Fail(taskID, "创建 ZIP 失败: "+err.Error())
			return
		}
		zw := zip.NewWriter(f)

		for i, jf := range jsFiles {
			if ctx.Err() != nil {
				_ = zw.Close()
				_ = f.Close()
				_ = os.Remove(zipPath)
				_ = m.runs.Cancel(taskID, fmt.Sprintf("用户手动停止，已打包 %d/%d", i, total))
				return
			}
			entry, zeErr := zw.Create(zipEntryName(jf.URL, i))
			if zeErr != nil {
				continue
			}
			_, _ = io.WriteString(entry, jf.Content)
			denom := total
			if denom < 1 { denom = 1 }
			pct := 72 + (i+1)*23/denom
			if pct > 95 { pct = 95 }
			_ = m.runs.Progress(taskID, pct, fmt.Sprintf("打包 %d/%d…", i+1, total))
		}

		if err := zw.Close(); err != nil {
			_ = f.Close()
			_ = m.runs.Fail(taskID, "ZIP 写入失败: "+err.Error())
			return
		}
		_ = f.Close()

		stat, _ := os.Stat(zipPath)
		var zipSize int64
		if stat != nil { zipSize = stat.Size() }

		_ = m.runs.Progress(taskID, 100, fmt.Sprintf("打包完成，共 %d 个文件", total))
		_ = m.runs.Succeed(taskID, map[string]any{
			"jsFiles": total,
			"zipSize": zipSize,
		})
		m.log.Info("js-download done", "task", taskID, "files", total, "bytes", zipSize)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

// serveFiles 流式返回指定任务打包好的 ZIP 文件（GET /files/<taskId>）。
func (m *Module) serveFiles(w http.ResponseWriter, r *http.Request) {
	taskID := path.Base(r.URL.Path)
	if taskID == "" || taskID == "." || taskID == "/" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 taskId"})
		return
	}
	zipPath := filepath.Join(m.dataDir, taskID+".zip")
	f, err := os.Open(zipPath)
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "文件不存在，任务可能尚未完成"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer f.Close()
	stat, _ := f.Stat()
	suffix := taskID
	if len(suffix) > 8 { suffix = suffix[:8] }
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="js-files-`+suffix+`.zip"`)
	if stat != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	}
	_, _ = io.Copy(w, f)
}

// zipEntryName 将 JS 文件 URL 转换为 ZIP 内的相对路径（host/path 结构）。
func zipEntryName(rawURL string, idx int) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Sprintf("file_%04d.js", idx)
	}
	p := strings.Trim(u.Path, "/")
	if p == "" {
		p = "index.js"
	}
	// 内联脚本 fragment 追加到文件名
	if u.Fragment != "" {
		base := filepath.Base(p)
		dir := filepath.Dir(p)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		frag := strings.ReplaceAll(u.Fragment, "/", "_")
		if ext == "" { ext = ".js" }
		p = filepath.Join(dir, stem+"_"+frag+ext)
	}
	name := u.Host + "/" + p
	// 无扩展名时补 .js
	if ext := filepath.Ext(filepath.Base(name)); ext == "" {
		name += ".js"
	}
	return name
}

func (m *Module) stopScan(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stopped": false, "msg": "无运行中的任务"})
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
}

func (m *Module) getTask(w http.ResponseWriter, r *http.Request) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	id := path.Base(r.URL.Path)
	t, ok, err := m.runs.Get(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}
