package backup

// functions.go —— 模块「可调用功能」自描述 + 通用 invoke/task 入口。
//
// 对外契约（经 AEGIS 后端 /api/v1/engine/m/scan-backup/* 代理）：
//   GET  /functions            列出本模块可调用功能及参数 schema（前端据此渲染表单）
//   POST /invoke               {taskId, function, params}：用「系统签发」的 taskId 发起调用
//   GET  /tasks/<taskId>       轮询任务进度/结果（读自持久化 task_runs 表）
//   GET  /findings?taskId=<id> 取某次任务归档的命中（读自 m_scan_backup_findings 表）
//
// 统一 task_id 契约：taskId 由 AEGIS 后端统一签发并透传进来，模块「不再自造 id」，
// 执行过程把状态/进度/结果落到 SQLite(按 task_id 主键)，系统据 task_id 即可取回，
// 不依赖前端是否在轮询。实现上复用既有 scanner，不改扫描核心逻辑。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"time"

	"redops/core"
)

func fptr(f float64) *float64 { return &f }

// backupFunctions 声明本模块对外可调用的功能目录。
func backupFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "scan",
			Name:        "备份/敏感文件探测",
			Description: "对目标做备份、源码、配置等敏感文件的存在性探测（仅 HEAD/Range，绝不下载文件体）。",
			Params: []core.ParamSpec{
				{
					Name: "targets", Label: "目标列表", Type: core.ParamStringList, Required: true,
					Placeholder: "每行一个 http(s) URL 或域名", Help: "支持多目标，每行一个",
				},
				{
					Name: "concurrency", Label: "并发数", Type: core.ParamInt, Default: 30,
					Min: fptr(1), Max: fptr(128), Help: "默认 30（HEAD 请求轻量，可调高）；上限 128",
				},
				{
					Name: "ratePerSec", Label: "限速 (req/s)", Type: core.ParamFloat, Default: 50,
					Min: fptr(0), Max: fptr(500), Help: "全局请求限速，0 表示不限速，上限 500；默认 50",
				},
				{
					Name: "maxDepth", Label: "递归深度", Type: core.ParamInt, Default: 2,
					Min: fptr(0), Max: fptr(3), Help: "目录递归发现深度，默认 2（两层覆盖更全）；0 关闭递归",
				},
				{
					Name: "includeEditor", Label: "编辑器遗留后缀", Type: core.ParamBool, Default: true,
					Help: "对已知文件追加 .bak/.old/~/.swp 等编辑器残留后缀，默认开启",
				},
				{
					Name: "crawl", Label: "智能爬取", Type: core.ParamBool, Default: false,
					Help: "提取真实文件名/目录派生候选，命中率更高但更慢",
				},
				{
					Name:        "cookie",
					Label:       "Cookie",
					Type:        core.ParamString,
					Default:     "",
					Placeholder: "PHPSESSID=abc123; token=xyz",
					Help:        "目标需要登录时填写；格式与浏览器请求头相同",
				},
				{
					Name:        "authorization",
					Label:       "Authorization",
					Type:        core.ParamString,
					Default:     "",
					Placeholder: "Bearer eyJhbGci... 或 Basic dXNlcjpwYXNz",
					Help:        "HTTP Authorization 头值，支持 Bearer Token / Basic Auth",
				},
				{
					Name:        "proxy",
					Label:       "上游代理",
					Type:        core.ParamString,
					Default:     "",
					Placeholder: "http://127.0.0.1:8080 或 socks5://127.0.0.1:1080",
					Help:        "经 Burp/SOCKS 代理转发全部探测流量；留空则使用系统环境变量代理",
				},
				{
					Name:    "extraWordlist",
					Label:   "扩展字典",
					Type:    core.ParamSelect,
					Default: "",
					Options: []core.ParamOption{
						{Value: "", Label: "不使用"},
						{Value: "raft-medium-files", Label: "内置 raft-medium-files（精选常见文件名，离线可用）"},
						{Value: "raft-medium-dirs", Label: "内置 raft-medium-dirs（精选常见目录名，离线可用）"},
						{Value: "raft-large-files", Label: "下载 SecLists raft-large-files（约 3.7 万条）"},
						{Value: "raft-medium-directories", Label: "下载 SecLists raft-medium-directories（约 2.6 万条）"},
						{Value: "dirsearch", Label: "下载 dirsearch 内置字典（约 1 万条）"},
						{Value: "custom", Label: "下载自定义 URL（填写下方地址）"},
					},
					Help: "内置字典已嵌入二进制，无需网络；下载型字典首次拉取后缓存到 data/backup/dicts/",
				},
				{
					Name:        "extraWordlistURL",
					Label:       "自定义字典 URL",
					Type:        core.ParamString,
					Default:     "",
					Placeholder: "https://example.com/wordlist.txt",
					Help:        "仅「下载自定义 URL」档位生效；需为可直接 GET 的纯文本（每行一条路径）",
				},
				{
					Name:        "customWordlistText",
					Label:       "自定义字典（粘贴）",
					Type:        core.ParamStringList,
					Default:     "",
					Placeholder: "每行一条路径，如 admin/config.php",
					Help:        "直接粘贴路径列表，与扩展字典叠加使用；去重由引擎自动处理",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": backupFunctions()})
}

type invokeRequest struct {
	TaskID    string          `json:"taskId"`              // 系统签发的任务 id(统一台账主键)
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"` // 仅用于日志/上下文，引擎不做项目鉴权
}

// fallbackTaskID 仅用于直连引擎调试(未经后端签发 taskId)时兜底，避免无主键无法落库。
// 正常链路 taskId 必由 AEGIS 后端透传。
func fallbackTaskID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "eng-" + hex.EncodeToString(b)
}

func (m *Module) invokeFunction(w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	switch req.Function {
	case "scan":
		m.invokeScan(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

// invokeScan 把一次扫描包装成可轮询任务。同一时刻只允许一个扫描在跑。
// taskId 由系统签发并透传：状态/进度/结果按 taskId 落 SQLite，跨页面/重启不丢。
func (m *Module) invokeScan(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪，无法登记任务"})
		return
	}
	var opt scanOptions
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &opt); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}
	if len(opt.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空（需为 http(s) URL 或域名）"})
		return
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}

	// 原子地检查+设置运行态（防止并发双启动 TOCTOU）
	ctx, cancel := context.WithCancel(context.Background())
	if !m.store.tryBeginScan("(解析中…)", false) {
		cancel()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描在运行，请先停止或等待完成"})
		return
	}
	if err := m.runs.Start(taskID, "scan"); err != nil {
		cancel()
		m.store.finishScan("登记任务失败: " + err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}
	m.store.setCancel(cancel)

	go func() {
		defer m.runs.GuardPanic(taskID, m.log)
		defer cancel()
		m.store.setJob(&scanJob{Opts: opt, Status: "running", StartedAt: nowStamp()})

		// 进度观察 goroutine：把 store 的实时扫描状态镜像成持久化任务进度。
		done := make(chan struct{})
		defer close(done)
		go func() {
			t := time.NewTicker(600 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					st := m.store.status()
					p := 0
					if st.Total > 0 {
						p = st.Probed * 100 / st.Total
					}
					_ = m.runs.Progress(taskID, p, fmt.Sprintf("已探测 %d/%d，命中 %d", st.Probed, st.Total, st.Found))
				}
			}
		}()

		m.sc.run(ctx, opt) // 阻塞至扫描结束/取消

		st := m.store.status()
		jobSt := m.store.jobStatus()

		// 无论成功/取消/超时，先落库命中，保证历史任务里始终有数据。
		m.saveFindings(taskID)

		switch {
		case jobSt == "canceled":
			// 用户主动取消：标记 canceled（区别于失败，结果已保存）。
			_ = m.runs.Cancel(taskID, fmt.Sprintf("用户已取消，已保存命中 %d 条", st.Found))
		case jobSt == "timeout":
			// 超时停止也算部分成功，结果已保存。
			_ = m.runs.Progress(taskID, 100, fmt.Sprintf("已达时限，命中 %d 条", st.Found))
			_ = m.runs.Succeed(taskID, map[string]any{
				"found":  st.Found,
				"probed": st.Probed,
				"total":  st.Total,
				"target": st.Target,
				"note":   "已达扫描时长上限，结果已保存",
			})
		case st.Err == "":
			// 正常完成。
			_ = m.runs.Progress(taskID, 100, fmt.Sprintf("扫描完成，命中 %d 条", st.Found))
			_ = m.runs.Succeed(taskID, map[string]any{
				"found":  st.Found,
				"probed": st.Probed,
				"total":  st.Total,
				"target": st.Target,
			})
		default:
			// 真实错误（目标不可达、内部异常等）。
			_ = m.runs.Fail(taskID, st.Err)
		}
	}()

	m.log.Info("backup function invoked", "function", "scan", "task", taskID,
		"targets", len(opt.Targets), "project", req.ProjectID)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

// getTask 轮询任务进度/结果。路径形如 /tasks/<taskId>，取末段为 id；读自持久化表。
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
