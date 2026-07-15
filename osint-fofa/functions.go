package osintfofa

// functions.go —— 模块「可调用功能」自描述 + 通用 invoke/task 入口。
//
// 对外契约（经 AEGIS 后端 /api/v1/engine/m/osint-fofa/* 代理）：
//
//	GET  /functions            列出本模块可调用功能及参数 schema（前端据此渲染表单）
//	POST /invoke               {taskId, function, params}：用「系统签发」的 taskId 发起查询
//	GET  /tasks/<taskId>       轮询任务进度/结果（读自持久化 task_runs 表）
//
// 统一 task_id 契约：taskId 由 AEGIS 后端统一签发并透传，模块「不自造 id」；
// 执行过程把状态/进度/结果落到 SQLite（按 task_id 主键），跨页面/重启不丢。

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

// fofaFunctions 声明本模块对外可调用的功能目录，前端据此动态渲染表单。
func fofaFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "query",
			Name:        "空间测绘查询",
			Description: "使用各平台自有查询语法（FOFA DSL / 奇安信鹰图 / Shodan Filters / ZoomEye / 360 Quake 等）批量拉取网络资产，多平台结果自动去重聚合。",
			Params: []core.ParamSpec{
				{
					Name:     "platform",
					Label:    "查询平台",
					Type:     core.ParamSelect,
					Required: true,
					Default:  "fofa",
					Help:     "选择单个平台或聚合所有已配置平台（需在「设置」中填写对应 API Key）",
					Options: []core.ParamOption{
						{Value: "fofa", Label: "FOFA（fofa.icu 中转，内置 Key，免费）"},
						{Value: "hunter", Label: "Hunter（奇安信鹰图）"},
						{Value: "shodan", Label: "Shodan（shodan.io）"},
						{Value: "zoomeye", Label: "ZoomEye（钟馗之眼）"},
						{Value: "quake", Label: "Quake 360（quake.360.net）"},
						{Value: "all", Label: "全平台聚合（已配置平台并行查询）"},
					},
				},
				{
					Name:        "fofaQuery",
					Label:       "FOFA 查询语句",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: `domain="example.com" && port="80"`,
					Help:        "FOFA 原生查询语法，平台=fofa 或 all 时生效",
				},
				{
					Name:        "hunterQuery",
					Label:       "Hunter 查询语句",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: `domain.suffix="example.com"`,
					Help:        "奇安信鹰图原生查询语法，平台=hunter 或 all 时生效",
				},
				{
					Name:        "shodanQuery",
					Label:       "Shodan 查询语句",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "hostname:example.com",
					Help:        "Shodan 原生查询语法，平台=shodan 或 all 时生效",
				},
				{
					Name:        "zoomeyeQuery",
					Label:       "ZoomEye 查询语句",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "hostname:example.com",
					Help:        "ZoomEye 原生查询语法，平台=zoomeye 或 all 时生效",
				},
				{
					Name:        "quakeQuery",
					Label:       "Quake 查询语句",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: `domain:"example.com"`,
					Help:        "360 Quake 原生查询语法，平台=quake 或 all 时生效",
				},
				{
					Name:    "pageSize",
					Label:   "每平台最大返回条数",
					Type:    core.ParamInt,
					Default: 100,
					Min:     fptr(10),
					Max:     fptr(500),
					Help:    "单平台最多拉取条数，范围 10~500；聚合模式下各平台独立计算",
				},
				// API Key 覆盖字段（优先级高于设置页面中的全局配置）
				{
					Name:        "fofaEmail",
					Label:       "FOFA Email（覆盖设置）",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "留空则使用设置页面中的配置",
					Help:        "临时覆盖全局 FOFA 账号邮箱",
				},
				{
					Name:        "fofaKey",
					Label:       "FOFA API Key（覆盖设置）",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "留空则使用设置页面中的配置",
					Help:        "临时覆盖全局 FOFA API Key",
				},
				{
					Name:        "hunterKey",
					Label:       "Hunter API Key（覆盖设置）",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "留空则使用设置页面中的配置",
					Help:        "临时覆盖全局 Hunter API Key",
				},
				{
					Name:        "shodanKey",
					Label:       "Shodan API Key（覆盖设置）",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "留空则使用设置页面中的配置",
					Help:        "临时覆盖全局 Shodan API Key",
				},
				{
					Name:        "zoomeyeKey",
					Label:       "ZoomEye API Key（覆盖设置）",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "留空则使用设置页面中的配置",
					Help:        "临时覆盖全局 ZoomEye API Key",
				},
				{
					Name:        "quakeKey",
					Label:       "Quake Token（覆盖设置）",
					Type:        core.ParamString,
					Required:    false,
					Placeholder: "留空则使用设置页面中的配置",
					Help:        "临时覆盖全局 360 Quake Token",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": fofaFunctions()})
}

// invokeRequest 是 POST /invoke 的请求体结构，与全平台统一 task_id 契约对齐。
type invokeRequest struct {
	TaskID    string          `json:"taskId"`              // 系统签发的任务 id（统一台账主键）
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"` // 仅用于日志/上下文
}

// fallbackTaskID 仅用于直连引擎调试（未经后端签发 taskId）时兜底，避免无主键无法落库。
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
	case "query":
		m.invokeQuery(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

// invokeQuery 把一次空间测绘查询包装成异步可轮询任务。
// 立即返回 {"taskId": "..."} 后在 goroutine 里执行实际 API 请求，状态写 SQLite。
func (m *Module) invokeQuery(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪，无法登记任务"})
		return
	}

	// 同一时间只允许一个查询任务运行
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有查询任务在运行，请等待完成或刷新页面"})
		return
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Minute)
	m.cancel = cancelFn
	m.mu.Unlock()

	var opts queryOptions
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &opts); err != nil {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
			cancelFn()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}

	// 参数校验：至少需要一个平台的查询语句
	if opts.Platform == "" {
		opts.Platform = "fofa"
	}
	if opts.PageSize <= 0 {
		opts.PageSize = 100
	}
	if opts.PageSize > 500 {
		opts.PageSize = 500
	}

	// 从数据库补全 API Key（用户在设置页面填写后持久化，调用时自动读取；params 中有值则优先用 params）
	if m.db != nil {
		tbl := m.db.Table("settings")
		m.loadSettingFallback(tbl, "fofaEmail", &opts.FOFAEmail)
		m.loadSettingFallback(tbl, "fofaKey", &opts.FOFAKey)
		m.loadSettingFallback(tbl, "hunterKey", &opts.HunterKey)
		m.loadSettingFallback(tbl, "shodanKey", &opts.ShodanKey)
		m.loadSettingFallback(tbl, "zoomeyeKey", &opts.ZoomEyeKey)
		m.loadSettingFallback(tbl, "quakeKey", &opts.QuakeKey)
	}
	// FOFA Key 最终兜底：设置页未配置时使用内置 fofa.icu 中转 key
	if opts.FOFAKey == "" {
		opts.FOFAKey = defaultFOFAKey
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	if err := m.runs.Start(taskID, "query"); err != nil {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	// 立即响应 taskId，查询在后台 goroutine 中异步执行
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})

	go func() {
		defer func() {
			// panic 兜底：任何 panic 都落终态，避免任务永卡 running（引擎不因单任务崩溃）。
			if r := recover(); r != nil {
				m.log.Warn("osint-fofa 查询 goroutine panic", "task", taskID, "panic", r)
				_ = m.runs.Fail(taskID, fmt.Sprintf("内部错误: %v", r))
			}
			cancelFn() // 释放 WithTimeout 定时器资源
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		_ = m.runs.Progress(taskID, 2, fmt.Sprintf("开始查询（平台: %s）…", opts.Platform))

		assets, err := runQuery(ctx, opts, func(pct int, msg string) {
			_ = m.runs.Progress(taskID, pct, msg)
		}, m.log)

		if err != nil {
			// 无论失败/取消，先归档已获取的部分资产，保证任务里始终有数据。
			m.saveFindings(taskID, assets)
			if ctx.Err() != nil {
				_ = m.runs.Cancel(taskID, fmt.Sprintf("查询已取消，已保存资产 %d 条", len(assets)))
			} else {
				_ = m.runs.Fail(taskID, err.Error())
			}
			return
		}

		// 把资产归档写入模块自有表，供 GET /findings 接口读取
		m.saveFindings(taskID, assets)

		_ = m.runs.Succeed(taskID, map[string]any{
			"count":    len(assets),
			"platform": opts.Platform,
		})
	}()

	m.log.Info("osint-fofa 查询任务已发起", "task", taskID, "platform", opts.Platform,
		"pageSize", opts.PageSize, "project", req.ProjectID)
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
