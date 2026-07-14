package portscan

// functions.go —— 模块「可调用功能」自描述 + 统一 invoke/task 入口。
//
// 对外契约(经 AEGIS 后端 /api/v1/engine/m/scan-port/* 代理):
//   GET  /functions            列出可调用功能及参数 schema(前端据此渲染表单)
//   POST /invoke               {taskId, function, params}:用「系统签发」的 taskId 发起调用
//   GET  /tasks/<taskId>       轮询任务进度/结果(读自持久化 task_runs 表)
//   GET  /findings?taskId=<id> 取某次任务归档的开放端口(读自 m_scan_port_findings 表)
//
// 统一 task_id:taskId 由 AEGIS 后端签发并透传,模块不自造;状态/进度/结果按 task_id 落
// SQLite,跨页面/重启不丢。实现上复用既有扫描引擎,不改扫描核心逻辑。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"redops/core"
)

func fptr(f float64) *float64 { return &f }

// portscanFunctions 声明本模块对外可调用的功能目录。
func portscanFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "scan",
			Name:        "端口扫描",
			Description: "对授权目标做端口扫描:默认内嵌 masscan 高速发现,无管理员/无 libpcap-Npcap 时自动回退纯 Go connect/UDP 扫描。可选服务识别与 banner 抓取。",
			Params: []core.ParamSpec{
				{
					Name: "targets", Label: "目标列表", Type: core.ParamStringList, Required: true,
					Placeholder: "每行一个 IP / 域名 / CIDR / host:port / URL", Help: "支持多目标,每行一个;域名会被解析",
				},
				{
					Name: "ports", Label: "端口", Type: core.ParamSelect, Default: "top100",
					Options: []core.ParamOption{
						{Value: "top100",  Label: "top100（实战推荐 · 约 100 个高频端口）"},
						{Value: "top500",  Label: "top500（约 370 个高价值端口）"},
						{Value: "top1000", Label: "top1000（端口 1-1000 + 常见高位）"},
						{Value: "all",     Label: "全端口（1-65535 · 耗时慎用）"},
						{Value: "custom",  Label: "自定义（填写下方端口列表）"},
					},
					Help: "masscan 下为发包速率模式;connect 下按并发+超时控制",
				},
				{
					Name:        "portsCustom",
					Label:       "自定义端口",
					Type:        core.ParamString,
					Default:     "22,80,443",
					Placeholder: "22,80,443,8000-8100",
					Help:        "仅「自定义」档位时生效，支持逗号分隔与区间（8000-8100）",
				},
				{
					Name: "mode", Label: "引擎", Type: core.ParamSelect, Default: "masscan",
					Options: []core.ParamOption{
						{Value: "masscan", Label: "masscan(内嵌·高速,需 root/libpcap)"},
						{Value: "connect", Label: "connect(纯 Go·免提权)"},
						{Value: "syn", Label: "SYN(Linux 原生·需 root/CAP_NET_RAW)"},
					},
					Help: "Linux 上 SYN 模式使用原生 raw socket，无需 npcap；masscan 不可用时自动回退 connect",
				},
				{
					Name: "proto", Label: "协议", Type: core.ParamSelect, Default: "tcp",
					Options: []core.ParamOption{
						{Value: "tcp", Label: "TCP"},
						{Value: "udp", Label: "UDP"},
						{Value: "both", Label: "TCP+UDP"},
					},
				},
				{
					Name: "rate", Label: "速率 (pps/req/s)", Type: core.ParamInt, Default: 1000,
					Min: fptr(0), Max: fptr(100000), Help: "masscan:发包速率;connect:每秒连接上限(0=不限)",
				},
				{
					Name: "concurrency", Label: "并发数 (connect)", Type: core.ParamInt, Default: 256,
					Min: fptr(1), Max: fptr(1024), Help: "仅 connect 引擎生效",
				},
				{
					Name: "timeout", Label: "连接超时 (ms)", Type: core.ParamInt, Default: 1500,
					Min: fptr(100), Max: fptr(10000),
				},
				{
					Name: "discovery", Label: "主机存活探测", Type: core.ParamBool, Default: false,
					Help: "多主机时先探活,跳过死主机",
				},
				{
					Name: "svc", Label: "服务识别", Type: core.ParamBool, Default: true,
				},
				{
					Name: "banner", Label: "抓取 Banner", Type: core.ParamBool, Default: true,
					Help: "对开放端口二次 connect 抓 banner/标题/证书 CN",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": portscanFunctions()})
}

type invokeRequest struct {
	TaskID    string          `json:"taskId"`              // 系统签发的任务 id(统一台账主键)
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"` // 仅用于日志/上下文,引擎不做项目鉴权
}

// fallbackTaskID 仅用于直连引擎调试(未经后端签发 taskId)时兜底,避免无主键无法落库。
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
// taskId 由系统签发并透传:状态/进度/结果按 taskId 落 SQLite,跨页面/重启不丢。
func (m *Module) invokeScan(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪,无法登记任务"})
		return
	}
	var opt scanOptions
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &opt); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}
	if opt.Ports == "custom" {
		opt.Ports = strings.TrimSpace(opt.PortsCustom)
		if opt.Ports == "" {
			opt.Ports = "top1000"
		}
	}
	if len(opt.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	name := opt.Name
	if name == "" {
		name = "端口扫描任务"
	}

	// 原子地检查+设置运行态（防止并发双启动 TOCTOU）
	ctx, cancel := context.WithCancel(context.Background())
	if !m.store.tryBeginScan(taskID, name, opt.Targets, opt) {
		cancel()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有扫描在运行,请先停止或等待完成"})
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
		defer cancel()

		// 进度观察 goroutine:把 store 的实时扫描状态镜像成持久化任务进度。
		// 用 defer close(done) 确保任意路径（含 panic-recover）都能让观察 goroutine 退出。
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
					_ = m.runs.Progress(taskID, p,
						fmt.Sprintf("[%s] 已探测 %d/%d,开放 %d", st.Engine, st.Probed, st.Total, st.Found))
				}
			}
		}()

		m.runScan(ctx, opt) // 阻塞至扫描结束/取消（defer close(done) 在此后触发）

		st := m.store.status()
		// 无论成功/取消，先落库端口，保证历史任务里始终有数据。
		m.saveFindings(taskID)
		switch {
		case st.Err == "已停止":
			_ = m.runs.Cancel(taskID, fmt.Sprintf("用户已取消，已保存开放端口 %d 条", st.Found))
		case st.Err != "":
			_ = m.runs.Fail(taskID, st.Err)
		default:
			_ = m.runs.Progress(taskID, 100,
				fmt.Sprintf("[%s] 扫描完成，开放 %d 个端口", st.Engine, st.Found))
			_ = m.runs.Succeed(taskID, map[string]any{
				"engine":   st.Engine,
				"found":    st.Found,
				"probed":   st.Probed,
				"total":    st.Total,
				"closed":   st.Closed,
				"filtered": st.Filtered,
				"target":   st.Target,
			})
		}
	}()

	m.log.Info("scan-port function invoked", "function", "scan", "task", taskID,
		"targets", len(opt.Targets), "ports", opt.Ports, "mode", opt.Mode, "project", req.ProjectID)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

// getTask 轮询任务进度/结果。路径形如 /tasks/<taskId>,取末段为 id;读自持久化表。
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
