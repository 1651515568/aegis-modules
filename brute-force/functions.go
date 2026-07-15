package bruteforce

// functions.go — 模块「可调用功能」自描述 + 通用 invoke/task 入口。
//
// 对外契约（经 AEGIS 后端代理）：
//   GET  /functions        列出可调用功能及参数 schema
//   POST /invoke           {taskId, function, params}：发起调用
//   POST /stop             停止当前运行中的爆破
//   GET  /tasks/<taskId>   轮询任务进度/结果（读自 task_runs 表）

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"redops/core"
)

func fptr(f float64) *float64 { return &f }

func bruteFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "brute",
			Name:        "弱口令爆破",
			Description: "对多个目标、多种协议并发进行弱口令爆破，支持内置用户名/密码字典或自定义列表。",
			Params: []core.ParamSpec{
				{
					Name:        "targets",
					Label:       "目标列表",
					Type:        core.ParamText,
					Required:    true,
					Placeholder: "192.168.1.1\n192.168.1.0/24\nssh.example.com:2222",
					Help:        "每行一个目标，支持 IP、主机名、CIDR 段（/24 最大）、host:port",
				},
				{
					Name:        "protocols",
					Label:       "协议列表",
					Type:        core.ParamText,
					Required:    true,
					Placeholder: "ssh\nmysql\nredis",
					Help:        "每行一个协议：ssh ftp http-basic http-form mysql redis postgresql telnet smtp",
				},
				{
					Name:    "usernamePreset",
					Label:   "用户名字典预设",
					Type:    core.ParamSelect,
					Default: "top10",
					Options: []core.ParamOption{
						{Value: "none", Label: "不使用预设（仅自定义）"},
						{Value: "top10", Label: "Top10 常见用户名"},
						{Value: "common", Label: "Common 常用用户名（~25条）"},
						{Value: "service", Label: "Service 服务账号专用"},
					},
					Help: "选择内置用户名字典预设，与自定义列表合并使用",
				},
				{
					Name:        "usernames",
					Label:       "自定义用户名列表",
					Type:        core.ParamText,
					Placeholder: "admin\nroot\noperator",
					Help:        "每行一个用户名，与预设合并（去重）",
				},
				{
					Name:    "passwordPreset",
					Label:   "密码字典预设",
					Type:    core.ParamSelect,
					Default: "weak",
					Options: []core.ParamOption{
						{Value: "none", Label: "不使用预设（仅自定义）"},
						{Value: "top10", Label: "Top10 最弱密码"},
						{Value: "weak", Label: "Weak 弱口令（~28条）"},
						{Value: "top100", Label: "Top100 常见弱口令"},
					},
					Help: "选择内置密码字典预设，与自定义列表合并使用",
				},
				{
					Name:        "passwords",
					Label:       "自定义密码列表",
					Type:        core.ParamText,
					Placeholder: "MyPassword123\nCompany@2024",
					Help:        "每行一个密码，与预设合并（去重）。支持空行表示空密码",
				},
				{
					Name:    "threads",
					Label:   "并发线程数",
					Type:    core.ParamInt,
					Default: 20,
					Min:     fptr(1),
					Max:     fptr(500),
					Help:    "并发 worker 数，默认 20，建议不超过 100 以免触发目标封锁",
				},
				{
					Name:    "hostConcurrency",
					Label:   "单目标并发上限",
					Type:    core.ParamInt,
					Default: 3,
					Min:     fptr(1),
					Max:     fptr(20),
					Help:    "每个 host:port 同时最多允许多少个连接，防止触发目标 max_connections 或账户锁定；默认 3",
				},
				{
					Name:    "timeoutMs",
					Label:   "探测超时 (ms)",
					Type:    core.ParamInt,
					Default: 5000,
					Min:     fptr(500),
					Max:     fptr(30000),
					Help:    "单次连接与认证的超时时间，默认 5000ms",
				},
				{
					Name:    "stopOnFirst",
					Label:   "发现后停止该目标",
					Type:    core.ParamBool,
					Default: true,
					Help:    "对同一目标:协议，发现有效凭据后跳过剩余密码组合",
				},
				{
					Name:        "httpFormURL",
					Label:       "HTTP 表单 URL",
					Type:        core.ParamString,
					Placeholder: "http://example.com/login",
					Help:        "http-form 协议使用的登录表单完整 URL",
				},
				{
					Name:        "httpFormUserField",
					Label:       "表单用户名字段",
					Type:        core.ParamString,
					Default:     "username",
					Placeholder: "username",
					Help:        "HTTP 表单中用户名的字段名（POST 参数名）",
				},
				{
					Name:        "httpFormPassField",
					Label:       "表单密码字段",
					Type:        core.ParamString,
					Default:     "password",
					Placeholder: "password",
					Help:        "HTTP 表单中密码的字段名（POST 参数名）",
				},
				{
					Name:        "httpFormFailText",
					Label:       "登录失败标志文本",
					Type:        core.ParamString,
					Placeholder: "用户名或密码错误",
					Help:        "响应包含此文字时判定为认证失败",
				},
				{
					Name:        "portOverrides",
					Label:       "端口覆盖",
					Type:        core.ParamString,
					Placeholder: "ssh:2222,mysql:3307",
					Help:        "逗号分隔，格式：协议:端口，覆盖默认端口。例如 ssh:2222,mysql:3307",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": bruteFunctions()})
}

// protoDictInput is the per-protocol dict config sent from the frontend.
type protoDictInput struct {
	Usernames      string `json:"usernames"`
	UsernamePreset string `json:"usernamePreset"`
	Passwords      string `json:"passwords"`
	PasswordPreset string `json:"passwordPreset"`
}

// invokeParams mirrors the frontend form for the "brute" function.
type invokeParams struct {
	Targets        string `json:"targets"`
	Protocols      string `json:"protocols"`
	// Global fallback dict (used when a protocol has no entry in ProtoDicts)
	Usernames      string `json:"usernames"`
	UsernamePreset string `json:"usernamePreset"`
	Passwords      string `json:"passwords"`
	PasswordPreset string `json:"passwordPreset"`
	// Per-protocol dict (map key = protocol id, e.g. "ssh", "mysql")
	ProtoDicts      map[string]protoDictInput `json:"protoDicts,omitempty"`
	Threads         int  `json:"threads"`
	HostConcurrency int  `json:"hostConcurrency"`
	TimeoutMs       int  `json:"timeoutMs"`
	StopOnFirst     bool `json:"stopOnFirst"`
	// HTTP Form
	HTTPFormURL       string `json:"httpFormURL"`
	HTTPFormUserField string `json:"httpFormUserField"`
	HTTPFormPassField string `json:"httpFormPassField"`
	HTTPFormFailText  string `json:"httpFormFailText"`
	// Port overrides string: "ssh:2222,mysql:3307"
	PortOverrides string `json:"portOverrides"`
}

type invokeRequest struct {
	TaskID    string          `json:"taskId"`
	Function  string          `json:"function"`
	Params    json.RawMessage `json:"params"`
	ProjectID string          `json:"projectId,omitempty"`
}

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
	case "brute":
		m.invokeBrute(w, req)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知功能: " + req.Function})
	}
}

func (m *Module) invokeBrute(w http.ResponseWriter, req invokeRequest) {
	if m.runs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}

	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有爆破任务在运行，请先停止"})
		return
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	m.cancel = cancelFn
	m.mu.Unlock()

	var p invokeParams
	// Set sensible defaults before unmarshaling
	p.UsernamePreset = "top10"
	p.PasswordPreset = "weak"
	p.StopOnFirst = true
	p.Threads = 20
	p.TimeoutMs = 5000
	p.HTTPFormUserField = "username"
	p.HTTPFormPassField = "password"

	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
			cancelFn()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数解析失败: " + err.Error()})
			return
		}
	}

	if strings.TrimSpace(p.Targets) == "" {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}
	if strings.TrimSpace(p.Protocols) == "" {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocols 不能为空"})
		return
	}

	// Fallback HTTP form settings from DB
	if m.db != nil {
		stbl := m.db.Table("settings")
		m.loadSettingFallback(stbl, "httpFormURL", &p.HTTPFormURL)
		m.loadSettingFallback(stbl, "httpFormUserField", &p.HTTPFormUserField)
		m.loadSettingFallback(stbl, "httpFormPassField", &p.HTTPFormPassField)
		m.loadSettingFallback(stbl, "httpFormFailText", &p.HTTPFormFailText)
	}

	// Parse port overrides
	portOverrides := parsePortOverrides(p.PortOverrides)

	// Build per-protocol dicts from input
	var protoDicts map[string]ProtoDict
	if len(p.ProtoDicts) > 0 {
		protoDicts = make(map[string]ProtoDict, len(p.ProtoDicts))
		for proto, pd := range p.ProtoDicts {
			preset := pd.UsernamePreset
			if preset == "none" {
				preset = ""
			}
			users := resolveList(splitLines(pd.Usernames), preset, BuiltinUsernames)

			ppreset := pd.PasswordPreset
			if ppreset == "none" {
				ppreset = ""
			}
			passes := resolveList(splitLines(pd.Passwords), ppreset, BuiltinPasswords)

			protoDicts[proto] = ProtoDict{
				Usernames: users,
				Passwords: passes,
			}
		}
	}

	// Build options
	opts := bruteOptions{
		Targets:             splitLines(p.Targets),
		Protocols:           splitLines(p.Protocols),
		Usernames:           splitLines(p.Usernames),
		Passwords:           splitLines(p.Passwords),
		UsernamePreset:      p.UsernamePreset,
		PasswordPreset:      p.PasswordPreset,
		ProtoDicts:          protoDicts,
		Threads:             p.Threads,
		HostConcurrency:     p.HostConcurrency,
		TimeoutMs:           p.TimeoutMs,
		StopOnFirst:         p.StopOnFirst,
		HTTPFormURL:         p.HTTPFormURL,
		HTTPFormUserField:   p.HTTPFormUserField,
		HTTPFormPassField:   p.HTTPFormPassField,
		HTTPFormSuccessCode: 200,
		HTTPFormFailText:    p.HTTPFormFailText,
		PortOverrides:       portOverrides,
	}

	// Normalize preset "none" to empty string
	if opts.UsernamePreset == "none" {
		opts.UsernamePreset = ""
	}
	if opts.PasswordPreset == "none" {
		opts.PasswordPreset = ""
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	if err := m.runs.Start(taskID, "brute"); err != nil {
		m.mu.Lock()
		m.cancel = nil
		m.mu.Unlock()
		cancelFn()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "登记任务失败: " + err.Error()})
		return
	}

	go func() {
		defer m.runs.GuardPanic(taskID, m.log)
		defer func() {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
		}()

		_ = m.runs.Progress(taskID, 2, fmt.Sprintf("开始爆破 %d 个目标，协议: %s",
			len(opts.Targets), strings.Join(opts.Protocols, ",")))

		results, err := m.sc.run(ctx, opts, func(completed, total, found int) {
			if total <= 0 {
				return
			}
			pct := completed * 90 / total
			if pct < 3 {
				pct = 3
			}
			if pct > 90 {
				pct = 90
			}
			_ = m.runs.Progress(taskID, pct,
				fmt.Sprintf("已探测 %d/%d，发现 %d 个有效凭据", completed, total, found))
		})

		if err != nil {
			if ctx.Err() != nil {
				m.saveFindings(taskID, results)
				_ = m.runs.Cancel(taskID, fmt.Sprintf("用户手动停止，已保存 %d 条结果", len(results)))
			} else {
				_ = m.runs.Fail(taskID, err.Error())
			}
			return
		}

		// 归档成功凭据到模块自有表（覆盖式，同 scan-backup saveFindings 模式）。
		m.saveFindings(taskID, results)

		_ = m.runs.Succeed(taskID, map[string]any{
			"total":   len(results),
			"results": results,
		})
	}()

	m.log.Info("brute invoke", "task", taskID,
		"targets", len(opts.Targets), "protocols", opts.Protocols)
	writeJSON(w, http.StatusAccepted, map[string]string{"taskId": taskID})
}

func (m *Module) stopBrute(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stopped": false, "msg": "无运行中的爆破任务"})
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

// splitLines splits a multiline string into non-empty trimmed lines.
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// parsePortOverrides parses "ssh:2222,mysql:3307" into a map.
func parsePortOverrides(s string) map[string]int {
	if s == "" {
		return nil
	}
	m := make(map[string]int)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		proto := strings.TrimSpace(kv[0])
		port, err := strconv.Atoi(strings.TrimSpace(kv[1]))
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		m[proto] = port
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
