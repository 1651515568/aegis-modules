package scandir

// functions.go —— 模块「可调用功能」自描述 + 统一 invoke/task 入口。
//
// 对外契约(经 AEGIS 后端 /api/v1/engine/m/scan-dir/* 代理):
//   GET  /functions            列出可调用功能及参数 schema(前端据此渲染表单)
//   POST /invoke               {taskId, function, params}:用「系统签发」的 taskId 发起调用
//   GET  /tasks/<taskId>       轮询任务进度/结果(读自持久化 task_runs 表)
//   GET  /findings?taskId=<id> 取某次任务归档的命中(读自 m_scan_dir_findings 表)
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

// scenePresets 场景预设 → (字典 id, 扩展名)。
// 字典 id 为空表示沿用用户所选；Extension 为空表示不展开扩展名。
var scenePresets = map[string]struct {
	Wordlist   string
	Extensions string
}{
	"web-generic":  {"common", "php,asp,aspx,jsp,html,htm"},
	"api-rest":     {"api", ""},
	"spring-boot":  {"spring-boot", ""},
	"php-app":      {"dirsearch", "php,php3,php5,phtml"},
	"source-leak":  {"quickhits", "zip,tar,gz,bak,sql,db,7z,rar"},
	"china-cms":    {"china-cms", "php,jsp,do,action"},
}

// dirscanFunctions 声明本模块对外可调用的功能目录。
func dirscanFunctions() []core.FunctionSpec {
	return []core.FunctionSpec{
		{
			ID:          "scan",
			Name:        "目录/文件爆破",
			Description: "对授权 Web 目标做目录与文件爆破:内置 dirsearch/SecLists/RAFT 等权威字典(支持 %EXT% 占位符)+ 扩展名展开,带软 404 基线过滤、状态码与 ffuf 风格 size/words/lines 过滤、全局限速与 429/503 退避,可选递归发现。也可把任意 .txt 字典投放到 data/scan-dir/wordlists/ 作为外部字典(id=file:<名>)。",
			Params: []core.ParamSpec{
				{
					Name: "targets", Label: "目标列表", Type: core.ParamStringList, Required: true,
					Placeholder: "每行一个 http(s)://host[:port][/sub] 或 域名/IP", Help: "支持多目标,每行一个;无 scheme 默认 http",
				},
				{
					Name: "scene", Label: "场景预设", Type: core.ParamSelect, Default: "",
					Options: []core.ParamOption{
						{Value: "", Label: "不使用（手动配置字典+扩展名）"},
						{Value: "web-generic", Label: "Web 通用（common + php/asp/jsp）"},
						{Value: "api-rest", Label: "API 端点（api 字典，无扩展名）"},
						{Value: "spring-boot", Label: "Spring Boot（Actuator / Swagger / H2）"},
						{Value: "php-app", Label: "PHP 应用（dirsearch + php/phtml）"},
						{Value: "source-leak", Label: "源码/备份泄露（quickhits + zip/sql/bak）"},
						{Value: "china-cms", Label: "国内CMS/OA/中间件（ThinkPHP/通达OA/Nacos/Dubbo等）"},
					},
					Help: "选择后自动填充「字典」和「扩展名」；手动设置字典时场景预设被忽略",
				},
				{
					Name: "wordlist", Label: "字典", Type: core.ParamSelect, Default: "combined",
					Options: []core.ParamOption{
						{Value: "combined", Label: "【最强默认】全合并(quickhits+api+spring-boot+国内+common)"},
						{Value: "quickhits", Label: "QuickHits(敏感/泄露文件)"},
						{Value: "api", Label: "API 端点"},
						{Value: "spring-boot", Label: "Spring Boot(Actuator/Swagger/H2)"},
						{Value: "china-cms", Label: "国内CMS/OA/中间件(~700条)"},
						{Value: "common", Label: "Common(经典通用 ~4.7k)"},
						{Value: "dirsearch", Label: "dirsearch(含 %EXT% ~9.6k)"},
						{Value: "raft-files", Label: "RAFT 文件族(~17k)"},
						{Value: "raft-dirs", Label: "RAFT 目录族(~30k)"},
						{Value: "custom", Label: "自定义词条"},
					},
					Help: "内置取自 dirsearch/SecLists/RAFT;外部字典见 /dict(id=file:<名>);选 custom 时在下方填写",
				},
				{
					Name: "customWords", Label: "自定义词条", Type: core.ParamStringList, Required: false,
					Placeholder: "每行一个路径名(字典=custom 时生效;支持 %EXT% 占位符)",
				},
				{
					Name: "wordlist2", Label: "第二字典(FUZ2Z)", Type: core.ParamString, Default: "",
					Placeholder: "字典 id 或 custom;留空=不启用",
					Help:        "ffuf 多关键字:目标/请求体/请求头里用 FUZ2Z 标记第二位置",
				},
				{
					Name: "customWords2", Label: "第二自定义词条", Type: core.ParamStringList, Required: false,
					Placeholder: "wordlist2=custom 时生效",
				},
				{
					Name: "fuzzMode", Label: "多关键字模式", Type: core.ParamSelect, Default: "clusterbomb",
					Options: []core.ParamOption{
						{Value: "clusterbomb", Label: "clusterbomb(笛卡尔积 N×M)"},
						{Value: "pitchfork", Label: "pitchfork(按下标并行)"},
					},
					Help: "ffuf 组合模式;仅启用第二字典时生效",
				},
				{
					Name: "extensions", Label: "扩展名", Type: core.ParamString, Default: "",
					Placeholder: "php,asp,aspx,jsp,bak,zip,txt", Help: "逗号分隔;替换 %EXT% 占位符,并对目录型词条追加",
				},
				{
					Name: "concurrency", Label: "并发数", Type: core.ParamInt, Default: 30,
					Min: fptr(1), Max: fptr(256), Help: "默认 30,上限 256；HEAD 模式可调更高",
				},
				{
					Name: "rate", Label: "限速 (req/s)", Type: core.ParamInt, Default: 0,
					Min: fptr(0), Max: fptr(2000), Help: "全局请求限速,0=不限速",
				},
				{
					Name: "timeout", Label: "超时 (ms)", Type: core.ParamInt, Default: 8000,
					Min: fptr(500), Max: fptr(30000),
				},
				{
					Name: "statusInclude", Label: "仅保留状态码", Type: core.ParamString, Default: "",
					Placeholder: "200,204,301,302,401,403", Help: "留空=保留除「排除」外的全部;支持区间如 200-299",
				},
				{
					Name: "statusExclude", Label: "排除状态码", Type: core.ParamString, Default: "404",
					Placeholder: "404", Help: "默认排除 404",
				},
				{
					Name: "filterLength", Label: "过滤响应大小", Type: core.ParamString, Default: "",
					Placeholder: "0,1234", Help: "ffuf -fs:过滤掉这些响应体字节数(逗号分隔)",
				},
				{
					Name: "filterWords", Label: "过滤词数", Type: core.ParamString, Default: "",
					Placeholder: "10,42", Help: "ffuf -fw:过滤掉这些词数",
				},
				{
					Name: "filterLines", Label: "过滤行数", Type: core.ParamString, Default: "",
					Placeholder: "1,7", Help: "ffuf -fl:过滤掉这些行数",
				},
				{
					Name: "filterRegex", Label: "正文过滤(正则)", Type: core.ParamString, Default: "",
					Placeholder: "Access Denied|您没有权限", Help: "ffuf -fr / dirsearch --exclude-texts:正文匹配则剔除",
				},
				{
					Name: "matchRegex", Label: "正文匹配(正则)", Type: core.ParamString, Default: "",
					Placeholder: "admin|console", Help: "ffuf -mr:仅保留正文匹配者",
				},
				{
					Name: "minLength", Label: "最小响应大小", Type: core.ParamInt, Default: 0,
					Min: fptr(0), Help: "dirsearch --minimal:小于此字节数剔除(0=不限)",
				},
				{
					Name: "maxLength", Label: "最大响应大小", Type: core.ParamInt, Default: 0,
					Min: fptr(0), Help: "dirsearch --maximal:大于此字节数剔除(0=不限)",
				},
				{
					Name: "prefixes", Label: "前缀变体", Type: core.ParamString, Default: "",
					Placeholder: ".,_", Help: "dirsearch --prefixes:为每词条加前缀(逗号分隔)",
				},
				{
					Name: "suffixes", Label: "后缀变体", Type: core.ParamString, Default: "",
					Placeholder: "~,.bak,/", Help: "dirsearch --suffixes:为每词条加后缀(逗号分隔)",
				},
				{
					Name: "crawl", Label: "链接抽取爬取", Type: core.ParamBool, Default: false,
					Help: "feroxbuster --extract-links / dirsearch --crawl:从响应抽取同主机链接再探,发现未链接内容",
				},
				{
					Name: "collectBackups", Label: "备份/源码泄露衍生", Type: core.ParamBool, Default: false,
					Help: "feroxbuster --collect-backups:命中文件时自动探 .bak/~/.old/.swp 等备份变体",
				},
				{
					Name: "randomAgent", Label: "随机 UA", Type: core.ParamBool, Default: false,
					Help: "dirsearch random-agent:每请求轮换 User-Agent",
				},
				{
					Name: "followRedirect", Label: "跟随跳转", Type: core.ParamBool, Default: false,
					Help: "关闭时记录 30x 与 Location(更利于发现目录)",
				},
				{
					Name: "recursion", Label: "递归深度", Type: core.ParamInt, Default: 0,
					Min: fptr(0), Max: fptr(3), Help: "对目录型命中递归爆破,0=关闭",
				},
				{
					Name: "method", Label: "请求方法", Type: core.ParamSelect, Default: "GET",
					Options: []core.ParamOption{
						{Value: "GET", Label: "GET"},
						{Value: "HEAD", Label: "HEAD(更快,无软 404 体比对)"},
						{Value: "POST", Label: "POST"},
						{Value: "PUT", Label: "PUT"},
						{Value: "DELETE", Label: "DELETE"},
						{Value: "PATCH", Label: "PATCH"},
						{Value: "OPTIONS", Label: "OPTIONS"},
					},
				},
				{
					Name: "requestBody", Label: "请求体", Type: core.ParamText, Default: "",
					Placeholder: "ffuf -d:非 GET/HEAD 时发送;可含 FUZZ(如 user=admin&pass=FUZZ)",
					Help:        "默认 Content-Type 为表单;可用「附加请求头」覆盖",
				},
				{
					Name: "proxy", Label: "上游代理", Type: core.ParamString, Default: "",
					Placeholder: "http://127.0.0.1:8080 或 socks5://127.0.0.1:1080",
					Help:        "ffuf -x / dirsearch --proxy:经 Burp/SOCKS 转发流量",
				},
				{
					Name: "userAgent", Label: "User-Agent", Type: core.ParamString, Default: "",
					Placeholder: "留空使用默认 UA",
				},
				{
					Name: "headers", Label: "附加请求头", Type: core.ParamStringList, Required: false,
					Placeholder: "每行一个 Key: Value(如 Cookie: a=b)",
				},
			},
		},
	}
}

func (m *Module) listFunctions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"functions": dirscanFunctions()})
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

// maxExpandedJobs 是单次扫描展开后总请求数的安全上限。
// 超过此值时在任务注册前拒绝请求，避免意外发起数十万次 HTTP 请求。
const maxExpandedJobs = 100_000

// estimateExpandedCount 估算一次扫描展开后的总请求数（字典展开 × 目标数量）。
// 包含前缀/后缀放大倍数，与 runResumable 实际展开逻辑保持一致。
func estimateExpandedCount(opt scanOptions) int {
	var templates []string
	if strings.EqualFold(opt.Wordlist, "custom") {
		templates = parseWordlist(strings.Join(opt.CustomWords, "\n"))
	} else {
		id := opt.Wordlist
		if id == "" {
			id = "combined" // 与 runResumable 默认值保持一致，避免预检低估
		}
		templates, _ = loadTemplates(id)
	}
	exts := parseExtensions(opt.Extensions)
	expanded := len(expandTemplates(templates, exts))

	// 前缀/后缀放大：与 applyAffixes 逻辑对齐，防止预检低估（P1）
	prefixes := parseAffix(opt.Prefixes)
	suffixes := parseAffix(opt.Suffixes)
	if len(prefixes)+len(suffixes) > 0 {
		expanded *= (1 + len(prefixes) + len(suffixes))
	}

	// clusterbomb 模式：主字典 × 第二字典
	if opt.Wordlist2 != "" && opt.FuzzMode != "pitchfork" {
		var tpl2 []string
		if strings.EqualFold(opt.Wordlist2, "custom") {
			tpl2 = parseWordlist(strings.Join(opt.CustomWords2, "\n"))
		} else {
			tpl2, _ = loadTemplates(opt.Wordlist2)
		}
		if len(tpl2) > 0 {
			expanded *= len(tpl2)
		}
	}
	return expanded * len(opt.Targets)
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
	if len(opt.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "targets 不能为空"})
		return
	}

	// 场景预设：若用户选择了场景且未手动设置字典，则自动填充字典和扩展名
	if opt.Scene != "" && opt.Wordlist == "" {
		if preset, ok := scenePresets[opt.Scene]; ok {
			opt.Wordlist = preset.Wordlist
			if opt.Extensions == "" {
				opt.Extensions = preset.Extensions
			}
		}
	}

	// 展开数量预检：超过 100000 时拒绝，防止意外发起超大规模扫描
	if total := estimateExpandedCount(opt); total > maxExpandedJobs {
		extCount := len(parseExtensions(opt.Extensions))
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf(
				"展开后预计请求数 %d 超过安全上限 %d。"+
					"当前配置：字典 %q × %d 个扩展名 × %d 个目标。"+
					"建议：减少扩展名数量，或改用更小的字典（如 quickhits/common），或拆分多目标为多次扫描。",
				total, maxExpandedJobs, opt.Wordlist, extCount, len(opt.Targets)),
		})
		return
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = fallbackTaskID()
	}
	name := opt.Name
	if name == "" {
		name = "目录扫描任务"
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
		sc := newScanner(m.log, m.store)

		// 进度观察 goroutine:把 store 的实时扫描状态镜像成持久化任务进度。
		done := make(chan struct{})
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
						if p > 99 {
							p = 99 // 递归层会增长 Total,完成前不报 100
						}
					}
					_ = m.runs.Progress(taskID, p,
						fmt.Sprintf("[%s] 已探测 %d/%d,命中 %d", st.Phase, st.Probed, st.Total, st.Found))
				}
			}
		}()

		sc.run(ctx, opt) // 阻塞至扫描结束/取消
		close(done)

		st := m.store.status()
		// 无论成功/取消，先落库命中，保证历史任务里始终有数据。
		m.saveFindings(taskID)
		switch {
		case st.Err == "已取消":
			_ = m.runs.Cancel(taskID, fmt.Sprintf("用户已取消，已保存命中 %d 条", st.Found))
		case st.Err != "":
			_ = m.runs.Fail(taskID, st.Err)
		default:
			_ = m.runs.Progress(taskID, 100, fmt.Sprintf("扫描完成，命中 %d 条", st.Found))
			_ = m.runs.Succeed(taskID, map[string]any{
				"found":    st.Found,
				"probed":   st.Probed,
				"total":    st.Total,
				"filtered": st.Filtered,
				"target":   st.Target,
			})
		}
	}()

	m.log.Info("scan-dir function invoked", "function", "scan", "task", taskID,
		"targets", len(opt.Targets), "wordlist", opt.Wordlist, "project", req.ProjectID)
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
