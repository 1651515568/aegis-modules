package backup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// hitsFile 是命中结果的持久化落盘路径(相对 cwd,与 data/state.json 同级)。
// data/ 已在 .gitignore 中,属运行期数据。
const hitsFile = "data/backup/hits.json"

// Evidence 是一条命中的「探测证据」(脱敏)。
// 演练定位:仅保存脱敏后的探测请求/响应摘要,用于复盘举证。
// 重要:从不下载完整文件内容,仅做 HEAD / Range 字节探测以确认存在性,
// 因此不保存任何真实的密钥 / 数据内容。
type Evidence struct {
	Request  string `json:"request"`  // 演示·已脱敏的探测请求骨架(HEAD / Range)
	Response string `json:"response"` // 演示·判定依据的响应特征(状态码 / 长度 / 类型)
	Note     string `json:"note"`     // 探测方式说明(为何无害:仅探存在性,不取内容)
}

// Hit 是一条备份 / 敏感文件泄露命中记录。
type Hit struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`         // 命中 URL
	File        string   `json:"file"`        // 文件名 / 路径
	Kind        string   `json:"kind"`        // 文件类型(源码 / 数据库 / 配置 / 其它)
	Size        string   `json:"size"`        // 文件大小(来自 Content-Length,未下载)
	Code        int      `json:"code"`        // HTTP 状态码
	Rule        string   `json:"rule"`        // 命中规则 / 字典项
	Host        string   `json:"host"`        // 来源主机
	Severity    string   `json:"severity"`    // 风险等级(高危 / 中危 / 低危)
	At          string   `json:"at"`          // 命中时间
	Note        string   `json:"note"`        // 一句话研判
	Detail      string   `json:"detail"`      // 风险说明 + 本次探测范围
	Sample      string   `json:"sample"`      // 脱敏命中内容片段说明(仅描述,不含真实内容)
	Evidence    Evidence `json:"evidence"`    // 探测证据(脱敏)
	Remediation string   `json:"remediation"` // 处置建议
	Refs        []string `json:"refs"`        // 参考(规范 / 工具)
	Chain       []string `json:"chain"`       // 来源链路(哪个步骤暴露的)
}

// scanStatus 是一次扫描任务的实时进度快照(供 /scan/status 轮询)。
type scanStatus struct {
	Running   bool   `json:"running"`
	Total     int    `json:"total"`
	Probed    int    `json:"probed"`
	Found     int    `json:"found"`
	Target    string `json:"target"`
	StartedAt string `json:"startedAt"`
	EndedAt   string `json:"endedAt"`
	Err       string `json:"err"`
	Demo      bool   `json:"demo"`      // 当前 hits 是否仍为演示种子(尚未跑过真实扫描)
	Resumable bool   `json:"resumable"` // 存在未完成的扫描任务(可续扫)
}

// scanJob 是一次扫描任务的可恢复描述(持久化到 job.json):用于断点续扫。
type scanJob struct {
	Opts      scanOptions `json:"opts"`      // 原始扫描参数(含 Targets)
	Completed []string    `json:"completed"` // 已完成目标的 host 标签
	Status    string      `json:"status"`    // running / done / canceled / timeout / limit
	StartedAt string      `json:"startedAt"`
}

// remaining 返回尚未完成的目标数(粗略:总目标 - 已完成)。
func (j *scanJob) remaining() int {
	r := len(j.Opts.Targets) - len(j.Completed)
	if r < 0 {
		return 0
	}
	return r
}

type store struct {
	mu        sync.RWMutex
	data      []Hit
	st        scanStatus
	cancel    context.CancelFunc
	path      string     // 命中持久化文件路径;空则不落盘
	job       *scanJob   // 当前/上次扫描任务(内存态,镜像 job.json)
	persistMu sync.Mutex // 串行化磁盘写,避免周期 flush 与按主机 checkpoint 并发写同一文件
}

func newStore(path string) *store { return &store{path: path} }

// jobPath 返回任务描述文件路径(与 hits.json 同目录)。
func (s *store) jobPath() string {
	if s.path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.path), "job.json")
}

// persistedDoc 是落盘 JSON 的结构:命中列表 + 一点扫描上下文,便于重启后还原展示。
type persistedDoc struct {
	Hits    []Hit  `json:"hits"`
	Target  string `json:"target"`
	EndedAt string `json:"endedAt"`
	SavedAt string `json:"savedAt"`
}

// persist 把当前命中快照原子写盘(临时文件 + rename)。在锁外做 IO,避免长时间持锁。
func (s *store) persist() {
	if s.path == "" {
		return
	}
	s.mu.RLock()
	doc := persistedDoc{
		Hits:    append([]Hit(nil), s.data...),
		Target:  s.st.Target,
		EndedAt: s.st.EndedAt,
		SavedAt: nowStamp(),
	}
	s.mu.RUnlock()

	if buf, err := json.MarshalIndent(doc, "", "  "); err == nil {
		s.writeAtomic(s.path, buf)
	}
}

// writeAtomic 串行化地把 buf 原子写到 path(临时文件 + rename)。
func (s *store) writeAtomic(path string, buf []byte) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path) // 原子替换,避免半写文件
}

// load 启动时从盘加载历史命中。返回是否成功加载到非空结果(供决定是否回落到 demo 种子)。
func (s *store) load() bool {
	if s.path == "" {
		return false
	}
	buf, err := os.ReadFile(s.path)
	if err != nil {
		return false
	}
	var doc persistedDoc
	if err := json.Unmarshal(buf, &doc); err != nil || len(doc.Hits) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = doc.Hits
	s.st = scanStatus{Target: doc.Target, EndedAt: doc.EndedAt, Demo: false}
	return true
}

// deleteHit 按 id 删除一条命中,返回是否删到。
func (s *store) deleteHit(id string) bool {
	s.mu.Lock()
	found := false
	// 使用新切片而非原地复用（s.data[:0]），避免底层数组尾部残留 Hit 指针，
	// 防止 GC 无法回收已删除命中持有的字符串/切片内存。
	out := make([]Hit, 0, len(s.data))
	for _, h := range s.data {
		if h.ID == id {
			found = true
			continue
		}
		out = append(out, h)
	}
	s.data = out
	s.mu.Unlock()
	if found {
		s.persist()
	}
	return found
}

// clearHits 清空全部命中并删除落盘文件(连同未完成任务一并清掉)。
func (s *store) clearHits() {
	s.mu.Lock()
	s.data = nil
	s.st.Demo = false
	s.st.Found = 0
	s.st.Resumable = false
	s.job = nil
	jobP := s.jobPath()
	s.mu.Unlock()
	if s.path != "" {
		_ = os.Remove(s.path)
	}
	if jobP != "" {
		_ = os.Remove(jobP)
	}
}

// ---- 断点续扫:任务描述持久化 ----

// saveJob 原子写当前任务到 job.json。
func (s *store) saveJob() {
	s.mu.RLock()
	job := s.job
	jobP := s.jobPath()
	s.mu.RUnlock()
	if job == nil || jobP == "" {
		return
	}
	if buf, err := json.MarshalIndent(job, "", "  "); err == nil {
		s.writeAtomic(jobP, buf)
	}
}

// setJob 设置当前任务并落盘。
func (s *store) setJob(j *scanJob) {
	s.mu.Lock()
	s.job = j
	s.mu.Unlock()
	s.saveJob()
}

// markTargetDone 标记一个目标完成(去重追加),并落盘任务进度。
func (s *store) markTargetDone(label string) {
	s.mu.Lock()
	if s.job != nil {
		dup := false
		for _, c := range s.job.Completed {
			if c == label {
				dup = true
				break
			}
		}
		if !dup {
			s.job.Completed = append(s.job.Completed, label)
		}
	}
	s.mu.Unlock()
	s.saveJob()
}

// jobStatus 返回当前内部任务状态字符串（running/done/canceled/timeout），无任务时为空。
func (s *store) jobStatus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.job == nil {
		return ""
	}
	return s.job.Status
}

// setJobStatus 更新任务状态(running/done/canceled/timeout/limit)并落盘。
func (s *store) setJobStatus(status string) {
	s.mu.Lock()
	if s.job != nil {
		s.job.Status = status
	}
	s.mu.Unlock()
	s.saveJob()
}

// loadJob 从盘加载任务描述到内存,返回该任务(无则 nil)。
func (s *store) loadJob() *scanJob {
	jobP := s.jobPath()
	if jobP == "" {
		return nil
	}
	buf, err := os.ReadFile(jobP)
	if err != nil {
		return nil
	}
	var j scanJob
	if err := json.Unmarshal(buf, &j); err != nil {
		return nil
	}
	s.mu.Lock()
	s.job = &j
	// 进程曾在扫描中途退出(status 仍为 running)或有剩余目标 → 标记可续扫。
	if !s.st.Running && j.Status != "done" && j.remaining() > 0 {
		s.st.Resumable = true
	}
	s.mu.Unlock()
	return &j
}

// resumeInfo 返回可续扫任务及其已完成目标集合(供 handler 续扫用)。
func (s *store) resumeInfo() (*scanJob, map[string]bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.job == nil || s.job.Status == "done" || s.job.remaining() <= 0 {
		return nil, nil
	}
	done := make(map[string]bool, len(s.job.Completed))
	for _, c := range s.job.Completed {
		done[c] = true
	}
	return s.job, done
}

func (s *store) seed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) > 0 {
		return
	}
	s.st.Demo = true
	s.data = []Hit{
		{
			ID: "bk-01", URL: "https://www.bank-corp.com/www.zip", File: "www.zip", Kind: "源码",
			Size: "48.2 MB", Code: 200, Rule: "备份字典: {host}.zip", Host: "www.bank-corp.com",
			Severity: "高危", At: "2026-05-30 10:02", Note: "整站源码打包,可直接下载(演示)",
			Detail: "以站点域名拼接常见备份后缀命中整站源码打包文件。演练中仅通过 HEAD 请求确认文件存在并读取 Content-Length,未下载文件体,未还原任何源码。",
			Sample: "[演示·已脱敏] HEAD 响应表明为 ZIP 归档(magic PK..),含 web 根目录结构;具体文件内容未读取。",
			Evidence: Evidence{
				Request:  "HEAD /www.zip HTTP/1.1\nHost: www.bank-corp.com",
				Response: "HTTP/1.1 200 OK\nContent-Type: application/zip\nContent-Length: 50535219\n[演示] 仅凭状态码 + 类型 + 长度判定存在,未读取文件体",
				Note:     "仅 HEAD 探测存在性,未发起 GET 下载;不获取任何源码内容。",
			},
			Remediation: "立即从 Web 根目录移除打包文件;禁止将备份产物置于可对外访问目录;在反代/WAF 拦截 .zip/.rar/.tar.gz 等归档后缀直接访问。",
			Refs:        []string{"OWASP: Backup/Source Code Disclosure", "字典: common-backups.txt"},
			Chain:       []string{"扫描打点: 收敛存活站点", "备份探测: 域名拼接备份字典", "存在性探测: HEAD 确认 200"},
		},
		{
			ID: "bk-02", URL: "https://www.bank-corp.com/web.rar", File: "web.rar", Kind: "源码",
			Size: "31.7 MB", Code: 200, Rule: "备份字典: web.rar", Host: "www.bank-corp.com",
			Severity: "高危", At: "2026-05-30 10:02", Note: "源码备份,含配置目录",
			Detail: "命中 web.rar 源码备份,文件较大。仅做 Range 首字节探测确认为 RAR 归档,未下载完整文件。",
			Sample: "[演示·已脱敏] Range 首 16 字节匹配 RAR 文件头(Rar!..);未解包、未读取内部文件。",
			Evidence: Evidence{
				Request:  "GET /web.rar HTTP/1.1\nHost: www.bank-corp.com\nRange: bytes=0-15",
				Response: "HTTP/1.1 206 Partial Content\nContent-Range: bytes 0-15/33240000\n[演示] 首字节为 RAR 魔数 → 判定为源码归档",
				Note:     "仅请求前 16 字节做文件类型识别,不下载文件体。",
			},
			Remediation: "下线源码备份;约束打包脚本输出目录;对历史遗留归档做一次全站清点。",
			Refs:        []string{"OWASP: Backup/Source Code Disclosure"},
			Chain:       []string{"备份探测: 域名拼接备份字典", "存在性探测: Range 首字节识别"},
		},
		{
			ID: "bk-03", URL: "https://oa.bank-corp.com/.git/config", File: ".git/", Kind: "源码",
			Size: "—", Code: 200, Rule: "VCS 泄露: /.git/config", Host: "oa.bank-corp.com",
			Severity: "高危", At: "2026-05-30 10:04", Note: "Git 泄露,可还原源码",
			Detail: "/.git/ 目录可匿名访问,存在 Git 仓库泄露,可借助 git-dumper 类工具还原完整源码与提交历史。演练仅读取 .git/config 文本确认泄露,未拉取对象包、未还原源码。",
			Sample: "[演示·已脱敏] .git/config 可读,确认存在 [core] / [remote] 段落结构;remote url 等敏感值已脱敏,未还原任何提交。",
			Evidence: Evidence{
				Request:  "GET /.git/config HTTP/1.1\nHost: oa.bank-corp.com",
				Response: "HTTP/1.1 200 OK\nContent-Type: text/plain\n[演示] 响应含 [core]/[remote] 配置结构(值已脱敏) → 判定 Git 泄露",
				Note:     "仅读取 config 文本确认泄露,未下载 objects、未执行还原。",
			},
			Remediation: "禁止部署 .git 目录到生产;在 Web 服务器拦截 /.git/ 路径;采用构建产物部署而非整仓上传。",
			Refs:        []string{"CWE-527 VCS Repository Exposure", "工具: git-dumper(仅说明,未使用)"},
			Chain:       []string{"备份探测: VCS 路径字典", "存在性探测: 读取 .git/config"},
		},
		{
			ID: "bk-04", URL: "https://203.0.113.18/backup.sql", File: "backup.sql", Kind: "数据库",
			Size: "212 MB", Code: 200, Rule: "备份字典: backup.sql", Host: "203.0.113.18",
			Severity: "高危", At: "2026-05-30 10:06", Note: "疑似全库导出,含用户表",
			Detail: "命中 MySQL 文本导出文件,体积大,极可能包含用户与交易数据。演练仅 HEAD 确认存在与体积,未下载、未读取任何记录。",
			Sample: "[演示·已脱敏] HEAD 表明为大体积 text/plain SQL 导出;按文件名推断含用户表,具体记录未读取、未落盘。",
			Evidence: Evidence{
				Request:  "HEAD /backup.sql HTTP/1.1\nHost: 203.0.113.18",
				Response: "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 222298112\n[演示] 大体积 SQL 导出 → 高危数据泄露面",
				Note:     "仅 HEAD 探测;不下载、不解析任何数据库记录。",
			},
			Remediation: "立即下线数据库导出文件并评估泄露影响;导出文件禁止置于 Web 目录;落地加密 + 访问审计;视情况启动数据泄露应急。",
			Refs:        []string{"OWASP: Sensitive Data Exposure", "字典: db-backups.txt"},
			Chain:       []string{"备份探测: 数据库备份字典", "存在性探测: HEAD 确认体积"},
		},
		{
			ID: "bk-05", URL: "https://203.0.113.18/db_2026.bak", File: "db_2026.bak", Kind: "数据库",
			Size: "1.1 GB", Code: 200, Rule: "备份字典: db_{year}.bak", Host: "203.0.113.18",
			Severity: "高危", At: "2026-05-30 10:06", Note: "SQL Server 备份(.bak)",
			Detail: "命中 SQL Server 备份文件,体积超 1GB。仅 HEAD 确认存在,未下载、未还原数据库。",
			Sample: "[演示·已脱敏] HEAD 表明为大体积二进制 .bak;内容未读取,未尝试 RESTORE。",
			Evidence: Evidence{
				Request:  "HEAD /db_2026.bak HTTP/1.1\nHost: 203.0.113.18",
				Response: "HTTP/1.1 200 OK\nContent-Type: application/octet-stream\nContent-Length: 1181116006\n[演示] 大体积数据库备份 → 高危",
				Note:     "仅 HEAD 探测存在性;不下载、不还原。",
			},
			Remediation: "下线 .bak 备份;数据库备份存放于隔离的内网备份域,禁止 Web 可达;启用最小权限与加密。",
			Refs:        []string{"OWASP: Sensitive Data Exposure"},
			Chain:       []string{"备份探测: 数据库备份字典", "存在性探测: HEAD 确认体积"},
		},
		{
			ID: "bk-06", URL: "https://oa.bank-corp.com/config.php.bak", File: "config.php.bak", Kind: "配置",
			Size: "3.4 KB", Code: 200, Rule: "备份字典: {file}.bak", Host: "oa.bank-corp.com",
			Severity: "高危", At: "2026-05-30 10:08", Note: "疑似含数据库连接串",
			Detail: "编辑器/部署遗留的 .bak 文件可被当作文本读取(不经 PHP 解析),极可能暴露数据库连接串等配置。演练仅 HEAD + 极小 Range 确认为文本配置,未读取连接串明文。",
			Sample: "[演示·已脱敏] Range 首部为 PHP 配置文本(<?php 起始,含 db 配置数组键名);连接串、口令等值已脱敏,未读取真实凭据。",
			Evidence: Evidence{
				Request:  "GET /config.php.bak HTTP/1.1\nHost: oa.bank-corp.com\nRange: bytes=0-127",
				Response: "HTTP/1.1 206 Partial Content\nContent-Type: text/plain\n[演示] 首部为 PHP 配置文本(键名可见,值已脱敏) → 判定配置泄露",
				Note:     "仅读取前 128 字节识别文件类型;不提取任何凭据值。",
			},
			Remediation: "删除所有 .bak/.old/.swp 编辑器遗留文件;轮换疑似暴露的数据库口令;在服务器禁止以文本返回 .bak 后缀。",
			Refs:        []string{"CWE-538 File and Directory Information Exposure", "字典: config-backups.txt"},
			Chain:       []string{"备份探测: 配置文件备份字典", "存在性探测: Range 文本类型识别"},
		},
		{
			ID: "bk-07", URL: "https://www.bank-corp.com/.env", File: ".env", Kind: "配置",
			Size: "1.2 KB", Code: 200, Rule: "敏感文件: /.env", Host: "www.bank-corp.com",
			Severity: "高危", At: "2026-05-30 10:08", Note: "疑似含 AK/SK、密钥",
			Detail: ".env 环境变量文件可匿名访问,通常含云 AK/SK、数据库口令、第三方密钥。演练仅 HEAD + 极小 Range 确认为 dotenv 文本,未读取任何密钥值。",
			Sample: "[演示·已脱敏] Range 首部为 KEY=VALUE 形式 dotenv 文本(键名如 DB_/APP_KEY 可见);所有 value 已脱敏,未读取真实密钥。",
			Evidence: Evidence{
				Request:  "GET /.env HTTP/1.1\nHost: www.bank-corp.com\nRange: bytes=0-63",
				Response: "HTTP/1.1 206 Partial Content\nContent-Type: text/plain\n[演示] 首部为 dotenv 文本(键名可见,值已脱敏) → 判定密钥泄露面",
				Note:     "仅读取前 64 字节识别格式;不提取任何 AK/SK 或口令值。",
			},
			Remediation: "立即下线 .env 并轮换其中全部密钥/口令;在 Web 服务器拦截 dotfile;敏感配置改由密钥管理服务下发。",
			Refs:        []string{"CWE-538 File and Directory Information Exposure", "字典: sensitive-files.txt"},
			Chain:       []string{"备份探测: 敏感文件字典", "存在性探测: Range 格式识别"},
		},
		{
			ID: "bk-08", URL: "https://www.bank-corp.com/WEB-INF/web.xml.bak", File: "web.xml.bak", Kind: "配置",
			Size: "6.8 KB", Code: 200, Rule: "备份字典: WEB-INF/{file}.bak", Host: "www.bank-corp.com",
			Severity: "中危", At: "2026-05-30 10:10", Note: "Java 应用部署描述符",
			Detail: "WEB-INF 下的 web.xml.bak 可被直接读取(.bak 绕过了对 WEB-INF 的保护),暴露 Servlet 映射与框架配置。演练仅 HEAD 确认存在,未读取 XML 内容。",
			Sample: "[演示·已脱敏] HEAD 表明为 text/xml 配置文件;Servlet 映射等结构未读取。",
			Evidence: Evidence{
				Request:  "HEAD /WEB-INF/web.xml.bak HTTP/1.1\nHost: www.bank-corp.com",
				Response: "HTTP/1.1 200 OK\nContent-Type: text/xml\nContent-Length: 6963\n[演示] WEB-INF 配置经 .bak 后缀绕过保护 → 配置泄露",
				Note:     "仅 HEAD 探测存在性;不读取 XML 内容。",
			},
			Remediation: "清理 WEB-INF 下的 .bak 文件;确认中间件对 WEB-INF 的访问保护覆盖所有后缀变体。",
			Refs:        []string{"CWE-538 File and Directory Information Exposure"},
			Chain:       []string{"备份探测: WEB-INF 备份字典", "存在性探测: HEAD 确认"},
		},
		{
			ID: "bk-09", URL: "https://203.0.113.18/upload/test.tar.gz", File: "test.tar.gz", Kind: "其它",
			Size: "8.9 MB", Code: 200, Rule: "备份字典: upload/*.tar.gz", Host: "203.0.113.18",
			Severity: "低危", At: "2026-05-30 10:12", Note: "上传目录临时打包,含日志",
			Detail: "上传目录下遗留临时打包文件,疑似含运行日志。演练仅 HEAD + Range 首字节确认为 gzip 归档,未下载、未解包。",
			Sample: "[演示·已脱敏] Range 首字节匹配 gzip 魔数(1f 8b);按文件名推断含日志,内部内容未读取。",
			Evidence: Evidence{
				Request:  "GET /upload/test.tar.gz HTTP/1.1\nHost: 203.0.113.18\nRange: bytes=0-7",
				Response: "HTTP/1.1 206 Partial Content\n[演示] 首字节为 gzip 魔数 → 判定为打包归档",
				Note:     "仅读取前 8 字节识别类型;不下载、不解包。",
			},
			Remediation: "清理上传目录下的临时归档;对 upload 目录禁用目录列举与归档后缀直接下载;评估日志中是否含敏感信息。",
			Refs:        []string{"字典: common-backups.txt"},
			Chain:       []string{"备份探测: 上传目录字典", "存在性探测: Range 首字节识别"},
		},
		{
			ID: "bk-10", URL: "https://oa.bank-corp.com/admin/data.zip", File: "data.zip", Kind: "其它",
			Size: "15 MB", Code: 403, Rule: "备份字典: admin/data.zip", Host: "oa.bank-corp.com",
			Severity: "中危", At: "2026-05-30 10:12", Note: "存在但 403,可尝试绕过",
			Detail: "命中疑似数据打包文件,但当前返回 403(存在但被拒绝)。演练仅记录该路径存在受限资源,未尝试任何鉴权/路径绕过下载。",
			Sample: "[演示·已脱敏] 返回 403 仅说明资源存在但被拒绝;未读取任何内容,未做绕过尝试。",
			Evidence: Evidence{
				Request:  "HEAD /admin/data.zip HTTP/1.1\nHost: oa.bank-corp.com",
				Response: "HTTP/1.1 403 Forbidden\n[演示] 403 表明资源存在但访问受限 → 标记待评估",
				Note:     "仅 HEAD 探测,得到 403 即停止;未尝试绕过或越权下载。",
			},
			Remediation: "确认该归档为何置于 Web 可达目录并下线;复核 admin 目录访问控制是否对所有方法/后缀一致生效。",
			Refs:        []string{"字典: db-backups.txt"},
			Chain:       []string{"备份探测: admin 目录字典", "存在性探测: HEAD 得到 403"},
		},
	}
}

func (s *store) list() []Hit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Hit, len(s.data))
	copy(out, s.data)
	return out
}

// summary 给 /stats 用 —— 与 vulnscan / operations 模块对齐,前端磁贴据此渲染。
// 风险等级计数只统计可访问(状态码 < 300)的命中,避免把 403/404 也算进危害面。
func (s *store) summary() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sev := map[string]int{"高危": 0, "中危": 0, "低危": 0}
	kind := map[string]int{"源码": 0, "数据库": 0, "配置": 0, "其它": 0}
	hosts := map[string]struct{}{}
	accessible := 0
	for _, h := range s.data {
		kind[h.Kind]++
		hosts[h.Host] = struct{}{}
		if h.Code < 300 {
			accessible++
			sev[h.Severity]++
		}
	}
	return map[string]any{
		"total":      len(s.data),
		"accessible": accessible,
		"hosts":      len(hosts),
		"high":       sev["高危"],
		"med":        sev["中危"],
		"low":        sev["低危"],
		"src":        kind["源码"],
		"db":         kind["数据库"],
		"conf":       kind["配置"],
		"other":      kind["其它"],
		"demo":       s.st.Demo,
	}
}

// ---- 扫描任务状态机 ----

// beginScan 开始一次扫描:复位计数、标记运行中。keepHits=false 清空旧命中(全新扫描);
// keepHits=true 保留已有命中(断点续扫,在原结果上追加)。
func (s *store) beginScan(target string, keepHits bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !keepHits {
		s.data = nil
	}
	s.st = scanStatus{Running: true, Target: target, StartedAt: nowStamp(), Demo: false, Found: len(s.data)}
}

// tryBeginScan 原子地检查并设置运行态，防止并发双启动（TOCTOU）。
// 若已在运行返回 false；否则等价于 beginScan，返回 true。
func (s *store) tryBeginScan(target string, keepHits bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Running {
		return false
	}
	if !keepHits {
		s.data = nil
	}
	s.st = scanStatus{Running: true, Target: target, StartedAt: nowStamp(), Demo: false, Found: len(s.data)}
	return true
}

// tryBeginScanWithCancel 原子地设置运行态+cancel，消除 tryBeginScan+setCancel 之间的 TOCTOU 窗口：
// 若 stop() 在两步之间到达会因 cancel==nil 而静默失效，导致扫描不可停止。
func (s *store) tryBeginScanWithCancel(target string, keepHits bool, cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Running {
		return false
	}
	if !keepHits {
		s.data = nil
	}
	s.st = scanStatus{Running: true, Target: target, StartedAt: nowStamp(), Demo: false, Found: len(s.data)}
	s.cancel = cancel
	return true
}

// tryBeginResume 原子地检查 Running + 提取续扫信息 + 设置运行态，防止 TOCTOU。
// 无可续扫任务或已在运行时返回 (nil, nil, false)。
func (s *store) tryBeginResume() (*scanJob, map[string]bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Running {
		return nil, nil, false
	}
	if s.job == nil || s.job.Status == "done" || s.job.remaining() <= 0 {
		return nil, nil, false
	}
	done := make(map[string]bool, len(s.job.Completed))
	for _, c := range s.job.Completed {
		done[c] = true
	}
	s.st = scanStatus{Running: true, Target: "(续扫中…)", StartedAt: nowStamp(), Demo: false, Found: len(s.data)}
	return s.job, done, true
}

func (s *store) setTarget(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Target = t
}

func (s *store) setTotal(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Total = n
}

// addTotal 动态增加候选总数 —— 递归发现新目录时按需扩容进度分母。
func (s *store) addTotal(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Total += n
}

func (s *store) incProbed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Probed++
}

func (s *store) addHit(h Hit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append(s.data, h)
	s.st.Found++
}

func (s *store) finishScan(errMsg string) {
	s.mu.Lock()
	fn := s.cancel
	s.st.Running = false
	s.st.EndedAt = nowStamp()
	s.st.Err = errMsg
	s.cancel = nil
	s.mu.Unlock()
	// 扫描自然结束（非用户 stop）时也必须调用 cancel 释放 context 资源，防止 context goroutine 泄漏。
	if fn != nil {
		fn()
	}
}

func (s *store) status() scanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.st
	// 未在运行、且存在未完成任务 → 可续扫(动态计算,避免状态漂移)。
	st.Resumable = !st.Running && s.job != nil && s.job.Status != "done" && s.job.remaining() > 0
	return st
}

func (s *store) setCancel(fn context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancel = fn
}

// stop 取消正在运行的扫描(若有)。
func (s *store) stop() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil && s.st.Running {
		s.cancel()
		return true
	}
	return false
}
