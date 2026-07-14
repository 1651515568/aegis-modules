# scan-dir 变更记录

## 0.7.2 — clusterbomb 边界测试

### ✨ 新增

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **TestCombineWordsEdgeCases** | 补全 `combineWords` 边界用例：空 w1/w2、1×1、pitchfork 不等长取短、未知 mode 退化 clusterbomb，共 7 个断言。 | `scanner_test.go` |
| **TestScanClusterbombEndToEnd** | mock HTTP server 验证 2×2=4 次请求全部发出（通过服务端计数），且仅正确组合命中 200，防止 clusterbomb 笛卡尔积漏发。 | `scanner_test.go` |

### ✅ 测试

`go vet` 干净，全部测试通过。

---

## 0.7.1 — HEAD→GET 自动切换专项测试

### ✨ 新增

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **TestScanHeadAutoSwitchMethod** | 端到端验证：Method=HEAD 且设置 FilterWords 时，引擎实际发出的请求全部为 GET（通过 mock server 记录 `r.Method` 逐一断言），防止 v0.7.0 修复被回归。 | `scanner_test.go` |

### ✅ 测试

`go vet` 干净，scan-dir 全部测试通过（含新增 HEAD→GET 专项测试）。

---

## 0.7.0 — HEAD→GET 自动切换

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **HEAD+过滤器自动切换 GET(P1)** | `method=HEAD` 且同时设置了 `filterWords`/`filterLines` 时，v0.6.0 仅打 `Warn` 日志，用户无感知静默漏报。v0.7.0 改为自动将 `method` 切换为 `GET`，并通过 `log.Info` + `store.setPhase` 通知用户，消除因 HEAD 无响应体导致过滤器永远匹配 0 的漏报问题。 | `scanner.go` |

### ✅ 用户可见行为

- 无感知切换：扫描结果正确，日志中有一条 Info 说明 + 扫描状态栏短暂提示。
- `filterLength`（依赖 Content-Length，HEAD 响应含此头）不触发切换。
- 测试：40+ 用例全部通过，`go vet` 干净。

---

## 0.6.0 — 并发提升 + looksLikeDir 修复 + UA 池扩充 + HEAD 过滤告警

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **并发上限提升(P1)** | `conc > 64` 硬限改为 `conc > 256`，适配内网高带宽、低延迟场景；原默认值 20 不变，用户可按需配置高并发。 | `scanner.go` |
| **looksLikeDir 修复(P2)** | 旧逻辑 `!strings.Contains(word,".")` 将 `.htaccess`/`.git`/`.env` 等以点开头的特殊文件名一律排除在目录递归之外，导致 `.git/` 等实际目录不被递归。新逻辑：3xx→尾斜杠（最可靠）不变；200 时改为「词条以点开头 OR 无扩展名」且响应 Content-Type 含 `text/html` 才推断为目录。 | `scanner.go` |
| **UA 池扩充(P3)** | 从 5 个扩充到 **23 个**，覆盖 Chrome/Firefox/Safari/Edge/Opera/Android/iPhone/Googlebot/curl 多平台多版本，大幅降低被单一 UA 特征封锁的概率。 | `scanner.go` |
| **HEAD+过滤器告警(P4)** | `method=HEAD` 且同时设置了 `filterWords`/`filterLines` 时，在日志中打 `Warn`：HEAD 模式不读响应体，`-fw/-fl` 过滤器永远匹配到 0，实际不生效，避免用户困惑。 | `scanner.go` |

### ✅ 测试

旧有 40+ 测试通过，`go vet` 干净。
新增 `looksLikeDir` 边界用例（.htaccess、.git、普通无扩展名目录、有扩展名文件）。

---

## 0.5.0 — 断点续扫 + 超大字典 + 多关键字 + 敏感度分级

补完评估中列出的四项增强,接近主流工具完整能力。

- **断点续扫(feroxbuster/dirsearch resume)**:全局 BFS 队列,每个基目录扫完即检查点落盘
  (剩余队列 + 已完成集合);被中断后 `GET /scan/status` 返回 `resumable=true`,`POST /scan/resume`
  从断点继续、保留已有命中、跳过已扫目录。命中按 URL 去重(递归/抽链/续扫不重复)。
- **超大字典支持**:作业改为从词条切片流式构造(不再每基目录物化 12 万级 job 切片),
  词条上限提至 26 万,可直接吃下 `directory-list-2.3-medium`(投放到外部字典目录即可)。
- **多关键字 clusterbomb / pitchfork(ffuf 多 -w)**:第二关键字 `FUZ2Z` + 第二字典,
  clusterbomb(笛卡尔积)或 pitchfork(按下标并行)。典型用法:`u=FUZZ&p=FUZ2Z` 配对爆破。
- **命中敏感度分级**:`classify.go` 按路径/扩展名把命中分到 critical/high/medium/low/info 并给中文
  类别(VCS 泄露、.env、密钥、数据库/备份、管理后台、调试端点、API 文档…)。前端按敏感度降序、
  SeverityTag 高亮,新增「高危命中」统计;归档表新增 severity/kind 列,任务详情页同步展示。

### 测试
新增:命中去重、resume 机制与端到端续扫、combine/split、pitchfork 端到端、classify 分级。
全模块 **40+ 测试**通过,`go vet` 干净。

---

## 0.4.0 — 上游代理 + 任意方法/请求体 fuzzing

- **上游代理(ffuf -x / dirsearch --proxy / feroxbuster --proxy)**:新增 `proxy` 参数,支持
  `http(s)://` 与 `socks5://`,经 Burp 等代理转发或内网跳板。启动前校验,非法即失败。
- **任意 HTTP 方法 + 请求体(ffuf -X / -d)**:`method` 放开为任意方法(GET/HEAD/POST/PUT/DELETE/
  PATCH/OPTIONS),新增 `requestBody`;非 GET/HEAD 时发送(默认表单 Content-Type,可被请求头覆盖)。
- **FUZZ 多位置定位(ffuf)**:FUZZ 关键字现可同时落在 URL、请求体、请求头键/值——支持 POST 参数
  fuzzing、Header fuzzing 等;任一位置含 FUZZ 即进入扁平 FUZZ 模式。
- 内部:请求参数收束为 `reqSpec`,probe/doRequest 透传请求体与逐请求请求头。

### 测试
新增:请求头 FUZZ 助手、POST + `requestBody=user=FUZZ` 端到端(仅 admin 命中)、非法 proxy 失败。
`go test`/`go vet` 通过。

---

## 0.3.0 — 生产级软 404 + 备份/源码泄露衍生

补齐评估出的两处关键短板,把软 404 抗扰与命中后衍生能力提升到生产级。

- **动态软 404 相似度判定(ffuf -ac / dirsearch DynamicContentParser / feroxbuster auto-filter)**:
  原先软 404 仅比 Content-Length,挡不住「对任意路径回 200 且把请求路径回显进模板」的动态页
  (长度每次漂移)。新增 `similarity.go`:校准时记录 wildcard 响应体头部样本(≤2KB),运行期对
  同状态命中用 Sørensen–Dice 字节二元组相似度比对,≥0.92 判为同质模板页并抑制——既挡住动态噪声,
  又放过正文显著不同的真实命中。静态(长度近似)快路径保留。
- **备份/源码泄露衍生(feroxbuster --collect-backups)**:命中文件(2xx + 含扩展名)时自动衍生
  `.bak`/`~`/`.old`/`.save`/`.orig`/`.swp`/`.tmp`/`.1`/`.zip`/`.tar.gz`/`.rar` 及 vim `.<name>.swp`
  变体并探测,捕获常见源码/配置泄露。与抽链共用「扩展发现」二次探测通道,不二次放大。

### 测试
新增:相似度函数(模板页高相似/异质低相似)、备份变体生成、动态软 404 端到端(仅保留正文不同者)。
`go test`/`go vet` 通过。

---

## 0.2.0 — 对标主流工具:权威字典 + 设计移植

参考 dirsearch / ffuf / feroxbuster / gobuster / dirb 的设计与实现,并整入业内权威字典。

### 内置权威字典(取自上游,随引擎编译;见 wordlists/)
| id | 来源 | 规模 |
|---|---|---|
| `quickhits` | SecLists Discovery/Web-Content/quickhits.txt | ~2.5k |
| `api` | SecLists api/api-endpoints.txt | ~0.3k |
| `common` | SecLists common.txt(含 dirb/dirbuster) | ~4.7k |
| `dirsearch` | dirsearch db/dicc.txt(含 `%EXT%` 占位符) | ~9.6k |
| `raft-files` | SecLists raft-medium-files.txt | ~17k |
| `raft-dirs` | SecLists raft-medium-directories.txt | ~30k |

- **外部字典(运行时投放,免重编译)**:把任意 `.txt` 丢进 `data/scan-dir/wordlists/`,即以
  `file:<名>` 出现在可选列表(`GET /dict` 可见)。便于直接接入 SecLists
  `directory-list-2.3-medium`、OneListForAll、ffuf/feroxbuster 自带等超大字典。含目录穿越防护。

### 从主流工具移植的设计
- **`%EXT%` 占位符 + 扩展名展开(dirsearch)**:词条含 `%EXT%` 按扩展名逐个替换;无占位符的目录型
  词条按 force-extensions 追加扩展名(等价 ffuf `-e` / dirsearch `-f`)。
- **FUZZ 关键字定位(ffuf)**:目标含 `FUZZ` 时逐词替换该位置(可 fuzz 路径段/查询值等),扁平探测。
- **响应匹配/过滤(ffuf matchers/filters)**:状态码白/黑名单(`-mc/-fc`)、大小/词数/行数过滤
  (`-fs/-fw/-fl`)、正文正则匹配/过滤(`-mr/-fr`,亦即 dirsearch `--exclude-texts`)、
  响应大小区间(dirsearch `--minimal/--maximal`)。
- **链接抽取爬取(feroxbuster `--extract-links` / dirsearch `--crawl`)**:对命中响应(HTML/JS/JSON)
  抽取同主机链接(href/src/action、JS 引号路径、robots.txt)回灌探测,发现「未链接 + 已链接」内容。
- **前缀/后缀变体(dirsearch `--prefixes/--suffixes`)**。
- **随机 User-Agent(dirsearch random-agent)**:UA 池轮换。
- **wildcard/软 404 自动校准(ffuf `-ac` / feroxbuster auto-filter)**:已在 0.1.0 实现。

### 安全上限调整
- 词条展开上限提至 120000(容纳 raft-medium);抽链每响应 ≤200 链接、不对抽链结果二次抽链。

### 测试
新增:`%EXT%`/前后缀展开、内置字典加载、外部字典名穿越防护、链接抽取、FUZZ 校验、
正文正则与大小区间过滤、crawl 端到端发现、FUZZ 端到端等用例。`go test`/`go vet` 通过。

---

## 0.1.0 — 初版(目录/文件爆破)

新增「目录扫描」能力(AEGIS id: `scan-dir`,Go 包名 `scandir`),按《AEGIS 能力模块开发规范》
与参考模块 `scan-port` / `scan-backup` 同构实现。

### 能力概述
对授权 Web 目标做目录与文件爆破,识别隐藏路径、后台入口与敏感文件。

### 核心特性
- **字典 × 扩展名展开**:内置精选通用字典(`wordlists/common.txt`,取材 SecLists/raft/dirbuster);
  预设 small / common / big,或自定义词条。对目录型词条 × 扩展名做笛卡尔积(`admin` × `[php,bak]`
  → `admin`、`admin.php`、`admin.bak`);已含扩展名的具体文件名(`index.php`、`.env`)不再追加。
- **软 404(wildcard)基线过滤**:每个基目录先打 2 个随机不存在路径,若站点对任意路径都回
  「存在类」状态且页面同质,则把同状态 + 同长度(容差 48B)的响应判为软 404 抑制,避免海量误报。
- **状态码过滤**:`statusInclude`(仅保留,支持 `200-299` 区间)/ `statusExclude`(默认排除 404)。
- **递归发现**:对目录型命中(200 无扩展名 / 30x 跳到尾斜杠)按 BFS 递归爆破,深度可配(0–3),
  受去重 + 基目录数硬上限(200)约束,防递归爆炸。
- **限速与退避**:全局最小间隔限速器(`rate` req/s,0=不限)+ 429/503 自适应退避 +
  瞬时网络错误重试(`limiter.go`)。
- **并发与超时**:并发上限 64,单请求超时可配;响应体读取上限 512KB(用于长度/词/行统计与软 404 比对)。
- **请求定制**:GET/HEAD、自定义 User-Agent、附加请求头(`Key: Value`)、可选跟随 30x。

### 契约与持久化
- 统一异步契约:`GET /functions`、`POST /invoke`(透传系统 task_id 立即返回)、`GET /tasks/<id>`、
  `GET /findings?taskId=`。
- 实时/辅助视图:`GET /hits`、`GET /dict`、`GET /export?format=json|csv|html`、`GET /scan/status`、
  `POST /scan`、`POST /scan/stop`、`GET /history`、`GET /history/get?id=`、`POST /history/delete`。
- 自有表 `m_scan_dir_findings`(按 task_id 归档命中)、`m_scan_dir_task_runs`(框架托管任务运行)。
- `k.DB` 为 nil 时相关接口降级 503,不 panic。
- **无外传/无回连**:仅对用户给定目标发起 HTTP 探测,不向 AEGIS 之外上报。

### 安全上限
- 词条展开上限 20000;递归基目录上限 200;并发上限 64;响应体读取上限 512KB。

### 测试
`scanner_test.go` 覆盖:字典解析/扩展名展开/目标规范化/状态码集合/请求头解析等纯函数、
软 404 抑制逻辑、限速器间隔、Retry-After 解析;并以本地 httptest 站点做端到端爆破、
wildcard 抑制、取消三类集成测试。`go test ./modules/scan-dir/...` 通过,`go vet` 无告警。

### 对现有代码的改动
- `src/lib/engineTasks.ts`:`FINDINGS_CAPABILITIES` 增加 `scan-dir`;`FindingRow` 把 `host` 改可选并
  新增目录扫描字段(path/status/length/words/lines/redirect/contentType/depth)。向后兼容。
- `src/pages/TaskDetail.tsx`:`TaskFindings` 渲染新增 `r.path !== undefined` 分支(目录命中:状态码 +
  路径 + 长度 + 跳转),并加 `dirCodeClass` 配色辅助。其余能力渲染不受影响。
- 未手改 `main.go` / `modules_gen.go` / `go.mod` / `core/`。
