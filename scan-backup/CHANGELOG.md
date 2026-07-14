# 备份文件模块（backup）变更说明

> 模块定位：对已授权目标做**未授权可达的备份 / 敏感文件与源码泄露**的「存在性探测」。
> 安全口径：默认仅 `HEAD` + `Range ≤16B` 判存在；对疑似泄露文件**绝不下载其文件体**。

---

## v0.9.0 — 内嵌字典 + 自定义粘贴字典

### ✨ 新增

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **内嵌字典文件(P1)** | 新增 `wordlists/raft-medium-files.txt`（精选 ~580 条常见 Web 文件名，覆盖 PHP/ASP/JSP/配置/备份/日志/密钥/CMS/框架/开发残留等）和 `wordlists/raft-medium-dirs.txt`（精选 ~380 条常见目录名）。两者通过 `//go:embed` 嵌入二进制，扫描时无需网络。 | `dict.go`、`wordlists/*.txt` |
| **embeddedPreset() 查找** | `dict.go` 新增 `embeddedPreset(name string)` 函数，按预置名返回已内嵌字典；`LoadExternalDict` 优先走该路径，命中即直接返回，跳过缓存/下载流程。 | `dict.go`、`extdict.go` |
| **自定义粘贴字典(P2)** | `scanOptions` 新增 `CustomWordlistText string` 字段；`runScan` 在外部字典加载后调用 `parseList` 解析粘贴文本并追加到 extDict 列表，去重由 `enqueue` 的 `seen` map 自动保证。 | `scanner.go` |
| **functions.go 参数更新** | `extraWordlist` 选项新增「内置 raft-medium-files」/「内置 raft-medium-dirs」两档（标注「离线可用」）；新增 `customWordlistText` ParamStringList 参数，前端渲染为多行文本框，与扩展字典叠加使用。 | `functions.go` |

### 🔧 字典加载优先级

```
内嵌预置 (embeddedPreset) → 磁盘缓存 (data/backup/dicts/) → 网络下载
```
内嵌预置的预设名（`raft-medium-files` / `raft-medium-dirs`）不再出现在 `presetWordlists` 下载表中，彻底离线可用。

### ✅ 测试

新增 5 项：`TestEmbeddedDictsLoaded` / `TestEmbeddedPresetLookup` / `TestCustomWordlistTextMerged` / `TestCustomWordlistTextDeduplicatedByScanner`。`go vet` 干净，47 项测试全部通过。

---

## v0.8.0 — 外部字典下载与缓存

### ✨ 新增

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **外部字典支持(P1)** | 新增 `extdict.go`：`LoadExternalDict` 函数支持 6 个预置名（`raft-medium-files` / `raft-large-files` / `raft-medium-directories` / `raft-large-directories` / `common` / `dirsearch`）及任意 `https://` URL。首次下载缓存至 `data/backup/dicts/<hash>.txt`，后续扫描离线读缓存（永久有效，可手动删缓存目录刷新）。下载超时 90s，单文件上限 20 MB。 | `extdict.go` |
| **scanOptions 字段** | 新增 `ExtraWordlist`（预设名/URL）和 `ExtraWordlistURL`（自定义 URL，`ExtraWordlist="custom"` 时生效）；外部字典词条以 root 候选方式投放，与内置词典去重，不消耗递归预算。 | `scanner.go` |
| **functions.go 参数** | 新增 `extraWordlist` ParamSelect（7 档含不使用/6 预设/自定义）和 `extraWordlistURL` ParamString，前端渲染为下拉+输入框组合。 | `functions.go` |

### ✅ 测试

`go vet` 干净，全部测试通过。

---

## v0.7.0 — 鉴权支持 + common 词典 + 检测精度修复

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **请求级鉴权透传(P1)** | 新增 `Cookie` / `Authorization` 两个扫描参数，通过 `authTransport`（实现 `http.RoundTripper`）在每个请求上统一注入，覆盖 HEAD / Range / GET 全部探测方法，无需修改 `do`/`doMagicN`/`sampleBody` 签名。支持 Cookie 字符串（`key=value; key2=value2`）和 Authorization 头（`Bearer token` / `Basic b64`）两种鉴权形式，目标无需匿名可达。`functions.go` 同步新增两个 `ParamString` 参数。 | `scanner.go`、`functions.go` |
| **common.txt 词典(P1)** | 新增 `wordlists/common.txt`（~450 条），覆盖管理后台/phpMyAdmin/WordPress/Joomla/Drupal/Laravel/Django/Rails/Spring Boot/Node.js/上传目录/备份目录/API 端点/调试端点/证书路径/常见配置目录，优先级仅次于 sensitvie.txt。四类词典合计实际路径 ~780 条（不含带日期/归档矩阵展开）。 | `wordlists/common.txt`、`dict.go` |

### 🐛 修复

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **looksLikeJSON 与 git-config 冲突(P1)** | `[{"key":"value"}]` 被错误识别为 git-config。修复：① `looksLikeJSON` 对 `[` 开头要求第二字节为 JSON 合法首字符；② 优先级链中 JSON 提前至 git-config 之前。 | `scanner.go` |

### ✅ 测试

| 测试 | 覆盖内容 |
|---|---|
| `TestAuthTransportInjectsCookieAndAuthorization` | mock server 验证 Cookie 和 Authorization 头被正确注入 |
| `TestBuildClientNoAuthTransportWhenEmpty` | 空鉴权时不包裹 authTransport |
| `TestCommonDictLoaded` | 断言 common 词典加载 ≥100 条 |
| `TestTextPatternLabel`(22 用例) + `TestLooksLikeFunctions`(11 断言) | 文本模式识别全函数覆盖 |

`go vet` 干净，全部测试通过。

---

## v0.6.1 — 检测精度修复 + 测试补全 + 词典扩充 Round 2

### 🐛 修复

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **looksLikeJSON 与 git-config 冲突(P1)** | `textPatternLabel` 中 git-config 分支（`b[0]=='['`）早于 `looksLikeJSON` 执行，导致 JSON 数组（`[{...}]`）被错误识别为 `git-config`。修复：① `looksLikeJSON` 对 `[` 开头的情况要求第二字节为 `{`/`"`/数字等 JSON 合法首字符；② 在 `textPatternLabel` 优先级链中将 `looksLikeJSON` 移至 git-config 检测之前。`[core]` 等真实 git-config 节头的第二字节为字母，不受影响。 | `scanner.go` |

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **TestTextPatternLabel(P1)** | 为 v0.6.0 新增的 `textPatternLabel` / `looksLikeYAML/JSON/XML/TOML` 补充单元测试，涵盖 pem/sql/env/git-config/yaml/json(对象+数组)/xml(声明+标签)/toml 及空串等边界 22 个用例。 | `scanner_test.go` |
| **TestLooksLikeFunctions** | 专项测试四个 `looksLike*` 函数的边界：空串、过短、正反例各一组，共 11 个断言。 | `scanner_test.go` |
| **词典 Round 2 扩充** | 新增约 80 条：Spring Boot Actuator 全端点（15条）、Kubernetes/Helm manifests（15条）、更多备份扩展变体（10条）、数据库 dump 文件名（10条）、更多日志/调试（8条）、源码打包泄露（10条）、WEB-INF/Java EE（5条）、Ruby/Python 运行时（8条）。合计词典条目约 380 行（含注释）。 | `wordlists/sensitive.txt` |

### ✅ 测试

`go vet` 干净，scan-backup 全部测试通过（含新增 22+11 个断言）。

---

## v0.6.0 — YAML/TOML/JSON/XML 文本模式识别 + 字典扩充

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **YAML/JSON/XML/TOML 识别(P1)** | `textPatternLabel()` 新增四类文本格式识别：`looksLikeYAML()`（`---` 或 `key: value`）、`looksLikeJSON()`（`{`/`[` 起始）、`looksLikeXML()`（`<?xml` 或元素起始标签）、`looksLikeTOML()`（`key = value` 含空格）。对 `docker-compose.yml`、`appsettings.json`、`config.toml` 等高价值配置文件在 soft-404 站点上不再漏报。 | `scanner.go` |
| **扩展名覆盖扩充(P1)** | `sensitiveTextExts` 新增 `.yml`/`.yaml`/`.toml`/`.json`/`.xml`，触发 64B 扩展探针；`sensitiveTextNames` 新增 `docker-compose.yml`、`application.yml`、`config.toml`、`settings.json` 等常见配置文件名。 | `scanner.go` |
| **字典补全(P2)** | `wordlists/sensitive.txt` 补充 `application-prod.yml`、`application-dev.yml`、`config.toml`、`Cargo.toml`、`settings.json`、`circle.yml`、`.github/workflows/deploy.yml` 等高价值路径，覆盖 Spring/Rust/.NET/GitHub Actions 场景。 | `wordlists/sensitive.txt` |

### ✅ 兼容性

- 无参数变更；新扩展名仅影响 64B 探针判断路径，不增加网络请求数。
- `looksLikeJSON` 仅在 `isSensitiveTextExt` 匹配（路径含 `.json` 等扩展）后才调用，不会与 HTML 软 404 冲突。

---

## v0.5.0 — 文本型敏感文件检测 + 性能上限提升 + 修复

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **文本型敏感文件检测(P1 Critical)** | `.env`/`.sql`/`id_rsa`/`.key` 等纯文本类高价值文件无二进制魔数。旧代码在 soft-404 站点上对此类文件仅能靠长度启发，动态 soft-404（长度不稳定）时全部漏报。v0.5.0 新增 `probeTextCap=64B` 扩展探针：对 `isSensitiveTextExt()` 匹配的路径读取 ≤64B 并运行 `textPatternLabel()`（识别 env/sql/pem/git-config 格式），成功识别后 `acceptCalibrated` 直接接受，不再依赖长度启发。| `scanner.go` |
| **魔数修复(P2)** | PHP 文件带 UTF-8 BOM（EF BB BF）前缀时旧代码无法识别 `<?php`；git config 要求 `[core]` 精确匹配，其他节区（`[user]`/`[remote "origin"]` 等）被漏判。新增 `hasPHPTag()` 跳过 BOM，git-config 改为「首字节 `[` 且 32 字节内含 `]`」宽松匹配。 | `scanner.go` |
| **并发/限速上限提升(P3)** | `Concurrency` 上限 32→**128**；`RatePerSec` 上限 100→**500**，适配高带宽内网扫描场景。`functions.go` 前端表单 Max 同步更新。 | `scanner.go` `functions.go` |
| **爬取候选优先级(P4)** | 爬取派生候选（命中率高）改为在字典候选**之前**投放，时长受限时优先消费高价值路径。 | `scanner.go` |

### 🐛 修复

- **移除死代码 `readBody bool`(P5)**：`do()` 的 `readBody` 参数自 v0.2.0 起恒为 `false`，移除参数和分支代码（同步更新 `recurse.go` 中的唯一调用点）。
- `doMagic` 重构为 `doMagicN(cap int)` + `doMagic()` 包装器，`cap` 参数化后可复用。

### 🔐 安全口径更新

- 文本型敏感文件读取上限 `probeTextCap=64B`（vs 二进制魔数 `probeReadCap=16B`），仍远小于文件体大小，满足「绝不下载文件体」承诺。
- `Evidence.Note` 同步更新说明三种探针场景（16B/64B/512B）。

### ⚙️ 参数变更

| 参数 | v0.4.0 | v0.5.0 |
|---|---|---|
| `concurrency` 上限 | 32 | **128** |
| `ratePerSec` 上限 | 100 | **500** |

### ✅ 测试覆盖

- 新增 `isSensitiveTextExt` / `textPatternLabel` / `looksLikeEnvContent` / `hasPHPTag` / `hasCloseBracket` 单元测试。
- 旧 38 个回归测试全部通过，`go vet` 干净。

---

## v0.4.0 — JS 挖掘 + 断点续扫

### ✨ 新增能力

| 能力 | 说明 | 关键文件 |
|---|---|---|
| **静态 JS 挖掘** | 爬取阶段抓 `.js` bundle / `.js.map` source map / `asset-manifest.json`,正则提取路径字面量与原始源码路径(剥离 webpack/vite 前缀、跳过 node_modules),喂入 discovery。SPA 站点链接藏在 JS 里也能挖到，无浏览器依赖（`fetchPage` 加 `limit` 参数，JS 上限 2MB） | `jsmine.go` |
| **断点续扫 + 增量落盘** | 扫描期间每 5s flush 命中（崩溃最多丢一个间隔）；持久化任务描述 `data/backup/job.json`（参数/已完成目标/状态）；每主机扫完即 checkpoint；`POST /scan/resume` 跳过已完成目标续跑（在原结果上追加）；重启自动检测未完成任务标记 `resumable`。取消/超时**不**误标主机完成，确保可续扫 | `store.go` `scanner.go` `recurse.go` |

新增 API：`POST /scan/resume`；`/scan/status` 增 `resumable` 字段。
测试：32 → **38**（+mineJS / looksLikePath / mineSourceMap / 续扫跳过 / 任务 checkpoint / 取消后可续扫）。

---

## v0.3.0 — 能力大幅增强

在 v0.2.0「真实存在性探测引擎」基础上，补齐字典 / 递归 / 爬取 / 结果管理 / 韧性 / 反误报六个方向，并修复一处安全隐患。

### ✨ 新增能力

| 能力 | 说明 | 关键文件 |
|---|---|---|
| **全局限速 + 自适应退避** | 进程内令牌间隔限速器（`RatePerSec`，默认 10/s）；命中 `429/503` 解析 `Retry-After` 否则指数退避，并全局降速 | `limiter.go` |
| **瞬时网络错误重试** | 连接重置 / 超时（非取消）退避重试 2 次，降低抖动漏报 | `limiter.go` `scanner.go` |
| **递归目录发现** | 探测高价值目录，确认存在后在其下递归投放高价值候选；动态队列 + 深度上限(`MaxDepth`) + 每主机预算 + 去重；三道防爆炸闸（仅干净 404 站点递归、预算封顶、深度封顶） | `recurse.go` |
| **智能爬取 / 链接提取** | 抓取目标普通页面 + `robots.txt` + `sitemap.xml`，提取真实文件名/目录；派生备份变体（已知文件→探其 `.bak/~/.old`）、直探泄露样文件、真实目录喂递归（`Crawl` / `MaxCrawlPages`） | `crawl.go` |
| **响应体相似度校准** | soft-404 站点用 Sørensen–Dice 二元组相似度比对 ≤512B 头部样本，替代「仅比 Content-Length」，对抗动态模板页 | `similarity.go` |
| **结果持久化** | 扫描完成/取消自动落盘 `data/backup/hits.json`（原子写），重启自动恢复 | `store.go` |
| **导出** | `GET /export?format=json\|csv\|html` 附件下载（CSV 带 UTF-8 BOM，HTML 为自包含报告） | `export.go` |
| **删除** | `POST /hits/clear`（清空+删文件）、`POST /hits/delete {id}`（删单条） | `handler.go` |
| **扫描时长上限** | `MaxDurationSec`，到点优雅停止并保存，区分「已取消 / 已达时长上限」 | `scanner.go` |

### 📚 字典扩充

| 词表 | v0.2.0 | v0.3.0 |
|---|---|---|
| archives（基名） | 57 | 173 |
| db-backups | 261 | 318 |
| sensitive | 95 | 264 |
| **带日期组合**（基名×9年×3分隔×8扩展，运行时生成） | — | 3024 |
| **baseEntries 合计** | **788** | **5050** |

价值优先排序：敏感文件 → 主机名归档 → 数据库导出 → 带日期备份(主机名优先) → 通用归档矩阵 → 编辑器后缀。

### 🐛 修复（安全）

- **`doMagic` 无上限排空 body**：读完 16B 后 `io.Copy(io.Discard, resp.Body)` 在服务器忽略 `Range` 回 `200`（整文件）时会把整份备份经网络拉下，违背「绝不下载文件体」承诺。已移除排空；新增 httptest 回归（服务器吐 8MB 时仅写出 ~16KB）。

### 🔐 安全口径调整（已如实更新文案）

- 默认 `HEAD` + `Range ≤16B`；soft-404 站点为区分真实文件与模板页**另读 ≤512B 头部**做相似度校准。
- 智能爬取仅获取目标**普通页面**（HTML/robots/sitemap，单页 ≤256KB）用于提链；对疑似**备份/敏感文件本身**仍只 ≤16/512B。
- 三处文案同步更新：前端免责声明、实测数据标记、每条命中的 `Evidence.Note`。

### ⚙️ 新增 / 变更的扫描参数

| 参数 | 默认 | 上限 | 说明 |
|---|---|---|---|
| `maxPerHost` | 2500 | 12000 | 每主机候选上限 |
| `ratePerSec` | 10 | 100 | 全局每秒请求数 |
| `maxDepth` | 1 | 3 | 递归深度（0=关） |
| `maxDurationSec` | 1800(前端) | 86400 | 扫描时长上限（0=不限） |
| `crawl` | 开(前端) | — | 智能爬取开关 |
| `maxCrawlPages` | 25 | 200 | 爬取页数上限 |

### ✅ 测试

- 单元 + httptest 集成共 **32 个**（v0.2.0 为 0）：限速器/退避/网络退避、目标规范化、候选生成/去重/带日期、分类研判、soft-404 判定与相似度校准、魔数识别、递归正/反例、爬取(提链/同源解析/robots/sitemap/looksSensitive/端到端派生命中)、`doMagic` 安全保证。
- 全部无网络外部依赖（httptest 走回环）。

### 🔁 API 一览（`/api/m/backup/*`）

```
GET  /hits            列出命中
GET  /stats           统计磁贴
GET  /dict            字典规模/来源
GET  /export?format=  导出 json|csv|html
GET  /scan/status     扫描进度
POST /scan            发起扫描
POST /scan/stop       停止扫描
POST /hits/clear      清空命中
POST /hits/delete     删除单条 {id}
```

---

## v0.2.0 — 真实存在性探测引擎（前序基线）

- HEAD/Range 真实探测、soft-404 多样本基线、魔数识别、http/https 回退、可取消、SecLists/OWASP 内置字典、前端控制台 + 命中详情。
