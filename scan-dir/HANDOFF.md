# scan-dir 交付与接入说明

目录扫描能力(目录/文件爆破),按《AEGIS 能力模块开发规范》与 `scan-port` / `scan-backup` 同构实现。
引擎 Go 后端 + AEGIS React 前端三件套均已包含。

## 一、接入步骤(引擎侧)

```bash
cd engine
go generate ./...         # 重新生成 modules_gen.go,自动加入 _ "redops/modules/scan-dir"
go build -o bin/redops .  # 构建
# 重启引擎 → 能力中心点同步 → 出现 cap_key=scan-dir(初始停用)→ 启用 → 按需授权
```

> 未手改 `main.go` / `modules_gen.go` / `go.mod` / `core/`。
> 模块靠 `register.go` 的 `init()` 自注册,`go generate` 负责把它 blank-import 进 `modules_gen.go`。

## 二、对外接口(经 AEGIS 代理 `/api/v1/engine/m/scan-dir/*`)

统一异步契约:
- `GET  /functions`        功能与参数 schema(前端动态渲染表单)
- `POST /invoke`           `{taskId, function:"scan", params}` → 立即返回 `{taskId}`
- `GET  /tasks/<taskId>`   轮询任务进度/结果(读 `m_scan_dir_task_runs`)
- `GET  /findings?taskId=` 该任务归档的命中(读 `m_scan_dir_findings`)

实时/辅助视图(可选,直连引擎调试 / 界面轮询):
- `GET  /hits`              当前扫描命中实时列表
- `GET  /dict`             内置字典规模与预设
- `GET  /export?format=`   导出 json|csv|html(附件下载,默认 json)
- `GET  /scan/status`      当前扫描进度(phase/total/probed/found/filtered)
- `POST /scan`             引擎本地直接发起(不登记 AEGIS 台账)
- `POST /scan/stop`        停止当前扫描
- `POST /scan/resume`      断点续扫(从检查点恢复待扫基目录队列,保留已有命中)
- `GET  /history`、`/history/get?id=`、`POST /history/delete`  本地最近扫描记录

`scan` 功能参数:
- 基本:`targets`(必填,多行;目标/请求体/请求头含 `FUZZ` 走 ffuf 关键字定位模式)、`wordlist`、
  `customWords`、`extensions`(替换 `%EXT%` 并对目录型词条追加)、`method`(任意方法)、`requestBody`
  (ffuf -d,非 GET/HEAD 发送,可含 FUZZ)、`proxy`(ffuf -x,http(s)/socks5)、`userAgent`、`headers`、
  `followRedirect`。
- 字典:`wordlist` 取 `GET /dict` 列出的 id——内置 `quickhits`/`api`/`common`/`dirsearch`/
  `raft-files`/`raft-dirs`,外部 `file:<名>`,或 `custom`(配合 `customWords`,支持 `%EXT%`)。
- 性能与克制:`concurrency`(≤64)、`rate`(req/s,0=不限)、`timeout`(ms)。
- 过滤(对标 ffuf/dirsearch):`statusInclude`/`statusExclude`、`filterLength`/`filterWords`/
  `filterLines`、`filterRegex`/`matchRegex`、`minLength`/`maxLength`。
- 发现增强:`recursion`(目录递归深度 0–3)、`crawl`(链接抽取爬取)、`collectBackups`(备份衍生)、
  `prefixes`/`suffixes`、`randomAgent`。
- 多关键字(ffuf):`wordlist2`(关键字 FUZ2Z 的第二字典)、`customWords2`、`fuzzMode`
  (clusterbomb/pitchfork);在目标/请求体/请求头里用 FUZ2Z 标记第二位置。
- 命中带 `severity`(critical/high/medium/low/info)与 `kind`(中文类别),归档表与任务详情页同步展示。
- 断点续扫:扫描被中断后 `/scan/status` 的 `resumable=true`,`POST /scan/resume` 从检查点继续。

### 内置 / 外部字典
- 内置字典随引擎编译,取自上游权威词表(dirsearch dicc、SecLists common/quickhits/api、RAFT 目录/文件)。
- **外部字典**:把任意 `.txt` 丢进引擎工作目录下的 `data/scan-dir/wordlists/`,即以 id `file:<名>`
  自动出现在 `GET /dict` 与前端字典下拉。可直接放入 SecLists `directory-list-2.3-medium`、
  OneListForAll 等超大字典,无须重编译。(文件名仅允许基名 .txt,内置目录穿越防护。)

## 三、前端三件套(已完成)

已在仓库根建 `src/capabilities/scan-dir/`:`meta.json`(id=scan-dir,扫描探测组 order 14,
icon FolderSearch)/ `manifest.ts` / `View.tsx`。靠 `src/capabilities/index.ts` 的 glob 自动注册,
无需改中心文件。View 走统一 task_id(createTask + `/invoke`)、轮询 `/scan/status`+`/hits` 展示
实时进度与命中表格(状态码配色 / 目录标记 / 长度 / 跳转 / 外链)、底部 `TaskList` 历史任务。
`npm run build`(tsc + vite)通过。

## 四、对现有文件的改动(已记录)

为让「任务详情页」展示本能力按 task_id 归档的命中,改动两处现有文件:

1. `src/lib/engineTasks.ts`
   - `FINDINGS_CAPABILITIES` 增加 `'scan-dir'`。
   - `FindingRow` 把 `host` 改为可选,新增目录扫描字段
     (path/status/length/words/lines/redirect/contentType/depth)。向后兼容,其它能力不受影响。

2. `src/pages/TaskDetail.tsx`
   - `TaskFindings` 列表渲染新增 `r.path !== undefined` 分支(目录命中:状态码 + 路径 + 长度 + 跳转),
     并加 `dirCodeClass` 配色辅助。其余分支(scan-port/scan-backup)不变。

二者均 `npm run build` 通过。除上述两处与新建的 `src/capabilities/scan-dir/`、
`engine/modules/scan-dir/` 外,未改动 AEGIS 其它代码。

## 五、自检结果

- `cd engine && go generate ./... && go build ./...` 通过;`go vet ./modules/scan-dir/...` 无告警;
  `go test ./modules/scan-dir/...` 通过(纯函数 + 限速器 + 端到端/wildcard/取消集成测试)。
- `npm run build` 通过。
- id 一致性:引擎 `manifest.yaml` `id` == 前端 `meta.json` `id` == 两侧目录名 == `scan-dir`。
