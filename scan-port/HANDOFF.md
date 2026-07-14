# scan-port 交付与接入说明

端口扫描能力,由 RedOps `portscan` 移植并按《AEGIS 能力模块开发规范》优化。
本目录仅含**引擎 Go 后端模块**;React 前端三件套(`src/capabilities/scan-port/`)未包含,见末尾。

## 一、接入步骤(引擎侧)

```bash
cd engine
go generate ./...        # 重新生成 modules_gen.go,自动加入 _ "redops/modules/scan-port"
go build -o bin/redops .  # 构建(默认不含 masscan 二进制也能编译)
# 重启引擎 → 能力中心点同步 → 出现 cap_key=scan-port(初始停用)→ 启用
```

> 未手改 `main.go` / `modules_gen.go` / `go.mod` / `core/` 及任何其它现有代码。
> 模块靠 `register.go` 的 `init()` 自注册,`go generate` 负责把它 blank-import 进 `modules_gen.go`。

## 二、放置 masscan 二进制(可选但推荐)

masscan 是默认扫描引擎,但二进制不随仓库分发。命名约定与放置见 [`bin/README.md`](./bin/README.md):

- 按 `masscan-<os>-<arch>[.exe]` 命名放入 `bin/`,再 `go build`。
- 运行时需管理员/root + Npcap(Win)/libpcap;**不满足会自动回退纯 Go connect 扫描**。
- 不放二进制也能正常用(走 connect/UDP 引擎)。

## 三、对外接口(经 AEGIS 代理 `/api/v1/engine/m/scan-port/*`)

统一异步契约:
- `GET  /functions`          功能与参数 schema(前端动态渲染表单)
- `POST /invoke`             `{taskId, function:"scan", params}` → 立即返回 `{taskId}`
- `GET  /tasks/<taskId>`     轮询任务进度/结果(读 `m_scan_port_task_runs`)
- `GET  /findings?taskId=`   该任务归档的开放端口(读 `m_scan_port_findings`)

实时/辅助视图(可选,直连引擎调试 / 界面轮询):
- `GET  /ports`             当前扫描的开放端口实时列表
- `GET  /export?format=`    导出当前结果 json|csv|html(附件下载,默认 json)
- `GET  /scan/status`       当前扫描进度(含 engine 字段:masscan/connect/syn)
- `POST /scan`              引擎本地直接发起(不登记 AEGIS 台账)
- `POST /scan/stop`         停止当前扫描
- `GET  /history`、`/history/get?id=`、`POST /history/delete`  本地最近扫描记录

`scan` 功能参数:`targets`(必填,多行)、`ports`、`mode`(masscan/connect/syn)、`proto`、
`rate`、`concurrency`、`timeout`、`discovery`、`svc`、`banner`。

## 四、与 RedOps 原版的差异

见 [`CHANGELOG.md`](./CHANGELOG.md)。要点:新增内嵌 masscan + 自动回退、统一 task_id 异步契约、
findings 归档表、持久化降级;原 connect/UDP/SYN/存活探测/自适应速率/指纹抓取逻辑全部保留,
原单元测试随模块一并迁入并通过。

## 五、前端三件套(已完成)

已在仓库根建 `src/capabilities/scan-port/`:`meta.json`(id=scan-port,扫描探测组 order 13,
icon Radar)/ `manifest.ts` / `View.tsx`。靠 `src/capabilities/index.ts` 的 glob 自动注册,
无需改中心文件。View 走统一 task_id(createTask + `/invoke`)、轮询 `/scan/status`+`/ports`
展示实时进度与开放端口表格、底部 `TaskList` 历史任务。`npm run build`(tsc + vite)通过。

## 六、对现有文件的改动(已记录)

为让「任务详情页」展示本能力按 task_id 归档的开放端口,改动两处现有文件:

1. `src/lib/engineTasks.ts`
   - `FINDINGS_CAPABILITIES` 增加 `'scan-port'`(白名单,详情页据此展示 /findings 命中)。
   - `FindingRow` 接口改为兼容多能力:公共字段(taskId/hitId/host/foundAt)保留必填,
     scan-backup 字段(url/file/kind/severity/code/rule/note)与 scan-port 字段
     (port/proto/service/banner)均改为可选。向后兼容,scan-backup 不受影响。

2. `src/pages/TaskDetail.tsx`
   - `TaskFindings` 列表渲染按行分支:`r.port !== undefined` 渲染端口命中
     (host:port / proto / service / banner),否则维持原 scan-backup 命中渲染。

二者均 `npm run build` 通过。除上述两处与新建的 `src/capabilities/scan-port/`、
`engine/modules/scan-port/` 外,未改动 AEGIS 其它代码。
