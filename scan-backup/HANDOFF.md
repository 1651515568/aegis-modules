# 备份文件模块（backup）— 交接说明

> 给接手同事:本文档讲**怎么把这个模块装进 RedOps 平台、怎么构建前端、有哪些接口**。
> 模块本身的能力清单与版本历史见同目录 `CHANGELOG.md`(当前 **v0.5.0**)。

---

## 1. 这是什么

RedOps 平台的「备份文件」能力模块:对**已授权**目标做备份/敏感文件与源码泄露的**存在性探测**。
安全口径:默认仅 `HEAD` + `Range ≤16B`；文本型敏感文件(`.env`/`.sql`/`id_rsa` 等)另读 ≤64B 做类型识别；soft-404 站点另读 ≤512B 做相似度校准。**绝不下载文件体**，遇 401/403 仅标记不绕过。

## 2. 依赖与前置

- **Go 1.24+**(开发用 1.26 验证通过)。
- 唯一外部依赖:平台内核包 **`redops/core`**(模块通过 `core.MustRegister` 自注册、用 `core.Logger`/`core.Manifest`/`core.Route`)。
  → 因此本模块**需放进 RedOps 仓库内**构建,不是独立 main 包。
- 前端:Vue 3 + Vite 5(仅构建期需要;产物 `frontend/dist/frontend.js` 已随包附带)。

## 3. 接入平台(后端)

把整个 `modules/backup/` 目录放到仓库的 `modules/` 下,然后在 `main.go` 的模块挂载区加一行 import:

```go
import (
    ...
    _ "redops/modules/backup"   // 备份文件
)
```

`init()` 会自动注册到 `core.Registry`,平台启动即加载;前端用户可随时启用/禁用。无需改动其它代码。

构建验证:
```bash
go build ./...
go vet ./modules/backup/
go test ./modules/backup/        # 38 个用例,纯函数 + httptest,无外网依赖
go test -race ./modules/backup/  # 并发安全(零数据竞争)
```

## 4. 构建前端

> ⚠️ 仓库 Makefile 里的 `pnpm` 路径在非原作者机器上失效。**直接用 npm 即可**:

```bash
cd modules/backup/frontend
npm install --no-save vite@^5.2.11 @vitejs/plugin-vue@^5.0.4 vue@^3.4.27
npx vite build        # 产出 dist/frontend.js + dist/style.css
```

平台运行时从磁盘 `modules/backup/frontend/dist/` 读取该产物提供给前端外壳(`FrontendFS()` 返回 nil = 走磁盘)。**改了 `src/View.vue` 后必须重新 build**,否则界面看到的是旧产物。

## 5. HTTP 接口(框架自动挂到 `/api/m/backup/*`)

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET  | `/hits`         | backup:view | 命中列表 |
| GET  | `/stats`        | backup:view | 统计磁贴 |
| GET  | `/dict`         | backup:view | 字典规模/来源 |
| GET  | `/export?format=json\|csv\|html` | backup:view | 导出(附件下载) |
| GET  | `/scan/status`  | backup:view | 扫描进度(含 `resumable`) |
| POST | `/scan`         | backup:scan | 发起扫描(请求体见下) |
| POST | `/scan/stop`    | backup:scan | 停止当前扫描 |
| POST | `/scan/resume`  | backup:scan | 续扫上次未完成任务 |
| POST | `/hits/clear`   | backup:scan | 清空命中(+删落盘文件) |
| POST | `/hits/delete`  | backup:scan | 删除单条 `{"id":"..."}` |

`POST /scan` 请求体(均有默认值):
```json
{
  "targets": ["https://example.com", "203.0.113.10"],
  "maxPerHost": 2500,      // 每主机候选上限(上限 12000)
  "concurrency": 12,       // 并发(上限 128)
  "ratePerSec": 10,        // 全局限速 req/s(上限 500)
  "maxDepth": 1,           // 递归目录深度(0 关,上限 3)
  "maxDurationSec": 1800,  // 时长上限秒(0 不限)
  "crawl": true,           // 智能爬取/链接提取
  "maxCrawlPages": 25,     // 爬取页数上限(上限 200)
  "includeEditor": true,   // 文件名套编辑器遗留后缀
  "timeoutMs": 6000        // 单请求超时
}
```

## 6. 运行期数据

- 命中持久化:`data/backup/hits.json`(原子写,重启自动恢复);
- 续扫任务:`data/backup/job.json`;
- `data/` 已在 `.gitignore`,属运行期数据,不要提交、可随时删。

## 7. 代码结构(modules/backup/)

```
manifest.yaml   模块清单(id/权限/导航/版本)
module.go       生命周期(Init/OnEnable/OnDisable),启用时加载持久化或种子
register.go     init() 自注册
handler.go      HTTP 路由与处理
scanner.go      扫描主流程 run/runScan(限速/重试/超时/续扫调度)
dict.go         字典加载 + 候选生成(含带日期组合)
recurse.go      递归目录发现(动态队列 + 预算 + 每主机完成计数)
crawl.go        智能爬取 / 链接提取 / robots / sitemap
jsmine.go       静态 JS 挖掘(bundle 路径字面量 + source map)
similarity.go   soft-404 响应体相似度校准(Dice 系数)
limiter.go      令牌间隔限速器 + 退避参数
classify.go     命中研判/文案/定级
store.go        内存态 + 持久化 + 任务/续扫
export.go       JSON/CSV/HTML 导出
wordlists/*.txt 内置字典(SecLists/OWASP)
*_test.go       38 个回归用例
```

## 8. 已知边界(非缺陷,是范围)

- 仅探测**未授权可达**的泄露面,不做认证态/登录后扫描(红队场景不需要)。
- 不渲染 JS(用静态 JS 挖掘替代,无浏览器依赖)。
- 单机内存态,适合中小规模;海量目标的分布式属平台级(内核已预留 `Queue()`)。
- 报告导出为表格/JSON;图表化未做。
