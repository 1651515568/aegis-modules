# scan-port 变更日志

## 0.4.0 — Linux 原生 SYN 扫描 / 主动服务探针 / UDP 服务识别增强 / OS 指纹

### ✨ 新增

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **Linux 原生 SYN 扫描** | 使用 `syscall.Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` + `IP_HDRINCL` 发包，`IPPROTO_TCP` 接收 SYN-ACK；无需 npcap 或 masscan，仅需 root / `CAP_NET_RAW`；通过 SYN Cookie（编码 dstIP/dstPort/secret 到 seq）验证响应合法性；BlackRock 伪随机置换扫描顺序；Banner 阶段自动触发 `enrichBanners`。 | `synscan_linux.go`（新建） |
| **SYN 扫描 stub 更新** | 编译标签由 `!npcap` 改为 `!npcap && !linux`，消除 Linux 与 npcap 版本的符号冲突。 | `synscan_stub.go` |
| **OS 指纹推断** | 双路径推断：① SYN 扫描阶段从 SYN-ACK IP 头提取 TTL + 窗口大小，`guessOSFromTTLWindow()` 归一判断（TTL≤64→Linux/macOS，≤128→Windows，≤255→网络设备）；② Banner 阶段 `guessOSFromBanner()` 关键词匹配（Ubuntu/Debian/CentOS/Cisco/Juniper/Huawei/MikroTik/Fortinet 等）。结果存入 `Port.OsGuess`，SYN 阶段优先。 | `osfingerprint.go`（新建），`store.go`，`enrich.go` |
| **主动服务探针（类 nmap NSE）** | `activeProbe()` 对 10 种协议发协议特定探测载荷：Redis（RESP PING）、Memcached（version 命令）、PostgreSQL（StartupMessage v3.0）、MongoDB（OP_QUERY isMaster）、RDP（TPKT+COTP+RDP_NEG_REQ，提取 TLS/NLA 协议版本）、VNC（读 RFB 协议版本字符串）、Kafka（ApiVersions v0 请求）、ZooKeeper（stat 四字命令）、MSSQL（TDS Pre-Login，提取 major.minor 版本）、Oracle（TNS Connect，区分 ACCEPT/REFUSE/REDIRECT）。在 `grabBanner()` 中作为第 3 优先级调用（TLS→HTTP→主动探针→被动读 greeting）。 | `probe_active.go`（新建），`banner.go` |
| **UDP 探针扩展** | 新增 8 个 UDP 协议探针：TFTP RRQ（`/etc/passwd`）、NetBIOS NBSTAT 节点状态查询、RPC portmapper GETPORT call、SIP OPTIONS 请求、mDNS `_services._dns-sd._udp.local` PTR 查询、ISAKMP IKEv1 Main Mode SA 提案、OpenVPN 硬重置客户端 v2、BACnet Who-Is 广播。`udpServiceName()` 同步新增 chargen/tftp/rpcbind/netbios-ns/netbios-dgm/isakmp/syslog/openvpn/sip/ipsec-nat/mdns/bacnet/wireguard。 | `udp.go` |

### ✅ 测试

新增 12 项测试（共 38 项，全部通过）：`TestGuessOSFromTTLWindow`、`TestGuessOSFromBanner`、`TestActiveProbeRedisPong`、`TestActiveProbeRedisNoAuth`、`TestActiveProbeMemcached`、`TestActiveProbeVNC`、`TestActiveProbeZookeeper`、`TestActiveProbeUnknownPort`、`TestNewUDPProbePayloads`、`TestUDPServiceNames`。`GOOS=linux/windows go vet` 均无警告。

---

## 0.3.2 — TCP connect 集成测试

### ✨ 新增

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **TestConnectScanIntegration** | 在本机启动 3 个随机 TCP 监听端口 + 1 个确定关闭端口，用 connect 引擎端到端扫描，断言开放端口全部发现、关闭端口不误报。`noopLogger` 实现 `core.Logger` 接口供测试 Module 复用。 | `scanner_test.go` |

### ✅ 测试

`go vet` 干净，全部 20 项测试通过（含新增集成测试）。

---

## 0.3.1 — 端口预设下拉 + IPv6 测试

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **端口预设下拉(ParamSelect)** | `ports` 参数由自由文本改为五档下拉：`top100`（实战推荐，默认）/ `top500`（约 370 高价值端口）/ `top1000`（1-1000 + 常见高位）/ `all`（全端口）/ `custom`（自定义）。新增 `portsCustom` 字符串参数，仅 `custom` 档位时生效，`invokeScan` 自动将 `opt.Ports` 替换为 `portsCustom` 值（空时回退 `top1000`）。 | `functions.go` |
| **top500Ports 端口集合** | 新增约 370 个高价值渗透测试端口，覆盖 Web 变体/数据库/中间件/远管/工控/云原生/IoT，命中率优于顺序枚举 1-500。`parsePorts("top500")` 直接返回此集合。 | `ports.go`、`scanner.go` |
| **IPv6 测试覆盖** | `TestParseTargets` 新增四个 IPv6 用例：裸地址、带端口方括号、裸方括号；`TestExpandCIDR` 新增 `/128` 单主机和 `/127` 双主机 IPv6 CIDR 展开验证；`TestParsePorts` 新增 `top500` 断言。 | `scanner_test.go` |

### ✅ 测试

`go vet` 干净，19 项测试全部通过（含新增 IPv6 + top500 用例）。

---

## 0.3.0 — IPv6 connect 模式支持

### ✨ 新增 / 增强

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **IPv6 目标解析(P1)** | `processTarget()` 新增对裸 `[::1]` 格式（方括号包裹无端口）的处理：剥掉方括号后 `add()`，确保后续 `net.JoinHostPort` 不会产生双重方括号 `[[::1]]:80` 的无效地址。`[::1]:8080` 格式已通过 `SplitHostPort` 正确处理，无需额外修改。 | `scanner.go` |
| **IPv6 CIDR 展开(P1)** | `expandCIDR()` 现已透明支持 IPv6 CIDR（如 `2001:db8::/64`）：`net.ParseCIDR` 返回 16 字节 IP，`incIP`/`cloneIP` 对任意字节长度均有效，展开受 `maxCIDRHosts=1024` 上限约束。IPv6 主机最终由 connect 引擎探测，`JoinHostPort` 自动补全方括号。 | `scanner.go` |
| **masscan 自动降级(P2)** | masscan 不支持 IPv6；当所有目标均为纯 IPv6（`To4()==nil`）时，`masscanRun` 返回非 nil 错误，`runScan` 自动回退 connect 扫描，用户无感知，结果不中断。 | `masscan.go`（已有逻辑，文档补全） |

### ✅ 安全上限

- IPv6 CIDR 展开受现有 `maxCIDRHosts=1024` 与 `maxHosts=4096` 约束，不引入新的资源风险。

### ✅ 测试

`go vet` 干净，回归测试通过。

---

## 0.2.0 — 稳定性与准确性修复

### 🐛 修复

| 项目 | 说明 | 影响文件 |
|---|---|---|
| **enrichBanners 并发尊重用户配置(P1)** | 旧代码 `conc := 64` 硬编码，忽略用户设置的 `scanOptions.Concurrency`，导致 banner 抓取阶段可能打满或浪费并发。改为 `opt.Concurrency`（保留 `<=0` 时回退 64 的兜底）。 | `enrich.go` |
| **hostUpFromDialErr Windows 兼容(P2)** | Windows 上 `WSAECONNREFUSED(10061)` / `WSAECONNRESET(10054)` 的 errno 数值与 POSIX 不同，`errors.Is(syscall.ECONNREFUSED)` 常无法匹配，导致 Windows 上 connect 扫描把「端口关闭（RST）」统计为「被过滤」，严重低估开放端口数。新增 `syscall.Errno(10061/10054)` 显式检测，三层兜底（POSIX + WSAE 数值 + 字符串）。 | `scanner.go` |
| **masscan 二进制完整性校验(P3)** | `ensureMasscan()` 仅检查 `len(data) < 1024`，无法区分真正可执行文件与格式有误的占位文件。新增 `isValidExecutableMagic()`：校验 ELF（`\x7fELF`）或 PE（`MZ`）魔数，不合法时返回错误并触发 connect 回退。 | `masscan.go` |
| **top1000Ports 名称与实现一致性(P4)** | `top1000Ports()` 内部实现为「端口 1-1000 顺序枚举 + commonHighPorts」，既不是 nmap 统计意义上的 top 1000，也包含大量几乎从不开放的稀少端口（如 2/3/4…）。已在注释中如实标注「标准端口 1-1000 + 常见高位端口」，避免误导。 | `ports.go` |

### ✅ 测试

`go vet` 干净，回归测试通过。

---

## 0.1.0 — 端口扫描能力(由 RedOps portscan 移植并按 AEGIS 规范优化)

引擎能力 id：`scan-port`(Go 包名 `portscan`)。归类「扫描探测」。

### 新增(相对 RedOps portscan)
- **内嵌 masscan 引擎(默认)**:`masscan.go` 通过 `//go:embed bin` 打包各平台 masscan 二进制,
  运行时按 `GOOS/GOARCH` 释放到 `data/scan-port/bin/` 后子进程调用,`-oL -` 流式解析开放端口;
  发包速率有硬上限,域名先解析为 IPv4 再交给 masscan。
- **自动回退**:masscan 不可用(二进制缺失 / 无管理员 / 无 libpcap-Npcap)时,自动回退到
  纯 Go connect/UDP 扫描(`scanner.go`),体验不中断。
- **AEGIS 统一异步契约**:`GET /functions`、`POST /invoke`、`GET /tasks/<id>`,统一 `task_id`
  透传、按 task_id 落 `m_scan_port_task_runs`,跨页面/重启不丢。
- **结果归档表**:`m_scan_port_findings`(迁移 `migrations/0001_findings.sql`),开放端口按
  task_id 归档,`GET /findings?taskId=` 取回。
- **持久化降级**:`k.DB` 为 nil 时 `/invoke`、`/findings`、`/tasks` 返回 503 而非 panic。
- **结果导出**:`GET /export?format=json|csv|html`(export.go),把当前扫描的开放端口
  以附件形式下载;前端在「发起端口扫描」面板提供 JSON/CSV/HTML 下载按钮。

### 保留(自 RedOps portscan,逻辑未改)
- 纯 Go TCP connect 扫描、UDP 扫描、主机存活探测、自适应速率(AIMD)、限速器、
  BlackRock 伪随机置换扫描顺序、banner/TLS/HTTP 指纹抓取、知名端口服务映射。
- 可选 SYN 半开扫描(`synscan.go` / `netroute_windows.go`,`//go:build npcap` 标签)。

### 依赖说明
- **默认构建零新增第三方依赖**(未改引擎 `go.mod`)。
- SYN 扫描需 `github.com/google/gopacket`,该依赖**不在** `go.mod`;启用前在 `engine/`
  执行 `go get github.com/google/gopacket` 并以 `go build -tags npcap` 构建。
- masscan 二进制不随仓库分发(AGPL-3.0 + 体积),放置方式见 `bin/README.md` 与 `HANDOFF.md`。
