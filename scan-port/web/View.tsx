import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Radar, Network, Server, Globe, Activity, Play, Square, RefreshCw, Download,
} from 'lucide-react'
import { Panel, StatCard, Progress } from '@/components/ui'
import { engineGet, enginePost, engineDownload } from '@/lib/engine'
import { ApiError } from '@/lib/api'
import { createTask, updateTask } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'scan-port'

interface Port {
  host: string
  port: number
  proto: string
  service: string
  banner: string
  osGuess: string
}

interface ScanStatus {
  running: boolean
  phase: string
  total: number
  probed: number
  found: number
  closed: number
  filtered: number
  alive: number
  rate: number
  engine: string
  elapsedMs: number
  target: string
  startedAt: string
  endedAt: string
  err: string
}

type Mode = 'masscan' | 'connect' | 'syn'
type Proto = 'tcp' | 'udp' | 'both'

const ENGINE_LABEL: Record<string, string> = {
  masscan: 'masscan（内嵌·高速）',
  connect: 'connect（纯 Go）',
  syn: 'SYN（半开）',
}

export default function View() {
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [ports, setPorts] = useState<Port[]>([])

  const [targets, setTargets] = useState('')
  const [portSpec, setPortSpec] = useState('top1000')
  const [portsCustom, setPortsCustom] = useState('22,80,443')
  const [mode, setMode] = useState<Mode>('masscan')
  const [proto, setProto] = useState<Proto>('tcp')
  const [rate, setRate] = useState(1000)
  const [concurrency, setConcurrency] = useState(256)
  const [timeout, setTimeoutMs] = useState(1500)
  const [discovery, setDiscovery] = useState(false)
  const [svc, setSvc] = useState(true)
  const [banner, setBanner] = useState(true)

  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [taskReload, setTaskReload] = useState(0)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  const refresh = useCallback(async () => {
    const [st, p] = await Promise.all([
      engineGet<{ status: ScanStatus; id: string }>(CAP, '/scan/status'),
      engineGet<{ items: Port[] }>(CAP, '/ports'),
    ])
    setStatus(st.status)
    setPorts(p.items ?? [])
    return st.status
  }, [])

  // 仅在扫描运行时轮询实时进度/端口（界面展示）。任务台账的进度/结果固化由
  // 后端 reconcile-on-read 负责（读取任务时按 task_id 拉引擎落库结果），本端不镜像。
  const startPolling = useCallback(() => {
    if (timer.current) return
    timer.current = setInterval(async () => {
      try {
        const st = await refresh()
        if (!st.running && timer.current) {
          clearInterval(timer.current); timer.current = null
          setTaskReload((n) => n + 1)
        }
      } catch { /* 轮询瞬时错误忽略 */ }
    }, 1500)
  }, [refresh])

  useEffect(() => {
    refresh().then((st) => { if (st.running) startPolling() }).catch((e) => setErr(String(e?.message ?? e)))
    return () => { if (timer.current) clearInterval(timer.current) }
  }, [refresh, startPolling])

  async function call(fn: () => Promise<unknown>) {
    setBusy(true); setErr(null)
    try { await fn(); await refresh() }
    catch (e) { setErr(e instanceof ApiError ? e.message : String((e as Error)?.message ?? e)) }
    finally { setBusy(false) }
  }

  async function startScan() {
    const list = targets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (!list.length) { setErr('请填写至少一个目标（IP / 域名 / CIDR，每行一个）'); return }
    await call(async () => {
      const params = {
        targets: list, ports: portSpec, portsCustom, mode, proto,
        rate, concurrency, timeout, discovery, svc, banner,
      }
      // 统一 task_id：先向系统申请 id 落台账，再透传给引擎 /invoke。
      const t = await createTask({ capabilityKey: CAP, action: 'scan', params })
      setTaskReload((n) => n + 1)
      try {
        await enginePost(CAP, '/invoke', { taskId: t.id, function: 'scan', params })
      } catch (e) {
        await updateTask(t.id, {
          status: 'failed', error: e instanceof Error ? e.message : String(e),
        }).catch(() => {})
        setTaskReload((n) => n + 1)
        throw e
      }
      startPolling()
    })
  }

  const running = status?.running ?? false
  const pct = status && status.total > 0 ? Math.min(100, Math.round((status.probed / status.total) * 100)) : 0
  const hosts = new Set(ports.map((p) => p.host)).size
  const tcpCount = ports.filter((p) => p.proto === 'tcp').length
  const udpCount = ports.filter((p) => p.proto === 'udp').length

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="开放端口" value={ports.length || '—'} icon={<Network size={18} />} />
        <StatCard label="涉及主机" value={hosts || '—'} icon={<Globe size={18} />} />
        <StatCard label="TCP / UDP" value={`${tcpCount} / ${udpCount}`} icon={<Server size={18} />} />
        <StatCard
          label="本次引擎"
          value={status?.engine ? (ENGINE_LABEL[status.engine] ?? status.engine) : '—'}
          icon={<Radar size={18} />}
        />
      </div>

      <Panel title="发起端口扫描" icon={<Radar size={16} />}>
        <div className="space-y-3">
          <textarea
            className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-sm text-slate-200 outline-none focus:border-cyber"
            rows={3} placeholder="目标，每行一个：192.168.1.0/24 或 example.com 或 10.0.0.5"
            value={targets} onChange={(e) => setTargets(e.target.value)} disabled={running}
          />
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">端口
              <select value={portSpec} onChange={(e) => setPortSpec(e.target.value)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                <option value="top100">top100（高频端口）</option>
                <option value="top500">top500（约 370 个）</option>
                <option value="top1000">top1000（推荐）</option>
                <option value="all">全端口（慎用）</option>
                <option value="custom">自定义</option>
              </select>
            </label>
            {portSpec === 'custom' && (
              <label className="flex items-center gap-2">自定义端口
                <input value={portsCustom} onChange={(e) => setPortsCustom(e.target.value)} disabled={running}
                  placeholder="22,80,443,8000-8100"
                  className="w-48 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
              </label>
            )}
            <label className="flex items-center gap-2">引擎
              <select value={mode} onChange={(e) => setMode(e.target.value as Mode)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                <option value="masscan">masscan（高速·需管理员）</option>
                <option value="connect">connect（免提权）</option>
                <option value="syn">SYN（需 npcap）</option>
              </select>
            </label>
            <label className="flex items-center gap-2">协议
              <select value={proto} onChange={(e) => setProto(e.target.value as Proto)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP+UDP</option>
              </select>
            </label>
            <label className="flex items-center gap-2">速率
              <input type="number" min={0} max={100000} value={rate}
                onChange={(e) => setRate(+e.target.value)} disabled={running}
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">并发
              <input type="number" min={1} max={1024} value={concurrency}
                onChange={(e) => setConcurrency(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">超时ms
              <input type="number" min={100} max={10000} value={timeout}
                onChange={(e) => setTimeoutMs(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={discovery} onChange={(e) => setDiscovery(e.target.checked)} disabled={running} />
              存活探测
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={svc} onChange={(e) => setSvc(e.target.checked)} disabled={running} />
              服务识别
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={banner} onChange={(e) => setBanner(e.target.checked)} disabled={running} />
              抓取 Banner
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <button onClick={() => call(() => enginePost(CAP, '/scan/stop'))} disabled={busy}
                className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={14} /> 停止扫描
              </button>
            ) : (
              <button onClick={startScan} disabled={busy}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber">
                <Play size={14} /> 发起扫描
              </button>
            )}
            <button onClick={() => call(async () => { await refresh() })} disabled={busy}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <RefreshCw size={14} /> 刷新
            </button>
            <div className="ml-auto flex items-center gap-1">
              {(['json', 'csv', 'html'] as const).map((f) => (
                <button key={f} onClick={() => engineDownload(CAP, '/export', `portscan-ports.${f}`, { format: f })}
                  disabled={ports.length === 0}
                  className="chip border border-line bg-base-600/60 text-slate-400">
                  <Download size={14} /> {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {running && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-slate-400">
                <span>{status?.phase || '扫描中…'}　{status?.target}</span>
                <span className="font-mono">{status?.probed}/{status?.total}（开放 {status?.found}）</span>
              </div>
              <Progress value={pct} />
            </div>
          )}
          {err && <div className="text-sm text-sev-high">{err}</div>}
        </div>
      </Panel>

      <Panel title={`开放端口（${ports.length}）`} icon={<Activity size={16} />} bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-slate-500">
                <th className="px-4 py-2 font-medium">主机</th>
                <th className="px-4 py-2 font-medium">端口</th>
                <th className="px-4 py-2 font-medium">协议</th>
                <th className="px-4 py-2 font-medium">服务</th>
                <th className="px-4 py-2 font-medium">OS</th>
                <th className="px-4 py-2 font-medium">Banner</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {ports.length === 0 && (
                <tr><td colSpan={6} className="p-6 text-center text-sm text-slate-500">暂无开放端口</td></tr>
              )}
              {ports.map((p, i) => (
                <tr key={`${p.host}/${p.proto}/${p.port}/${i}`} className="hover:bg-base-600/40">
                  <td className="px-4 py-2 font-mono text-slate-300">{p.host}</td>
                  <td className="px-4 py-2 font-mono text-cyber">{p.port}</td>
                  <td className="px-4 py-2">
                    <span className="chip border border-line bg-base-600/60 text-xs text-slate-400">{p.proto}</span>
                  </td>
                  <td className="px-4 py-2 text-slate-300">{p.service || '—'}</td>
                  <td className="px-4 py-2 text-xs text-slate-400">{p.osGuess || '—'}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">{p.banner || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="历史任务" icon={<Radar size={16} />} bodyClass="p-3">
        <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload}
          emptyHint="暂无任务记录，发起一次扫描后将登记到此。" />
      </Panel>
    </div>
  )
}
