import { useEffect, useRef, useState } from 'react'
import { Crosshair, Globe, Shield, Cpu, Play, Square, RefreshCw, Download, ChevronRight } from 'lucide-react'
import { Panel, StatCard } from '@/components/ui'
import { engineGet, enginePost } from '@/lib/engine'
import { ApiError } from '@/lib/api'
import { createTask, updateTask, pollTask } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'scan-probe'

interface ProbeResult {
  host: string
  port: number
  protocol: string
  cms: string
  framework: string
  waf: string
  server: string
  title: string
  statusCode: number
  os: string
  faviconHash?: number
  components?: string[]
}

const wafColor = (waf: string) => waf === '无' ? 'text-slate-500' : 'text-amber-400'
const statusColor = (code: number) => {
  if (!code) return 'text-slate-500'
  if (code < 300) return 'text-emerald-400'
  if (code < 400) return 'text-amber-400'
  return 'text-sev-high'
}

export default function ScanProbeView() {
  const [targets, setTargets] = useState('')
  const [threads, setThreads] = useState(20)
  const [timeout, setTimeout_] = useState(5000)
  const [detectWaf, setDetectWaf] = useState(true)
  const [detectCms, setDetectCms] = useState(true)
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<ProbeResult[]>([])
  const [filter, setFilter] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [progress, setProgress] = useState<string | null>(null)
  const [taskReload, setTaskReload] = useState(0)

  // Track whether the user manually stopped to suppress the "failed" error message.
  const stoppedRef = useRef(false)

  // Restore last-run results from SQLite on mount so the table survives page refresh.
  useEffect(() => {
    engineGet<{ items: ProbeResult[] }>(CAP, '/results')
      .then((d) => { if (d.items?.length) setResults(d.items) })
      .catch(() => {})
  }, [])

  async function stopProbe() {
    stoppedRef.current = true
    try {
      await enginePost(CAP, '/stop', {})
    } catch { /* engine may already be idle */ }
  }

  async function startProbe() {
    const list = targets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (!list.length) { setErr('请填写至少一个目标'); return }
    setErr(null)
    setRunning(true)
    setResults([])
    setProgress('正在提交任务…')
    stoppedRef.current = false

    const params = { targets: list, threads, timeoutMs: timeout, detectWaf, detectCms }
    let task: Awaited<ReturnType<typeof createTask>> | null = null
    try {
      task = await createTask({ capabilityKey: CAP, action: 'probe', params })
      setTaskReload((n) => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'probe', params })

      const finished = await pollTask(task.id, {
        intervalMs: 1500,
        timeoutMs: 10 * 60 * 1000,
        onProgress: (t) => setProgress(`${t.message ?? '探测中…'} (${t.progress}%)`),
      })

      if (finished.status === 'succeeded') {
        try {
          const r = await engineGet<{ items: ProbeResult[] }>(CAP, '/findings', { taskId: finished.id })
          setResults(r.items ?? [])
        } catch { setErr('加载结果失败') }
        setProgress(null)
      } else if (finished.status === 'failed' && !stoppedRef.current) {
        setErr(finished.error ?? '探测失败')
      }
    } catch (e: unknown) {
      if (!stoppedRef.current) {
        const msg = e instanceof ApiError ? e.message : (e instanceof Error ? e.message : String(e))
        if (task) await updateTask(task.id, { status: 'failed', error: msg }).catch(() => {})
        setErr(msg)
      }
    } finally {
      setRunning(false)
      setProgress(null)
      stoppedRef.current = false
      setTaskReload((n) => n + 1)
    }
  }

  const fl = filter.toLowerCase()
  const filtered = results.filter(
    (r) => !fl ||
      r.host.toLowerCase().includes(fl) ||
      r.cms.toLowerCase().includes(fl) ||
      r.framework.toLowerCase().includes(fl) ||
      r.waf.toLowerCase().includes(fl) ||
      r.server.toLowerCase().includes(fl) ||
      r.title.toLowerCase().includes(fl) ||
      (r.components ?? []).some((c) => c.toLowerCase().includes(fl)),
  )
  const withWaf = results.filter((r) => r.waf !== '无').length
  const cmsDetected = results.filter((r) => r.cms !== '—').length

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="探测目标" value={results.length || '—'} icon={<Crosshair size={18} />} />
        <StatCard label="CMS 识别" value={cmsDetected || '—'} icon={<Globe size={18} />} />
        <StatCard label="WAF 保护" value={withWaf || '—'} icon={<Shield size={18} />} />
        <StatCard label="框架/中间件" value={results.length ? new Set(results.filter((r) => r.framework !== '—').map((r) => r.framework)).size : '—'} icon={<Cpu size={18} />} />
      </div>

      <Panel title="发起指纹探测" icon={<Crosshair size={16} />}>
        <div className="space-y-3">
          <textarea value={targets} onChange={(e) => setTargets(e.target.value)} disabled={running}
            rows={3} placeholder={'http://192.168.1.100\nhttps://target.com\n192.168.1.101:8080'}
            className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-sm text-slate-200 outline-none focus:border-cyber" />
          <div className="flex flex-wrap gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">并发
              <input type="number" min={1} max={200} value={threads}
                onChange={(e) => setThreads(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">超时 ms
              <input type="number" min={1000} value={timeout}
                onChange={(e) => setTimeout_(+e.target.value)} disabled={running}
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={detectWaf} onChange={(e) => setDetectWaf(e.target.checked)} disabled={running} />
              WAF 识别
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={detectCms} onChange={(e) => setDetectCms(e.target.checked)} disabled={running} />
              CMS 指纹
            </label>
          </div>
          <div className="flex items-center gap-2">
            {running ? (
              <button onClick={stopProbe}
                className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={14} /> 停止
              </button>
            ) : (
              <button onClick={startProbe}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber">
                <Play size={14} /> 开始探测
              </button>
            )}
            <button onClick={() => { setResults([]); setErr(null) }} disabled={running}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <RefreshCw size={14} /> 清空
            </button>
            {results.length > 0 && (
              <button
                onClick={() => {
                  const csv = ['主机,端口,协议,状态码,CMS,框架,组件,WAF,Server,标题,OS,FaviconHash']
                    .concat(results.map((r) => [
                      r.host, r.port, r.protocol, r.statusCode,
                      r.cms, r.framework, (r.components ?? []).join('|'), r.waf, r.server, r.title, r.os, r.faviconHash ?? '',
                    ].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')))
                    .join('\n')
                  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
                  const a = document.createElement('a')
                  a.href = URL.createObjectURL(blob)
                  a.download = 'probe-results.csv'
                  a.click()
                }}
                className="chip border border-line bg-base-600/60 text-slate-400 ml-auto">
                <Download size={14} /> 导出 CSV
              </button>
            )}
          </div>
          {progress && (
            <div className="flex items-center gap-2 text-sm text-cyber">
              <span className="animate-pulse">●</span> {progress}
            </div>
          )}
          {err && <div className="text-sm text-sev-high">{err}</div>}
        </div>
      </Panel>

      {results.length > 0 && (
        <Panel title={`指纹结果（${filtered.length}）`} icon={<ChevronRight size={16} />}
          action={
            <input value={filter} onChange={(e) => setFilter(e.target.value)}
              placeholder="过滤主机/CMS/框架/WAF/Server/标题…"
              className="rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-300 outline-none focus:border-cyber" />
          }
          bodyClass="p-0"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-slate-500">
                  <th className="px-4 py-2 font-medium">主机</th>
                  <th className="px-4 py-2 font-medium">状态</th>
                  <th className="px-4 py-2 font-medium">CMS · 框架 · Favicon</th>
                  <th className="px-4 py-2 font-medium">WAF</th>
                  <th className="px-4 py-2 font-medium">Server</th>
                  <th className="px-4 py-2 font-medium">OS</th>
                  <th className="px-4 py-2 font-medium">标题</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filtered.map((r, i) => (
                  <tr key={i} className="hover:bg-base-600/40">
                    <td className="px-4 py-2 font-mono text-cyber text-xs">{r.protocol}://{r.host}:{r.port}</td>
                    <td className={`px-4 py-2 font-mono text-xs ${statusColor(r.statusCode)}`}>
                      {r.statusCode || '—'}
                    </td>
                    <td className="px-4 py-2 text-slate-300 text-xs max-w-48">
                      <div className="flex flex-wrap items-center gap-1">
                        {r.components && r.components.length > 0 ? (
                          r.components.map((c, ci) => (
                            <span key={ci} className={`chip ${
                              ci === 0
                                ? 'border border-cyber/30 bg-cyber/10 text-cyber'
                                : 'border border-purple-500/30 bg-purple-500/10 text-purple-400'
                            }`}>{c}</span>
                          ))
                        ) : (
                          <>
                            {r.cms !== '—' && (
                              <span className="chip border border-cyber/30 bg-cyber/10 text-cyber">{r.cms}</span>
                            )}
                            {r.framework !== '—' && (
                              <span className="chip border border-purple-500/30 bg-purple-500/10 text-purple-400">{r.framework}</span>
                            )}
                            {r.cms === '—' && r.framework === '—' && (
                              <span className="text-slate-500">—</span>
                            )}
                          </>
                        )}
                        {r.faviconHash ? (
                          <span className="chip border border-slate-600/40 bg-slate-700/40 text-slate-500 font-mono text-[10px]" title={`Favicon Hash（Shodan/Fofa）: ${r.faviconHash}`}>
                            #{r.faviconHash}
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className={`px-4 py-2 text-xs ${wafColor(r.waf)}`}>
                      {r.waf !== '无' ? (
                        <span className="chip border border-amber-400/30 bg-amber-400/10 text-amber-400">{r.waf}</span>
                      ) : <span className="text-slate-500">—</span>}
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-400 max-w-32 truncate">{r.server}</td>
                    <td className="px-4 py-2 text-xs text-slate-400">{r.os !== '—' ? r.os : <span className="text-slate-600">—</span>}</td>
                    <td className="px-4 py-2 text-xs text-slate-500 max-w-36 truncate">{r.title || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel title="历史任务" icon={<ChevronRight size={16} />} bodyClass="p-3">
        <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload}
          emptyHint="暂无任务记录，发起一次探测后将登记到此。" />
      </Panel>
    </div>
  )
}
