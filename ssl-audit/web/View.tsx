import { useCallback, useEffect, useRef, useState } from 'react'
import { ShieldCheck, ShieldAlert, ShieldX, Play, Square, RefreshCw } from 'lucide-react'
import { engineGet, enginePost } from '@/lib/engine'
import { createTask, updateTask } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'ssl-audit'

interface ScanStatus {
  running: boolean
  total: number
  probed: number
  found: number
  done: boolean
  error?: string
  startedAt?: string
  endedAt?: string
}

interface Finding {
  id: string
  taskId: string
  host: string
  port: number
  severity: string
  category: string
  label: string
  detail: string
  evidence: string
  foundAt: string
}

interface CertDetail {
  id: string
  taskId: string
  host: string
  port: number
  subject: string
  issuer: string
  notBefore: string
  notAfter: string
  daysLeft: number
  keyType: string
  keyBits: number
  sigAlgo: string
  tlsVersion: string
  cipher: string
  hsts: string
  selfSigned: boolean
  scanErr?: string
}

interface ScanResults {
  hosts: Array<{
    target: { host: string; port: number }  // Go ScanTarget json:"host"/"port"
    cert: CertDetail | null
    findings: Finding[]
    scanErr?: string
  }>
  stats: {
    total: number
    withIssues: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

const SEV_CLASS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/40',
  high:     'bg-orange-500/20 text-orange-400 border border-orange-500/40',
  medium:   'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
  low:      'bg-blue-500/20 text-blue-400 border border-blue-500/40',
  info:     'bg-gray-500/20 text-gray-400 border border-gray-500/40',
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${SEV_CLASS[sev] ?? SEV_CLASS.info}`}>
      {sev}
    </span>
  )
}

function DaysLeft({ days }: { days: number }) {
  const cls = days < 0 ? 'text-red-400' : days < 7 ? 'text-red-400' : days < 30 ? 'text-orange-400' : days < 90 ? 'text-yellow-400' : 'text-green-400'
  return <span className={`font-mono font-semibold ${cls}`}>{days < 0 ? '已过期' : `${days}天`}</span>
}

export default function View() {
  const [targets, setTargets] = useState('')
  const [concurrency, setConcurrency] = useState(10)
  const [timeoutMs, setTimeoutMs] = useState(10000)
  const [activeTab, setActiveTab] = useState<'findings' | 'certs'>('findings')
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [results, setResults] = useState<ScanResults | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [taskReload, setTaskReload] = useState(0)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)
  const taskIdRef = useRef<string | null>(null)

  const refresh = useCallback(async () => {
    const [st, res] = await Promise.all([
      engineGet<ScanStatus>(CAP, '/status'),
      engineGet<ScanResults>(CAP, '/results'),
    ])
    setStatus(st)
    setResults(res)
    return st
  }, [])

  const stopPolling = useCallback(() => {
    if (timer.current) { clearInterval(timer.current); timer.current = null }
  }, [])

  const startPolling = useCallback(() => {
    if (timer.current) return
    timer.current = setInterval(async () => {
      try {
        const st = await refresh()
        if (!st.running && st.done) {
          stopPolling()
          setTaskReload((n) => n + 1)
          if (taskIdRef.current) {
            await updateTask(taskIdRef.current, { status: st.error ? 'failed' : 'succeeded', error: st.error }).catch(() => {})
          }
        }
      } catch { /* 轮询瞬时错误忽略 */ }
    }, 1500)
  }, [refresh, stopPolling])

  useEffect(() => {
    refresh().catch(() => {})
    return stopPolling
  }, [refresh, stopPolling])

  async function startScan() {
    const list = targets.split(/[\n,;]+/).map((t) => t.trim()).filter(Boolean)
    if (!list.length) { setErr('请填写至少一个目标'); return }
    setBusy(true); setErr(null)
    try {
      const params = { targets: list, concurrency, timeoutMs }
      const t = await createTask({ capabilityKey: CAP, action: 'scan', params })
      taskIdRef.current = t.id
      setTaskReload((n) => n + 1)
      try {
        await enginePost(CAP, '/invoke', { taskId: t.id, function: 'scan', params })
      } catch (e) {
        await updateTask(t.id, { status: 'failed', error: String((e as Error)?.message ?? e) }).catch(() => {})
        setTaskReload((n) => n + 1)
        throw e
      }
      startPolling()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  async function stopScan() {
    await enginePost(CAP, '/stop').catch(() => {})
    stopPolling()
    setTaskReload((n) => n + 1)
  }

  const pct = status && status.total > 0 ? Math.round((status.probed / status.total) * 100) : 0
  const allFindings = results?.hosts.flatMap((h) => h.findings ?? []) ?? []
  const allCerts    = results?.hosts.map((h) => h.cert).filter(Boolean) as CertDetail[] ?? []
  const stats       = results?.stats

  return (
    <div className="space-y-4 animate-fade-in">

      {/* 统计概览 */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {[
          { label: '扫描目标', value: stats?.total ?? '—' },
          { label: '有问题', value: stats?.withIssues ?? '—', cls: 'text-orange-400' },
          { label: 'Critical', value: stats?.critical ?? '—', cls: 'text-red-400' },
          { label: 'High', value: stats?.high ?? '—', cls: 'text-orange-400' },
          { label: 'Medium', value: stats?.medium ?? '—', cls: 'text-yellow-400' },
        ].map(({ label, value, cls }) => (
          <div key={label} className="rounded-lg border border-line bg-base-700/40 px-4 py-3">
            <div className={`text-2xl font-bold ${cls ?? 'text-cyber'}`}>{value}</div>
            <div className="mt-0.5 text-xs text-muted">{label}</div>
          </div>
        ))}
      </div>

      {/* 扫描配置 */}
      <div className="rounded-lg border border-line bg-base-800">
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          <ShieldCheck size={15} className="text-cyber" />
          <span className="text-sm font-medium">发起扫描</span>
        </div>
        <div className="space-y-3 p-4">
          <textarea
            className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-sm placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-cyber"
            rows={4}
            placeholder={'目标，每行一个\nexample.com\nexample.com:8443\n192.168.1.1'}
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            disabled={status?.running || busy}
          />
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-2 text-muted">
              并发数
              <input type="number" min={1} max={20} value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                disabled={status?.running || busy}
                className="w-16 rounded border border-line bg-base-700 px-2 py-1 text-center text-xs" />
            </label>
            <label className="flex items-center gap-2 text-muted">
              超时(ms)
              <input type="number" min={3000} max={30000} step={1000} value={timeoutMs}
                onChange={(e) => setTimeoutMs(Number(e.target.value))}
                disabled={status?.running || busy}
                className="w-20 rounded border border-line bg-base-700 px-2 py-1 text-center text-xs" />
            </label>
          </div>

          {/* 进度条 */}
          {status?.running && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-muted">
                <span>正在扫描… {status.probed}/{status.total}</span>
                <span>{pct}%</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-base-600">
                <div className="h-full rounded-full bg-cyber transition-all" style={{ width: `${pct}%` }} />
              </div>
            </div>
          )}

          <div className="flex gap-2">
            {status?.running ? (
              <button onClick={stopScan}
                className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500">
                <Square size={13} /> 停止扫描
              </button>
            ) : (
              <button onClick={startScan} disabled={busy}
                className="flex items-center gap-1.5 rounded-lg bg-cyber px-4 py-2 text-sm font-medium text-black hover:opacity-90 disabled:opacity-50">
                <Play size={13} /> 发起扫描
              </button>
            )}
            <button onClick={() => refresh().catch(() => {})}
              className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-2 text-sm text-muted hover:text-foreground">
              <RefreshCw size={13} />
            </button>
          </div>

          {err && <div className="text-sm text-red-400">{err}</div>}
        </div>
      </div>

      {/* 结果 Tabs */}
      {(allFindings.length > 0 || allCerts.length > 0) && (
        <div className="rounded-lg border border-line bg-base-800">
          <div className="flex items-center gap-1 border-b border-line px-2 pt-2">
            {(['findings', 'certs'] as const).map((tab) => (
              <button key={tab} onClick={() => setActiveTab(tab)}
                className={`rounded-t px-4 py-2 text-sm font-medium transition-colors ${activeTab === tab ? 'border-b-2 border-cyber text-cyber' : 'text-muted hover:text-foreground'}`}>
                {tab === 'findings' ? `发现问题 (${allFindings.length})` : `证书详情 (${allCerts.length})`}
              </button>
            ))}
          </div>

          {activeTab === 'findings' && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-xs text-muted">
                    <th className="px-4 py-2 w-24">严重度</th>
                    <th className="px-4 py-2">主机</th>
                    <th className="px-4 py-2 w-20">分类</th>
                    <th className="px-4 py-2">问题</th>
                    <th className="px-4 py-2">详情</th>
                  </tr>
                </thead>
                <tbody>
                  {allFindings.map((f) => (
                    <tr key={f.id} className="border-b border-line/50 hover:bg-base-700/30">
                      <td className="px-4 py-2"><SevBadge sev={f.severity} /></td>
                      <td className="px-4 py-2 font-mono text-xs text-cyber">{f.host}:{f.port}</td>
                      <td className="px-4 py-2 text-xs text-muted">{f.category}</td>
                      <td className="px-4 py-2 font-medium">{f.label}</td>
                      <td className="px-4 py-2 text-xs text-muted max-w-xs truncate" title={f.detail}>{f.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'certs' && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-xs text-muted">
                    <th className="px-4 py-2">主机</th>
                    <th className="px-4 py-2">证书 CN</th>
                    <th className="px-4 py-2">颁发机构</th>
                    <th className="px-4 py-2 w-20">剩余天数</th>
                    <th className="px-4 py-2 w-24">TLS 版本</th>
                    <th className="px-4 py-2 w-24">密钥</th>
                  </tr>
                </thead>
                <tbody>
                  {allCerts.map((c) => (
                    <tr key={c.id} className="border-b border-line/50 hover:bg-base-700/30">
                      <td className="px-4 py-2 font-mono text-xs text-cyber">{c.host}:{c.port}</td>
                      <td className="px-4 py-2 text-xs max-w-xs truncate" title={c.subject}>{c.subject}</td>
                      <td className="px-4 py-2 text-xs text-muted max-w-xs truncate" title={c.issuer}>{c.issuer}</td>
                      <td className="px-4 py-2"><DaysLeft days={c.daysLeft} /></td>
                      <td className="px-4 py-2 text-xs">
                        <span className={`rounded px-1.5 py-0.5 ${c.tlsVersion === 'TLS 1.3' ? 'bg-green-500/20 text-green-400' : c.tlsVersion === 'TLS 1.2' ? 'bg-blue-500/20 text-blue-400' : 'bg-red-500/20 text-red-400'}`}>
                          {c.tlsVersion}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs text-muted">{c.keyType} {c.keyBits}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* 历史任务 */}
      <div className="rounded-lg border border-line bg-base-800">
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          <span className="text-sm font-medium">历史任务</span>
        </div>
        <div className="p-4">
          <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload} />
        </div>
      </div>

    </div>
  )
}
