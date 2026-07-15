import { useEffect, useRef, useState } from 'react'
import {
  Satellite, Database, Server, Globe, Shield,
  Play, Square, RefreshCw, Download, Save, CheckCircle2,
  ChevronDown, ChevronUp, Key,
} from 'lucide-react'
import { Panel, StatCard, Progress } from '@/components/ui'
import { engineGet, enginePost } from '@/lib/engine'
import { createTask, updateTask, pollTask, listTasks, type TaskRecord } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'osint-fofa'

// ── 类型 ────────────────────────────────────────────────────────────────────

interface Settings {
  fofaEmail: string
  fofaKey: string
  hunterKey: string
  shodanKey: string
  zoomeyeKey: string
  quakeKey: string
}

interface FindingRow {
  taskId: string
  assetId: string
  ip: string
  port: number
  domain: string
  protocol: string
  title: string
  banner: string
  country: string
  city: string
  os: string
  source: string
  createdAt: string
}

const EMPTY_SETTINGS: Settings = {
  fofaEmail: '', fofaKey: '', hunterKey: '', shodanKey: '', zoomeyeKey: '', quakeKey: '',
}

// ── 平台与样式配置 ────────────────────────────────────────────────────────

const PLATFORMS = [
  { id: 'fofa',    label: 'FOFA',           placeholder: 'domain="example.com" && port="80"' },
  { id: 'hunter',  label: 'Hunter（鹰图）',   placeholder: 'domain.suffix="example.com"' },
  { id: 'shodan',  label: 'Shodan',          placeholder: 'hostname:example.com' },
  { id: 'zoomeye', label: 'ZoomEye（钟馗）',  placeholder: 'hostname:example.com' },
  { id: 'quake',   label: 'Quake 360',       placeholder: 'domain:"example.com"' },
  { id: 'all',     label: '全平台聚合',       placeholder: '' },
]

const sourceChip: Record<string, string> = {
  fofa:    'border-blue-400/40 bg-blue-400/10 text-blue-400',
  hunter:  'border-amber-400/40 bg-amber-400/10 text-amber-400',
  shodan:  'border-red-400/40 bg-red-400/10 text-red-400',
  zoomeye: 'border-purple-400/40 bg-purple-400/10 text-purple-400',
  quake:   'border-orange-400/40 bg-orange-400/10 text-orange-400',
}

// ── 主组件 ───────────────────────────────────────────────────────────────────

export default function FofaView() {
  // Settings
  const [savedSettings, setSavedSettings] = useState<Settings>(EMPTY_SETTINGS)
  const [formSettings, setFormSettings]   = useState<Settings>(EMPTY_SETTINGS)
  const [savingKeys, setSavingKeys]        = useState(false)
  const [saveMsg, setSaveMsg]              = useState<string | null>(null)
  const [keysOpen, setKeysOpen]            = useState(false)

  // 查询表单
  const [platform, setPlatform]           = useState('fofa')
  const [fofaQuery, setFofaQuery]         = useState('')
  const [hunterQuery, setHunterQuery]     = useState('')
  const [shodanQuery, setShodanQuery]     = useState('')
  const [zoomeyeQuery, setZoomeyeQuery]   = useState('')
  const [quakeQuery, setQuakeQuery]       = useState('')
  const [pageSize, setPageSize]           = useState(100)

  // 任务状态
  const [running, setRunning]       = useState(false)
  const [progress, setProgress]     = useState<string | null>(null)
  const [progressPct, setProgressPct] = useState(0)
  const [err, setErr]               = useState<string | null>(null)
  const [results, setResults]       = useState<FindingRow[]>([])
  const [filterSrc, setFilterSrc]   = useState('all')
  const [filterQ, setFilterQ]       = useState('')
  const [taskReload, setTaskReload] = useState(0)

  const stoppedRef = useRef(false)
  const mountedRef = useRef(true)

  // ── 初始化 ──────────────────────────────────────────────────────────────
  useEffect(() => {
    mountedRef.current = true

    async function init() {
      try {
        const s = await engineGet<Settings>(CAP, '/settings')
        if (mountedRef.current) setSavedSettings(s)
      } catch { /* 引擎未启用时忽略 */ }

      // 恢复进行中的任务
      try {
        const [running_, pending_] = await Promise.all([
          listTasks({ capabilityKey: CAP, status: 'running', limit: 1 }),
          listTasks({ capabilityKey: CAP, status: 'pending', limit: 1 }),
        ])
        const active = running_[0] ?? pending_[0]
        if (active && mountedRef.current) {
          setRunning(true)
          setProgress('重连查询任务…')
          setTaskReload((n) => n + 1)
          pollTask(active.id, {
            intervalMs: 2000, timeoutMs: 10 * 60 * 1000,
            onProgress: (t) => {
              if (mountedRef.current) {
                setProgress(t.message ?? '查询中…')
                setProgressPct(t.progress)
              }
            },
          }).then(async (fin) => {
            if (!mountedRef.current) return
            await applyFinished(fin, stoppedRef, setResults, setErr)
            setRunning(false); setProgress(null); setProgressPct(0)
            setTaskReload((n) => n + 1); stoppedRef.current = false
          }).catch(() => { if (mountedRef.current) setRunning(false) })
        }
      } catch { /* 无活跃任务 */ }
    }

    init().catch(console.error)
    return () => { mountedRef.current = false }
  }, [])

  // ── 保存 Settings ────────────────────────────────────────────────────────
  async function saveApiKeys() {
    setSavingKeys(true); setSaveMsg(null)
    try {
      await enginePost(CAP, '/settings', formSettings)
      const fresh = await engineGet<Settings>(CAP, '/settings')
      setSavedSettings(fresh)
      setSaveMsg('已保存')
    } catch {
      setSaveMsg('保存失败')
    } finally {
      setSavingKeys(false)
      setTimeout(() => setSaveMsg(null), 3000)
    }
  }

  // ── 执行查询 ─────────────────────────────────────────────────────────────
  async function startQuery() {
    const hasQuery =
      (platform === 'fofa' && fofaQuery.trim()) ||
      (platform === 'hunter' && hunterQuery.trim()) ||
      (platform === 'shodan' && shodanQuery.trim()) ||
      (platform === 'zoomeye' && zoomeyeQuery.trim()) ||
      (platform === 'quake' && quakeQuery.trim()) ||
      (platform === 'all' && (fofaQuery.trim() || hunterQuery.trim() || shodanQuery.trim() || zoomeyeQuery.trim() || quakeQuery.trim()))
    if (!hasQuery || running) return

    stoppedRef.current = false
    setErr(null); setResults([]); setProgressPct(0)

    const params: Record<string, unknown> = {
      platform, pageSize,
      fofaQuery:    fofaQuery.trim(),
      hunterQuery:  hunterQuery.trim(),
      shodanQuery:  shodanQuery.trim(),
      zoomeyeQuery: zoomeyeQuery.trim(),
      quakeQuery:   quakeQuery.trim(),
    }

    let task: Awaited<ReturnType<typeof createTask>> | null = null
    let finished: TaskRecord | null = null

    setRunning(true); setProgress('启动查询…'); setTaskReload((n) => n + 1)

    try {
      task = await createTask({ capabilityKey: CAP, action: 'query', params })
      setTaskReload((n) => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'query', params })
      finished = await pollTask(task.id, {
        intervalMs: 2000, timeoutMs: 10 * 60 * 1000,
        onProgress: (t) => {
          if (mountedRef.current) {
            setProgress(t.message ?? '查询中…')
            setProgressPct(t.progress)
          }
        },
      })
    } catch (e: unknown) {
      if (!stoppedRef.current && mountedRef.current) {
        const msg = e instanceof Error ? e.message : String(e)
        if (task) await updateTask(task.id, { status: 'failed', error: msg }).catch(() => {})
        setErr(msg)
      }
    } finally {
      if (mountedRef.current) {
        if (finished) await applyFinished(finished, stoppedRef, setResults, setErr)
        setRunning(false); setProgress(null); setProgressPct(0)
        setTaskReload((n) => n + 1); stoppedRef.current = false
      }
    }
  }

  async function stopQuery() {
    stoppedRef.current = true
    // 真正通知引擎取消当前查询（原先仅复位本地状态，后台仍会跑到超时）。
    try { await enginePost(CAP, '/stop', {}) } catch { /* 停止请求失败也照常复位本地状态 */ }
    setRunning(false); setProgress(null); setProgressPct(0)
  }

  // ── 统计 & 过滤 ──────────────────────────────────────────────────────────
  const configuredCount = [
    savedSettings.fofaEmail && savedSettings.fofaKey,
    savedSettings.hunterKey,
    savedSettings.shodanKey,
    savedSettings.zoomeyeKey,
    savedSettings.quakeKey,
  ].filter(Boolean).length

  const allSources = [...new Set(results.map((r) => r.source))].sort()

  const filtered = results.filter((r) => {
    if (filterSrc !== 'all' && r.source !== filterSrc) return false
    if (filterQ) {
      const q = filterQ.toLowerCase()
      return r.ip.includes(q) || r.domain.toLowerCase().includes(q) ||
             r.title.toLowerCase().includes(q) || r.protocol.toLowerCase().includes(q)
    }
    return true
  })

  const uniqueIPs = new Set(results.map((r) => r.ip)).size
  const services  = new Set(results.map((r) => r.protocol)).size

  // ── 导出 CSV ─────────────────────────────────────────────────────────────
  function exportCSV() {
    const header = 'ip,port,domain,protocol,title,banner,country,city,os,source'
    const rows = filtered.map((r) =>
      [r.ip, r.port, r.domain, r.protocol, r.title, r.banner, r.country, r.city, r.os, r.source]
        .map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`)
        .join(','),
    )
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `osint-fofa-${platform}-${Date.now()}.csv`
    a.click(); URL.revokeObjectURL(url)
  }

  // ── Settings 字段配置 ─────────────────────────────────────────────────────
  const settingsFields: { key: keyof Settings; label: string }[] = [
    { key: 'fofaEmail',  label: 'FOFA Email' },
    { key: 'fofaKey',    label: 'FOFA API Key' },
    { key: 'hunterKey',  label: 'Hunter API Key' },
    { key: 'shodanKey',  label: 'Shodan API Key' },
    { key: 'zoomeyeKey', label: 'ZoomEye API Key' },
    { key: 'quakeKey',   label: 'Quake 360 Token' },
  ]

  // ── 渲染 ─────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4 animate-fade-in">

      {/* 统计卡片 */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="查询结果" value={results.length || '—'} icon={<Database size={18} />} />
        <StatCard label="唯一 IP"  value={uniqueIPs || '—'}      icon={<Server size={18} />} />
        <StatCard label="服务类型" value={services || '—'}       icon={<Globe size={18} />} />
        <StatCard label="已配置平台" value={`${configuredCount}/5`} icon={<Shield size={18} />} />
      </div>

      {/* API Key 配置（可收起） */}
      <section className="panel">
        <header
          className="panel-head cursor-pointer select-none"
          onClick={() => setKeysOpen((v) => !v)}
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Key size={16} /> API Key 配置
          </div>
          <div className="flex items-center gap-2">
            {configuredCount > 0 && (
              <span className="chip border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs">
                <CheckCircle2 size={12} /> 已配置 {configuredCount}/5 个平台
              </span>
            )}
            {keysOpen
              ? <ChevronUp size={14} className="text-slate-400" />
              : <ChevronDown size={14} className="text-slate-400" />}
          </div>
        </header>

        {keysOpen && (
          <div className="p-4 space-y-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {settingsFields.map(({ key, label }) => {
                const configured = key === 'fofaKey'
                  ? Boolean(savedSettings.fofaEmail && savedSettings.fofaKey)
                  : key === 'fofaEmail'
                  ? Boolean(savedSettings.fofaEmail && savedSettings.fofaKey)
                  : Boolean(savedSettings[key])
                return (
                  <div key={key} className="flex flex-col gap-0.5">
                    <label className="flex items-center gap-1 text-xs text-slate-400">
                      {label}
                      {configured && <CheckCircle2 size={11} className="text-emerald-400" />}
                    </label>
                    <input
                      type="password"
                      value={formSettings[key]}
                      onChange={(e) => setFormSettings((s) => ({ ...s, [key]: e.target.value }))}
                      placeholder={configured ? '已配置（留空使用存储值）' : '未配置'}
                      className="rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
                    />
                  </div>
                )
              })}
            </div>
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={saveApiKeys}
                disabled={savingKeys}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber disabled:opacity-50"
              >
                <Save size={12} /> {savingKeys ? '保存中…' : '保存 Key'}
              </button>
              {saveMsg && (
                <span className={`text-xs ${saveMsg === '已保存' ? 'text-emerald-400' : 'text-sev-high'}`}>
                  {saveMsg}
                </span>
              )}
            </div>
          </div>
        )}
      </section>

      {/* 查询配置 */}
      <Panel title="查询配置" icon={<Satellite size={16} />}>
        <div className="space-y-3">
          {/* 平台选择 */}
          <div className="flex flex-wrap gap-2">
            {PLATFORMS.map((p) => (
              <button
                key={p.id}
                onClick={() => setPlatform(p.id)}
                disabled={running}
                className={`chip border transition disabled:opacity-50 ${
                  platform === p.id
                    ? 'border-cyber/50 bg-cyber/10 text-cyber'
                    : 'border-line bg-base-700/40 text-slate-400 hover:bg-base-600/50'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* 查询语句输入区 */}
          <div className="space-y-2">
            {(platform === 'fofa' || platform === 'all') && (
              <div>
                <label className="mb-1 block text-xs text-slate-400">
                  FOFA 查询语法
                  {platform === 'all' && <span className="ml-1 text-slate-600">（留空则跳过 FOFA）</span>}
                </label>
                <input
                  value={fofaQuery}
                  onChange={(e) => setFofaQuery(e.target.value)}
                  disabled={running}
                  placeholder='domain="example.com" && country="CN"'
                  className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber disabled:opacity-50"
                />
              </div>
            )}
            {(platform === 'hunter' || platform === 'all') && (
              <div>
                <label className="mb-1 block text-xs text-slate-400">
                  Hunter 查询语法
                  {platform === 'all' && <span className="ml-1 text-slate-600">（留空则跳过 Hunter）</span>}
                </label>
                <input
                  value={hunterQuery}
                  onChange={(e) => setHunterQuery(e.target.value)}
                  disabled={running}
                  placeholder='domain.suffix="example.com"'
                  className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber disabled:opacity-50"
                />
              </div>
            )}
            {(platform === 'shodan' || platform === 'all') && (
              <div>
                <label className="mb-1 block text-xs text-slate-400">
                  Shodan 查询语法
                  {platform === 'all' && <span className="ml-1 text-slate-600">（留空则跳过 Shodan）</span>}
                </label>
                <input
                  value={shodanQuery}
                  onChange={(e) => setShodanQuery(e.target.value)}
                  disabled={running}
                  placeholder="hostname:example.com"
                  className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber disabled:opacity-50"
                />
              </div>
            )}
            {(platform === 'zoomeye' || platform === 'all') && (
              <div>
                <label className="mb-1 block text-xs text-slate-400">
                  ZoomEye 查询语法
                  {platform === 'all' && <span className="ml-1 text-slate-600">（留空则跳过 ZoomEye）</span>}
                </label>
                <input
                  value={zoomeyeQuery}
                  onChange={(e) => setZoomeyeQuery(e.target.value)}
                  disabled={running}
                  placeholder="hostname:example.com"
                  className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber disabled:opacity-50"
                />
              </div>
            )}
            {(platform === 'quake' || platform === 'all') && (
              <div>
                <label className="mb-1 block text-xs text-slate-400">
                  Quake 360 查询语法
                  {platform === 'all' && <span className="ml-1 text-slate-600">（留空则跳过 Quake）</span>}
                </label>
                <input
                  value={quakeQuery}
                  onChange={(e) => setQuakeQuery(e.target.value)}
                  disabled={running}
                  placeholder='domain:"example.com"'
                  className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber disabled:opacity-50"
                />
              </div>
            )}
          </div>

          {/* 参数行 */}
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="mb-1 block text-xs text-slate-400">每平台最大结果数</label>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                disabled={running}
                className="rounded-lg border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200 disabled:opacity-50"
              >
                <option value={50}>50 条</option>
                <option value={100}>100 条</option>
                <option value={500}>500 条</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              {!running ? (
                <button
                  onClick={startQuery}
                  className="chip border border-cyber/40 bg-cyber/10 text-cyber"
                >
                  <Play size={14} /> 执行查询
                </button>
              ) : (
                <button
                  onClick={stopQuery}
                  className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high"
                >
                  <Square size={14} /> 停止
                </button>
              )}
              {results.length > 0 && !running && (
                <button
                  onClick={exportCSV}
                  className="chip border border-line bg-base-600/40 text-slate-400 hover:text-slate-200"
                >
                  <Download size={14} /> 导出 CSV
                </button>
              )}
            </div>
          </div>

          {/* 进度 */}
          {running && progress && (
            <div className="space-y-1.5">
              <Progress value={progressPct} />
              <p className="flex items-center gap-1.5 text-xs text-slate-400">
                <RefreshCw size={11} className="animate-spin" /> {progress}
              </p>
            </div>
          )}

          {/* 提示：全平台聚合说明 */}
          {platform === 'all' && !running && (
            <p className="text-xs text-slate-500">
              全平台聚合：FOFA / Hunter / Shodan / ZoomEye / Quake 360 中已配置 Token 且填写对应查询语句的平台将并发查询，结果自动去重。
            </p>
          )}

          {err && (
            <div className="rounded-lg border border-sev-high/30 bg-sev-high/10 px-3 py-2 text-sm text-sev-high">
              {err}
            </div>
          )}
        </div>
      </Panel>

      {/* 结果表格 */}
      {results.length > 0 && (
        <Panel
          title={`查询结果（${filtered.length} / ${results.length}）`}
          icon={<Satellite size={16} />}
          bodyClass="p-0"
          action={
            <div className="flex flex-wrap items-center gap-1.5">
              {allSources.length > 1 && (
                <select
                  value={filterSrc}
                  onChange={(e) => setFilterSrc(e.target.value)}
                  className="rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-300"
                >
                  <option value="all">所有来源</option>
                  {allSources.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              )}
              <input
                value={filterQ}
                onChange={(e) => setFilterQ(e.target.value)}
                placeholder="过滤 IP / 域名 / 协议…"
                className="rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-300 outline-none focus:border-cyber"
              />
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-slate-500">
                  <th className="px-4 py-2 font-medium">IP</th>
                  <th className="px-4 py-2 font-medium">端口</th>
                  <th className="px-4 py-2 font-medium">协议</th>
                  <th className="px-4 py-2 font-medium">域名</th>
                  <th className="px-4 py-2 font-medium">标题</th>
                  <th className="px-4 py-2 font-medium">Banner</th>
                  <th className="px-4 py-2 font-medium">归属</th>
                  <th className="px-4 py-2 font-medium">OS</th>
                  <th className="px-4 py-2 font-medium">来源</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="p-6 text-center text-sm text-slate-500">暂无匹配结果</td>
                  </tr>
                ) : (
                  filtered.map((r, i) => (
                    <tr key={`${r.assetId}:${i}`} className="hover:bg-base-600/30">
                      <td className="px-4 py-2 font-mono text-cyber">{r.ip}</td>
                      <td className="px-4 py-2 font-mono text-slate-300">{r.port}</td>
                      <td className="px-4 py-2">
                        <span className="chip border border-line bg-base-600/60 text-xs text-slate-400">{r.protocol || '—'}</span>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-slate-300 max-w-[140px] truncate">{r.domain || '—'}</td>
                      <td className="px-4 py-2 text-xs text-slate-300 max-w-[160px] truncate" title={r.title}>{r.title || '—'}</td>
                      <td className="px-4 py-2 font-mono text-xs text-slate-500 max-w-[120px] truncate" title={r.banner}>{r.banner || '—'}</td>
                      <td className="px-4 py-2 text-xs text-slate-400 whitespace-nowrap">
                        {[r.country, r.city].filter(Boolean).join(' · ') || '—'}
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-500">{r.os || '—'}</td>
                      <td className="px-4 py-2">
                        <span className={`chip border text-xs ${sourceChip[r.source] ?? 'border-line bg-base-600/60 text-slate-400'}`}>
                          {r.source}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* 任务历史 */}
      <TaskList params={{ capabilityKey: CAP }} reloadToken={taskReload} />
    </div>
  )
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

async function applyFinished(
  finished: TaskRecord,
  stoppedRef: { current: boolean },
  setResults: (r: FindingRow[]) => void,
  setErr: (e: string | null) => void,
) {
  if (finished.status === 'succeeded') {
    try {
      const r = await engineGet<{ items: FindingRow[] }>(CAP, `/findings?taskId=${finished.id}`)
      setResults(r.items ?? [])
      setErr(null)
    } catch {
      setErr('加载结果失败')
    }
  } else if (finished.status === 'failed' && !stoppedRef.current) {
    setErr(finished.error ?? '查询失败')
  }
}
