import { useEffect, useRef, useState } from 'react'
import {
  KeySquare, Play, Square, Download, RefreshCw,
  CheckCircle2, BookOpen, X, ChevronLeft, ChevronRight,
} from 'lucide-react'
import { Progress } from '@/components/ui'
import { engineGet, enginePost } from '@/lib/engine'
import { createTask, updateTask, pollTask, listTasks, type TaskRecord } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'brute-force'

// ── 协议配置（左侧列表） ──────────────────────────────────────────────────────

interface ProtoConfig {
  id: string
  label: string
  defaultPort: number
  port: number
  enabled: boolean
}

const INITIAL_PROTOCOLS: ProtoConfig[] = [
  { id: 'ssh',        label: 'SSH',        defaultPort: 22,    port: 22,    enabled: true  },
  { id: 'ftp',        label: 'FTP',        defaultPort: 21,    port: 21,    enabled: true  },
  { id: 'telnet',     label: 'Telnet',     defaultPort: 23,    port: 23,    enabled: false },
  { id: 'smtp',       label: 'SMTP',       defaultPort: 25,    port: 25,    enabled: false },
  { id: 'pop3',       label: 'POP3',       defaultPort: 110,   port: 110,   enabled: false },
  { id: 'imap',       label: 'IMAP',       defaultPort: 143,   port: 143,   enabled: false },
  { id: 'http-basic', label: 'HTTP Basic', defaultPort: 80,    port: 80,    enabled: false },
  { id: 'http-form',  label: 'HTTP Form',  defaultPort: 80,    port: 80,    enabled: false },
  { id: 'mysql',      label: 'MySQL',      defaultPort: 3306,  port: 3306,  enabled: true  },
  { id: 'mssql',      label: 'MSSQL',      defaultPort: 1433,  port: 1433,  enabled: false },
  { id: 'redis',      label: 'Redis',      defaultPort: 6379,  port: 6379,  enabled: true  },
  { id: 'postgresql', label: 'PostgreSQL', defaultPort: 5432,  port: 5432,  enabled: false },
  { id: 'mongodb',    label: 'MongoDB',    defaultPort: 27017, port: 27017, enabled: false },
  { id: 'ldap',       label: 'LDAP',       defaultPort: 389,   port: 389,   enabled: false },
  { id: 'smb',        label: 'SMB',        defaultPort: 445,   port: 445,   enabled: false },
  { id: 'vnc',        label: 'VNC',        defaultPort: 5900,  port: 5900,  enabled: false },
  { id: 'dameng',     label: '达梦DM',     defaultPort: 5236,  port: 5236,  enabled: false },
]

// ── 每协议字典配置 ────────────────────────────────────────────────────────────

interface ProtoDict {
  usernamePreset: string
  usernames: string
  passwordPreset: string
  passwords: string
}

const DEFAULT_DICT: ProtoDict = {
  usernamePreset: 'top10',
  usernames: '',
  passwordPreset: 'weak',
  passwords: '',
}

const U_PRESETS = [
  { v: 'none',    l: '仅自定义' },
  { v: 'top10',   l: 'Top10' },
  { v: 'common',  l: 'Common(25)' },
  { v: 'service', l: 'Service' },
]
const P_PRESETS = [
  { v: 'none',   l: '仅自定义' },
  { v: 'top10',  l: 'Top10' },
  { v: 'weak',   l: 'Weak(28)' },
  { v: 'top100', l: 'Top100' },
]

// ── 结果类型 ──────────────────────────────────────────────────────────────────

interface BruteResult {
  protocol: string
  target: string    // host:port
  username: string
  password: string
  success: number | boolean
  errMsg: string
  foundAt: string
}

// ── 主组件 ───────────────────────────────────────────────────────────────────

export default function BruteForceView() {
  // 协议列表
  const [protocols, setProtocols] = useState<ProtoConfig[]>(INITIAL_PROTOCOLS)
  // 目标
  const [targetsText, setTargetsText] = useState('')
  // 每协议字典
  const [protoDicts, setProtoDicts] = useState<Record<string, ProtoDict>>({})
  // 字典配置弹窗
  const [dictOpen, setDictOpen] = useState(false)
  const [dictTab, setDictTab] = useState('ssh')
  // HTTP Form 配置
  const [httpFormURL, setHttpFormURL] = useState('')
  const [httpFormUser, setHttpFormUser] = useState('username')
  const [httpFormPass, setHttpFormPass] = useState('password')
  const [httpFormFail, setHttpFormFail] = useState('')
  // 参数
  const [threads, setThreads] = useState(20)
  const [timeoutMs, setTimeoutMs] = useState(5000)
  const [stopOnFirst, setStopOnFirst] = useState(true)
  // 任务状态
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<BruteResult[]>([])
  const [progress, setProgress] = useState<string | null>(null)
  const [progressPct, setProgressPct] = useState(0)
  const [err, setErr] = useState<string | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const [taskReload, setTaskReload] = useState(0)
  const [histOpen, setHistOpen] = useState(false)

  const stoppedRef = useRef(false)
  const mountedRef = useRef(true)
  const startTimeRef = useRef(0)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // 计时器
  useEffect(() => {
    if (running) {
      startTimeRef.current = Date.now()
      timerRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000))
      }, 1000)
    } else {
      if (timerRef.current) clearInterval(timerRef.current)
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [running])

  // 重连正在跑的任务
  useEffect(() => {
    mountedRef.current = true
    async function init() {
      try {
        const s = await engineGet<{ running: boolean }>(CAP, '/status')
        if (!mountedRef.current || !s.running) return
        const [rt, pt] = await Promise.all([
          listTasks({ capabilityKey: CAP, status: 'running', limit: 1 }),
          listTasks({ capabilityKey: CAP, status: 'pending', limit: 1 }),
        ])
        const active = rt[0] ?? pt[0]
        if (!active || !mountedRef.current) return
        setRunning(true); setProgress('重连任务…'); setTaskReload(n => n + 1)
        pollTask(active.id, {
          intervalMs: 2000, timeoutMs: 30 * 60 * 1000,
          onProgress: t => { if (mountedRef.current) { setProgress(t.message ?? '爆破中…'); setProgressPct(t.progress) } },
        }).then(async fin => {
          if (!mountedRef.current) return
          await applyFinished(fin)
          setRunning(false); setProgress(null); setProgressPct(0)
          setTaskReload(n => n + 1); stoppedRef.current = false
        }).catch(() => { if (mountedRef.current) setRunning(false) })
      } catch { /* ignore */ }
    }
    init()
    return () => { mountedRef.current = false }
  }, [])

  // ── 辅助 ──────────────────────────────────────────────────────────────────
  function getDict(id: string): ProtoDict { return protoDicts[id] ?? DEFAULT_DICT }
  function setDict(id: string, patch: Partial<ProtoDict>) {
    setProtoDicts(prev => ({ ...prev, [id]: { ...(prev[id] ?? DEFAULT_DICT), ...patch } }))
  }
  function toggleProto(id: string) {
    setProtocols(prev => prev.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p))
  }
  function setProtoPort(id: string, port: number) {
    setProtocols(prev => prev.map(p => p.id === id ? { ...p, port } : p))
  }

  const enabledProtos = protocols.filter(p => p.enabled)

  async function applyFinished(fin: TaskRecord) {
    if (fin.status === 'succeeded') {
      try {
        const r = await engineGet<{ items: BruteResult[] }>(CAP, `/findings?taskId=${fin.id}`)
        setResults(r.items ?? []); setErr(null)
      } catch { setErr('加载结果失败') }
    } else if (fin.status === 'failed' && !stoppedRef.current) {
      setErr(fin.error ?? '任务失败')
    }
  }

  // ── 开始爆破 ──────────────────────────────────────────────────────────────
  async function startBrute() {
    const targets = targetsText.trim()
    if (!targets || enabledProtos.length === 0 || running) return
    stoppedRef.current = false
    setErr(null); setResults([]); setProgressPct(0); setElapsed(0)

    // 构建端口覆盖（只传非默认端口）
    const portParts: string[] = []
    for (const p of enabledProtos) {
      if (p.port !== p.defaultPort) portParts.push(`${p.id}:${p.port}`)
    }

    // 构建每协议字典
    const dictParam: Record<string, {
      usernamePreset: string; usernames: string;
      passwordPreset: string; passwords: string;
    }> = {}
    for (const p of enabledProtos) {
      const d = getDict(p.id)
      dictParam[p.id] = {
        usernamePreset: d.usernamePreset, usernames: d.usernames,
        passwordPreset: d.passwordPreset, passwords: d.passwords,
      }
    }

    const params = {
      targets,
      protocols: enabledProtos.map(p => p.id).join('\n'),
      threads, timeoutMs, stopOnFirst,
      portOverrides: portParts.join(','),
      httpFormURL, httpFormUserField: httpFormUser,
      httpFormPassField: httpFormPass, httpFormFailText: httpFormFail,
      protoDicts: dictParam,
    }

    let task: Awaited<ReturnType<typeof createTask>> | null = null
    let finished: TaskRecord | null = null

    setRunning(true); setProgress('启动中…'); setTaskReload(n => n + 1)
    try {
      task = await createTask({ capabilityKey: CAP, action: 'brute', params })
      setTaskReload(n => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'brute', params })
      finished = await pollTask(task.id, {
        intervalMs: 2000, timeoutMs: 60 * 60 * 1000,
        onProgress: t => { if (mountedRef.current) { setProgress(t.message ?? '爆破中…'); setProgressPct(t.progress) } },
      })
    } catch (e: unknown) {
      if (!stoppedRef.current && mountedRef.current) {
        const msg = e instanceof Error ? e.message : String(e)
        if (task) await updateTask(task.id, { status: 'failed', error: msg }).catch(() => {})
        setErr(msg)
      }
    } finally {
      if (mountedRef.current) {
        if (finished) await applyFinished(finished)
        setRunning(false); setProgress(null); setProgressPct(0)
        setTaskReload(n => n + 1); stoppedRef.current = false
      }
    }
  }

  async function stopBrute() {
    stoppedRef.current = true
    try { await enginePost(CAP, '/stop', {}) } catch { /* ignore */ }
    setRunning(false); setProgress(null); setProgressPct(0)
  }

  function exportCSV() {
    const header = 'ID,IP,Port,Serv,User,Pass,Time'
    const rows = successes.map((r, i) => {
      const [ip, port] = splitTarget(r.target)
      return [i + 1, ip, port, r.protocol, r.username, r.password, r.foundAt]
        .map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
    })
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url
    a.download = `brute-force-${Date.now()}.csv`
    a.click(); URL.revokeObjectURL(url)
  }

  // 导入目标文件
  function importTargets() {
    const input = document.createElement('input')
    input.type = 'file'; input.accept = '.txt'
    input.onchange = async () => {
      const file = input.files?.[0]; if (!file) return
      const text = await file.text()
      setTargetsText(prev => (prev.trim() ? prev.trim() + '\n' : '') + text.trim())
    }
    input.click()
  }

  const successes = results.filter(r => r.success)
  const queueTotal = enabledProtos.length * (targetsText.trim().split('\n').filter(Boolean).length || 0)

  // ── 渲染 ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full flex-col gap-0 animate-fade-in" style={{ minHeight: 0 }}>

      {/* ─── 顶部工具栏 ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-base-800/80 px-4 py-2">
        {/* 刷新 */}
        <button
          onClick={() => { setResults([]); setErr(null) }}
          className="chip border border-line bg-base-700/40 text-slate-400 hover:text-slate-200"
        >
          <RefreshCw size={13} /> 刷新
        </button>

        {/* 目标导入 */}
        <button
          onClick={importTargets}
          className="chip border border-line bg-base-700/40 text-slate-400 hover:text-slate-200"
        >
          <ChevronLeft size={13} />目标导入
        </button>

        {/* 字典配置 */}
        <button
          onClick={() => { setDictOpen(true); setDictTab(enabledProtos[0]?.id ?? 'ssh') }}
          className="chip border border-cyber/40 bg-cyber/10 text-cyber font-medium"
        >
          <BookOpen size={13} /> 字典配置
        </button>

        <div className="h-4 w-px bg-line" />

        {/* 线程 */}
        <label className="flex items-center gap-1.5 text-xs text-slate-400">
          线程
          <input type="number" value={threads} min={1} max={500}
            onChange={e => setThreads(Number(e.target.value))}
            className="w-16 rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyber" />
        </label>

        {/* 超时 */}
        <label className="flex items-center gap-1.5 text-xs text-slate-400">
          超时(ms)
          <input type="number" value={timeoutMs} min={500} max={30000} step={500}
            onChange={e => setTimeoutMs(Number(e.target.value))}
            className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyber" />
        </label>

        <div className="h-4 w-px bg-line" />

        {/* 仅破解一个账户 */}
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-300">
          <input type="checkbox" checked={stopOnFirst} onChange={e => setStopOnFirst(e.target.checked)}
            className="accent-cyber" />
          仅破解一个账户
        </label>

        {/* 历史任务 */}
        <button
          onClick={() => setHistOpen(v => !v)}
          className={`ml-auto chip border text-xs ${histOpen ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}
        >
          <ChevronRight size={13} /> 任务历史
        </button>
      </div>

      {/* ─── 主体：左侧协议 + 右侧内容 ────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">

        {/* 左侧协议列表 */}
        <div className="flex w-44 flex-shrink-0 flex-col border-r border-line bg-base-900/60 overflow-y-auto">
          <div className="border-b border-line px-3 py-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">
            服务&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;端口
          </div>
          {protocols.map(p => (
            <div
              key={p.id}
              className={`group flex items-center gap-2 border-b border-line/40 px-3 py-1.5 transition ${
                p.enabled ? 'bg-cyber/5' : 'opacity-50 hover:opacity-80'
              }`}
            >
              {/* checkbox */}
              <button
                onClick={() => toggleProto(p.id)}
                className={`flex h-4 w-4 flex-shrink-0 items-center justify-center rounded border text-[10px] transition ${
                  p.enabled
                    ? 'border-emerald-500/60 bg-emerald-500/20 text-emerald-400'
                    : 'border-line bg-base-700/40 text-slate-600'
                }`}
              >
                {p.enabled && '✓'}
              </button>
              {/* label */}
              <span className={`flex-1 text-xs ${p.enabled ? 'text-slate-200' : 'text-slate-500'}`}>
                {p.label}
              </span>
              {/* port */}
              <input
                type="number"
                value={p.port}
                onChange={e => setProtoPort(p.id, Number(e.target.value))}
                className="w-14 rounded border border-transparent bg-transparent text-right text-xs text-slate-400 outline-none focus:border-line focus:bg-base-700/60 focus:text-slate-200"
              />
            </div>
          ))}
        </div>

        {/* 右侧主内容 */}
        <div className="flex flex-1 flex-col overflow-hidden">

          {/* 目标输入 + 操作按钮行 */}
          <div className="flex gap-3 border-b border-line p-3">
            {/* 目标文本框 */}
            <div className="flex-1">
              <textarea
                value={targetsText}
                onChange={e => setTargetsText(e.target.value)}
                rows={4}
                placeholder={"192.168.1.1, 192.168.1.1/24\n192.168.1.1:2222\nSSH://192.168.1.1:22"}
                className="w-full resize-none rounded-lg border border-cyber/30 bg-base-800/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber placeholder:text-slate-600"
              />
            </div>

            {/* 右侧按钮组 */}
            <div className="flex flex-col justify-between gap-2 py-0.5">
              {!running ? (
                <button
                  onClick={startBrute}
                  disabled={!targetsText.trim() || enabledProtos.length === 0}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-5 py-2 text-sm font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-40"
                >
                  <Play size={14} fill="currentColor" /> Crack
                </button>
              ) : (
                <button
                  onClick={stopBrute}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-sev-high/40 bg-sev-high/10 px-5 py-2 text-sm font-semibold text-sev-high transition hover:bg-sev-high/20"
                >
                  <Square size={14} fill="currentColor" /> Stop
                </button>
              )}
              <button
                onClick={exportCSV}
                disabled={successes.length === 0}
                className="flex items-center justify-center gap-1.5 rounded-lg border border-line bg-base-700/40 px-4 py-2 text-xs text-slate-400 transition hover:text-slate-200 disabled:opacity-30"
              >
                <Download size={13} /> 导出
              </button>
            </div>
          </div>

          {/* 进度条 */}
          {running && (
            <div className="border-b border-line px-4 py-2 space-y-1">
              <Progress value={progressPct} />
              <p className="flex items-center gap-1.5 text-xs text-slate-400">
                <RefreshCw size={10} className="animate-spin" />{progress ?? '爆破中…'}
              </p>
            </div>
          )}
          {err && (
            <div className="border-b border-line px-4 py-2">
              <div className="rounded border border-sev-high/30 bg-sev-high/10 px-3 py-1.5 text-xs text-sev-high">{err}</div>
            </div>
          )}

          {/* 结果表格 */}
          <div className="flex-1 overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-base-900/90 backdrop-blur-sm">
                <tr className="border-b border-line text-left text-slate-500">
                  <th className="px-3 py-2 font-medium w-10">ID</th>
                  <th className="px-3 py-2 font-medium">IP</th>
                  <th className="px-3 py-2 font-medium w-14">Port</th>
                  <th className="px-3 py-2 font-medium w-20">Serv</th>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Pass</th>
                  <th className="px-3 py-2 font-medium w-32">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/40">
                {[...results]
                  .sort((a, b) => (b.success ? 1 : 0) - (a.success ? 1 : 0))
                  .map((r, i) => {
                    const [ip, port] = splitTarget(r.target)
                    const ok = Boolean(r.success)
                    return (
                      <tr key={i} className={ok ? 'bg-emerald-500/5 hover:bg-emerald-500/10' : 'hover:bg-base-700/20 opacity-50'}>
                        <td className="px-3 py-1.5 text-slate-500">{i + 1}</td>
                        <td className="px-3 py-1.5 font-mono text-slate-300">
                          {ok && <CheckCircle2 size={11} className="mr-1 inline text-emerald-400" />}
                          {ip}
                        </td>
                        <td className="px-3 py-1.5 font-mono text-slate-400">{port}</td>
                        <td className="px-3 py-1.5 text-slate-400">{r.protocol}</td>
                        <td className="px-3 py-1.5 font-mono text-slate-200">{r.username}</td>
                        <td className="px-3 py-1.5 font-mono">
                          {ok
                            ? <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 text-emerald-300">{r.password || '(空)'}</span>
                            : <span className="text-slate-500">{r.password || '(空)'}</span>}
                        </td>
                        <td className="px-3 py-1.5 text-slate-500 whitespace-nowrap">
                          {r.foundAt ? r.foundAt.replace('T', ' ').slice(0, 16) : '—'}
                        </td>
                      </tr>
                    )
                  })}
                {results.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-16 text-center text-slate-600">
                      <div className="text-2xl mb-2">⊘</div>
                      No Data
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* 状态栏 */}
          <div className="flex items-center gap-6 border-t border-line bg-base-900/60 px-4 py-1.5 text-xs text-slate-500">
            <span>服务存活: <span className="text-slate-300">{enabledProtos.length}</span></span>
            <span>破解成功: <span className={successes.length > 0 ? 'text-emerald-400 font-semibold' : 'text-slate-300'}>{successes.length}</span></span>
            <span>检测队列: <span className="text-slate-300">{results.length}/{queueTotal || '—'}</span></span>
            <span>用时: <span className="text-slate-300">{elapsed}s</span></span>
            {running && <span className="ml-auto flex items-center gap-1 text-cyber"><RefreshCw size={10} className="animate-spin" /> 爆破中…</span>}
          </div>
        </div>

        {/* 任务历史侧边栏 */}
        {histOpen && (
          <div className="w-80 flex-shrink-0 overflow-y-auto border-l border-line bg-base-900/60 p-3">
            <TaskList params={{ capabilityKey: CAP }} reloadToken={taskReload} />
          </div>
        )}
      </div>

      {/* ─── 字典配置弹窗 ──────────────────────────────────────────────── */}
      {dictOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="relative flex w-[720px] max-w-[95vw] max-h-[85vh] flex-col rounded-xl border border-line bg-base-900 shadow-2xl">
            {/* 弹窗标题 */}
            <div className="flex items-center justify-between border-b border-line px-5 py-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <BookOpen size={15} className="text-cyber" />
                字典配置 — 每种协议独立字典
              </div>
              <button onClick={() => setDictOpen(false)} className="text-slate-500 hover:text-slate-200">
                <X size={16} />
              </button>
            </div>

            {/* 协议 Tab */}
            <div className="flex overflow-x-auto border-b border-line bg-base-800/40 px-4 pt-2 gap-1">
              {enabledProtos.map(p => (
                <button
                  key={p.id}
                  onClick={() => setDictTab(p.id)}
                  className={`px-3 py-1.5 text-xs rounded-t border-b-2 transition whitespace-nowrap ${
                    dictTab === p.id
                      ? 'border-cyber text-cyber bg-cyber/10'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {p.label}
                </button>
              ))}
              {enabledProtos.length === 0 && (
                <span className="py-2 text-xs text-slate-500">请先在左侧勾选协议</span>
              )}
            </div>

            {/* 字典配置内容 */}
            <div className="flex-1 overflow-y-auto p-5">
              {enabledProtos.length === 0 ? (
                <p className="text-center text-sm text-slate-500 py-8">请先在左侧列表中勾选要爆破的协议</p>
              ) : (() => {
                const proto = enabledProtos.find(p => p.id === dictTab) ?? enabledProtos[0]
                const dict = getDict(proto.id)
                return (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      {/* 用户名字典 */}
                      <div>
                        <p className="mb-2 text-xs font-semibold text-slate-300">用户名字典</p>
                        <div className="mb-2 flex gap-1 flex-wrap">
                          {U_PRESETS.map(opt => (
                            <button key={opt.v}
                              onClick={() => setDict(proto.id, { usernamePreset: opt.v })}
                              className={`rounded border px-2 py-1 text-xs transition ${
                                dict.usernamePreset === opt.v
                                  ? 'border-cyber/50 bg-cyber/15 text-cyber'
                                  : 'border-line bg-base-700/40 text-slate-400 hover:text-slate-200'
                              }`}>
                              {opt.l}
                            </button>
                          ))}
                        </div>
                        <textarea
                          value={dict.usernames}
                          onChange={e => setDict(proto.id, { usernames: e.target.value })}
                          rows={6}
                          placeholder={"admin\nroot\noperator"}
                          className="w-full resize-none rounded-lg border border-line bg-base-800/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
                        />
                        <p className="mt-1 text-xs text-slate-500">与预设合并去重</p>
                      </div>

                      {/* 密码字典 */}
                      <div>
                        <p className="mb-2 text-xs font-semibold text-slate-300">密码字典</p>
                        <div className="mb-2 flex gap-1 flex-wrap">
                          {P_PRESETS.map(opt => (
                            <button key={opt.v}
                              onClick={() => setDict(proto.id, { passwordPreset: opt.v })}
                              className={`rounded border px-2 py-1 text-xs transition ${
                                dict.passwordPreset === opt.v
                                  ? 'border-cyber/50 bg-cyber/15 text-cyber'
                                  : 'border-line bg-base-700/40 text-slate-400 hover:text-slate-200'
                              }`}>
                              {opt.l}
                            </button>
                          ))}
                        </div>
                        <textarea
                          value={dict.passwords}
                          onChange={e => setDict(proto.id, { passwords: e.target.value })}
                          rows={6}
                          placeholder={"Company@2024\nWelcome123\n(空行=空密码)"}
                          className="w-full resize-none rounded-lg border border-line bg-base-800/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
                        />
                        <p className="mt-1 text-xs text-slate-500">空行表示空密码</p>
                      </div>
                    </div>

                    {/* HTTP Form 专属配置 */}
                    {proto.id === 'http-form' && (
                      <div className="rounded-lg border border-indigo-400/30 bg-indigo-400/5 p-4">
                        <p className="mb-3 text-xs font-semibold text-indigo-300">HTTP Form 配置</p>
                        <div className="grid grid-cols-2 gap-3">
                          {[
                            { l: '登录 URL', v: httpFormURL, s: setHttpFormURL, ph: 'http://example.com/login' },
                            { l: '失败标志文本', v: httpFormFail, s: setHttpFormFail, ph: '用户名或密码错误' },
                            { l: '用户名字段名', v: httpFormUser, s: setHttpFormUser, ph: 'username' },
                            { l: '密码字段名', v: httpFormPass, s: setHttpFormPass, ph: 'password' },
                          ].map(({ l, v, s, ph }) => (
                            <div key={l}>
                              <label className="mb-1 block text-xs text-slate-400">{l}</label>
                              <input value={v} onChange={e => s(e.target.value)} placeholder={ph}
                                className="w-full rounded border border-line bg-base-800/60 px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-indigo-400" />
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })()}
            </div>

            {/* 弹窗底部 */}
            <div className="flex items-center justify-between border-t border-line px-5 py-3">
              <span className="text-xs text-slate-500">
                已配置 {enabledProtos.length} 个协议的独立字典
              </span>
              <button
                onClick={() => setDictOpen(false)}
                className="rounded-lg border border-cyber/40 bg-cyber/10 px-4 py-1.5 text-sm text-cyber hover:bg-cyber/20 transition"
              >
                确认
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

function splitTarget(target: string): [string, string] {
  const idx = target.lastIndexOf(':')
  if (idx === -1) return [target, '']
  return [target.slice(0, idx), target.slice(idx + 1)]
}
