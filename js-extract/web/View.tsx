import { useRef, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  FileCode2, Globe, KeyRound, ShieldAlert, Play, Square,
  ChevronRight, ChevronDown, Download, Clock, RefreshCw,
  Link2, MapPin, Cloud, Mail, ExternalLink, Hash,
  Flame, BadgeCheck, Layers,
} from 'lucide-react'
import { Panel, StatCard } from '@/components/ui'
import { engineGet, enginePost, engineDownload } from '@/lib/engine'
import { ApiError } from '@/lib/api'
import { createTask, updateTask, pollTask } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'js-extract'

// ── 类型 ─────────────────────────────────────────────────────────────
type Category = 'endpoint' | 'secret' | 'ip' | 'cloud' | 'sourcemap' | 'jwt' | 'email' | 'url'
type Severity  = 'high' | 'medium' | 'low' | 'info'

interface JSFinding {
  id: string
  taskId: string
  jsUrl: string
  pageUrl: string
  category: Category
  severity: Severity
  label: string
  value: string
  ctx: string
  entropy: number
  confident: boolean
  foundAt: string
}

// ── Meta 映射 ────────────────────────────────────────────────────────
const CAT_META: Record<Category, { label: string; Icon: LucideIcon; color: string }> = {
  endpoint:  { label: 'API 端点',   Icon: Link2,     color: 'border-cyber/30 bg-cyber/10 text-cyber' },
  secret:    { label: '密钥凭据',   Icon: KeyRound,  color: 'border-sev-high/30 bg-sev-high/10 text-sev-high' },
  ip:        { label: '内网地址',   Icon: MapPin,    color: 'border-amber-400/30 bg-amber-400/10 text-amber-400' },
  cloud:     { label: '云存储',     Icon: Cloud,     color: 'border-purple-400/30 bg-purple-400/10 text-purple-400' },
  sourcemap: { label: 'Source Map', Icon: FileCode2, color: 'border-sev-high/30 bg-sev-high/10 text-sev-high' },
  jwt:       { label: 'JWT Token',  Icon: Hash,      color: 'border-orange-400/30 bg-orange-400/10 text-orange-400' },
  email:     { label: '邮箱地址',   Icon: Mail,      color: 'border-slate-400/30 bg-slate-700/40 text-slate-400' },
  url:       { label: '外部 URL',   Icon: Globe,     color: 'border-slate-500/30 bg-base-600/60 text-slate-400' },
}

const SEV_META: Record<Severity, { label: string; cls: string }> = {
  high:   { label: '高危', cls: 'border-sev-high/40 bg-sev-high/10 text-sev-high' },
  medium: { label: '中危', cls: 'border-amber-400/40 bg-amber-400/10 text-amber-400' },
  low:    { label: '低危', cls: 'border-blue-400/40 bg-blue-400/10 text-blue-400' },
  info:   { label: '信息', cls: 'border-slate-500/40 bg-base-600/60 text-slate-400' },
}

const ALL_CATS = Object.keys(CAT_META) as Category[]
type TabKey = 'all' | Category | 'byfile'

// 熵值颜色
function entropyColor(ent: number): string {
  if (ent >= 4.5) return 'text-sev-high'
  if (ent >= 3.5) return 'text-amber-400'
  if (ent >= 2.5) return 'text-slate-300'
  return 'text-slate-500'
}
function entropyLabel(ent: number): string {
  if (ent >= 4.5) return '极高熵'
  if (ent >= 3.5) return '高熵'
  if (ent >= 2.5) return '中熵'
  return '低熵'
}

// ── 主组件 ───────────────────────────────────────────────────────────
export default function JSExtractView() {
  const [targets, setTargets]    = useState('')
  const [maxDepth, setMaxDepth]  = useState(1)
  const [timeoutMs, setTo]       = useState(10000)
  const [cookie, setCookie]      = useState('')
  const [auth, setAuth]          = useState('')

  const [fullSite, setFullSite]     = useState(false)
  const [maxPages, setMaxPages]     = useState(200)
  const [running, setRunning]       = useState(false)
  const [progress, setProgress]     = useState<string | null>(null)
  const [dlRunning, setDlRunning]   = useState(false)
  const [dlProgress, setDlProgress] = useState<string | null>(null)
  const [err, setErr]              = useState<string | null>(null)
  const [findings, setFindings]    = useState<JSFinding[]>([])
  const [tab, setTab]              = useState<TabKey>('all')
  const [expanded, setExpanded]    = useState<string | null>(null)
  const [filter, setFilter]        = useState('')
  const [taskReload, setTaskReload] = useState(0)
  const stoppedRef = useRef(false)

  // ── 操作 ──────────────────────────────────────────────────────────
  async function stopScan() {
    stoppedRef.current = true
    try { await enginePost(CAP, '/stop', {}) } catch { /* already idle */ }
  }

  async function startDownload() {
    const list = targets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (!list.length) { setErr('请填写至少一个目标 URL'); return }
    setErr(null); setDlRunning(true); setDlProgress('提交下载任务…')

    const params = { targets: list, maxDepth: fullSite ? 0 : maxDepth, timeoutMs, cookie, auth, fullSite, maxPages }
    let task: Awaited<ReturnType<typeof createTask>> | null = null
    try {
      task = await createTask({ capabilityKey: CAP, action: 'download', params })
      setTaskReload((n) => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'download', params })

      const finished = await pollTask(task.id, {
        intervalMs: 1500,
        timeoutMs: 20 * 60 * 1000,
        onProgress: (t) => setDlProgress(`${t.message ?? '打包中…'} (${t.progress}%)`),
      })

      if (finished.status === 'succeeded') {
        setDlProgress(null)
        await engineDownload(CAP, '/files/' + finished.id, 'js-files.zip')
      } else if (finished.status === 'failed') {
        setErr(finished.error ?? '下载失败')
      }
    } catch (e: unknown) {
      const msg = e instanceof ApiError ? e.message : (e instanceof Error ? e.message : String(e))
      if (task) await updateTask(task.id, { status: 'failed', error: msg }).catch(() => {})
      setErr(msg)
    } finally {
      setDlRunning(false); setDlProgress(null)
      setTaskReload((n) => n + 1)
    }
  }

  async function startScan() {
    const list = targets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (!list.length) { setErr('请填写至少一个目标 URL'); return }
    setErr(null); setFindings([]); setRunning(true); setProgress('提交任务…')
    stoppedRef.current = false

    const params = { targets: list, maxDepth, timeoutMs, cookie, auth }
    let task: Awaited<ReturnType<typeof createTask>> | null = null
    try {
      task = await createTask({ capabilityKey: CAP, action: 'scan', params })
      setTaskReload((n) => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'scan', params })

      const finished = await pollTask(task.id, {
        intervalMs: 1500,
        timeoutMs: 20 * 60 * 1000,
        onProgress: (t) => setProgress(`${t.message ?? '分析中…'} (${t.progress}%)`),
      })

      if (finished.status === 'succeeded') {
        const r = await engineGet<{ items: JSFinding[] }>(CAP, '/findings', { taskId: finished.id })
        setFindings(r.items ?? [])
        setProgress(null)
      } else if (finished.status === 'failed' && !stoppedRef.current) {
        setErr(finished.error ?? '扫描失败')
      }
    } catch (e: unknown) {
      if (!stoppedRef.current) {
        const msg = e instanceof ApiError ? e.message : (e instanceof Error ? e.message : String(e))
        if (task) await updateTask(task.id, { status: 'failed', error: msg }).catch(() => {})
        setErr(msg)
      }
    } finally {
      setRunning(false); setProgress(null); stoppedRef.current = false
      setTaskReload((n) => n + 1)
    }
  }

  // ── 导出 ──────────────────────────────────────────────────────────
  function exportCSV() {
    const rows = [
      ['严重', '置信', '类别', '标签', '熵值', '值', 'JS 文件', '来源页面', '发现时间'],
      ...findings.map((f) => [
        SEV_META[f.severity]?.label ?? f.severity,
        f.confident ? '★' : '',
        CAT_META[f.category]?.label ?? f.category,
        f.label, f.entropy > 0 ? f.entropy.toFixed(2) : '',
        f.value, f.jsUrl, f.pageUrl, f.foundAt,
      ]),
    ]
    const csv = rows.map((r) => r.map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n')
    dl(new Blob([csv], { type: 'text/csv;charset=utf-8' }), 'js-extract.csv')
  }

  function exportJSON() {
    dl(new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' }), 'js-extract.json')
  }

  function dl(blob: Blob, name: string) {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = name
    a.click()
  }

  // ── 统计 ──────────────────────────────────────────────────────────
  const counts = { all: findings.length, byfile: 0 } as Record<TabKey, number>
  for (const cat of ALL_CATS) counts[cat] = findings.filter((f) => f.category === cat).length

  const highCount      = findings.filter((f) => f.severity === 'high').length
  const confidentCount = findings.filter((f) => f.confident).length
  const highEntCount   = findings.filter((f) => f.entropy >= 3.5).length

  // 按 JS 文件分组
  const byFile = new Map<string, JSFinding[]>()
  for (const f of findings) {
    const g = byFile.get(f.jsUrl) ?? []
    g.push(f)
    byFile.set(f.jsUrl, g)
  }

  const fl = filter.toLowerCase()
  const visible = findings.filter((f) => {
    if (tab !== 'all' && tab !== 'byfile' && f.category !== tab) return false
    if (!fl) return true
    return (
      f.value.toLowerCase().includes(fl) ||
      f.label.toLowerCase().includes(fl) ||
      f.jsUrl.toLowerCase().includes(fl) ||
      f.pageUrl.toLowerCase().includes(fl)
    )
  })

  // ── UI ────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4 animate-fade-in">

      {/* 统计卡片 */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="总发现" value={findings.length || '—'} icon={<FileCode2 size={18} />} />
        <StatCard label="高危" value={highCount || '—'} tone="critical" icon={<ShieldAlert size={18} />} />
        <StatCard label="高置信匹配" value={confidentCount || '—'} tone="high" icon={<BadgeCheck size={18} />} />
        <StatCard label="高熵密值" value={highEntCount || '—'} tone="critical" icon={<Flame size={18} />} />
      </div>

      {/* 配置面板 */}
      <Panel title="发起 JS 信息提取" icon={<FileCode2 size={16} />}>
        <div className="space-y-3">
          <textarea
            value={targets} onChange={(e) => setTargets(e.target.value)} disabled={running}
            rows={3} placeholder={'https://target.com\nhttps://app.example.com/login'}
            className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-sm text-slate-200 outline-none focus:border-cyber"
          />
          <div className="flex flex-wrap gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">
              爬取深度
              <input type="number" min={0} max={3} value={maxDepth}
                onChange={(e) => setMaxDepth(+e.target.value)} disabled={running || dlRunning || fullSite}
                className="w-16 rounded border border-line bg-base-700/60 px-2 py-1 font-mono disabled:opacity-40" />
              <span className="text-xs text-slate-500">（0=当前页，1=跟进一层，最深3）</span>
            </label>
            <label className="flex items-center gap-2">
              超时 ms
              <input type="number" min={1000} max={60000} value={timeoutMs}
                onChange={(e) => setTo(+e.target.value)} disabled={running || dlRunning}
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
          </div>
          {/* 全站下载模式 */}
          <div className="flex flex-wrap items-center gap-4 rounded-lg border border-amber-400/20 bg-amber-400/5 px-3 py-2 text-sm text-slate-300">
            <label className="flex cursor-pointer items-center gap-2 select-none">
              <input type="checkbox" checked={fullSite}
                onChange={(e) => setFullSite(e.target.checked)} disabled={running || dlRunning}
                className="accent-amber-400" />
              <span className="text-amber-400 font-medium">全站模式</span>
              <span className="text-xs text-slate-500">（下载时递归爬取整个域名/IP 的所有页面，忽略爬取深度）</span>
            </label>
            {fullSite && (
              <label className="flex items-center gap-2">
                最大页数
                <input type="number" min={10} max={2000} value={maxPages}
                  onChange={(e) => setMaxPages(+e.target.value)} disabled={running || dlRunning}
                  className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
                <span className="text-xs text-slate-500">页（上限 2000）</span>
              </label>
            )}
          </div>
          <div className="flex flex-wrap gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">Cookie
              <input value={cookie} onChange={(e) => setCookie(e.target.value)} disabled={running}
                placeholder="PHPSESSID=abc; token=xyz"
                className="w-64 rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs" />
            </label>
            <label className="flex items-center gap-2">Auth
              <input value={auth} onChange={(e) => setAuth(e.target.value)} disabled={running}
                placeholder="Bearer eyJhbGci..."
                className="w-64 rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs" />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <button onClick={stopScan} className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={14} /> 停止
              </button>
            ) : (
              <button onClick={startScan} disabled={dlRunning}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber disabled:opacity-40">
                <Play size={14} /> 开始提取
              </button>
            )}
            <button onClick={startDownload} disabled={running || dlRunning}
              className="chip border border-amber-400/40 bg-amber-400/10 text-amber-400 disabled:opacity-40">
              {dlRunning
                ? <><span className="animate-spin inline-block">↻</span> 打包中…</>
                : <><Download size={14} /> 下载 JS 文件</>
              }
            </button>
            <button onClick={() => { setFindings([]); setErr(null) }} disabled={running}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <RefreshCw size={14} /> 清空
            </button>
            {findings.length > 0 && (
              <div className="ml-auto flex gap-1">
                <button onClick={exportCSV} className="chip border border-line bg-base-600/60 text-slate-400">
                  <Download size={14} /> CSV
                </button>
                <button onClick={exportJSON} className="chip border border-line bg-base-600/60 text-slate-400">
                  <Download size={14} /> JSON
                </button>
              </div>
            )}
          </div>
          {progress && (
            <div className="flex items-center gap-2 text-sm text-cyber">
              <span className="animate-pulse">●</span> {progress}
            </div>
          )}
          {dlProgress && (
            <div className="flex items-center gap-2 text-sm text-amber-400">
              <span className="animate-pulse">●</span> {dlProgress}
            </div>
          )}
          {err && <div className="text-sm text-sev-high">{err}</div>}
        </div>
      </Panel>

      {/* 结果面板 */}
      {findings.length > 0 && (
        <Panel title={`发现清单（${visible.length} / ${findings.length}）`}
          icon={<ShieldAlert size={16} />} bodyClass="p-0"
          action={
            <input value={filter} onChange={(e) => setFilter(e.target.value)}
              placeholder="搜索值/标签/JS路径…"
              className="rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-300 outline-none focus:border-cyber"
            />
          }
        >
          {/* Tab 栏 */}
          <div className="flex overflow-x-auto border-b border-line px-3">
            {(['all', ...ALL_CATS, 'byfile'] as TabKey[]).map((k) => {
              const cnt = k === 'byfile' ? byFile.size : (counts[k] ?? 0)
              if (k !== 'all' && k !== 'byfile' && cnt === 0) return null
              const meta = k === 'all' ? null : k === 'byfile' ? null : CAT_META[k as Category]
              const Icon = k === 'byfile' ? Layers : meta ? meta.Icon : FileCode2
              const tabLabel = k === 'all' ? '全部' : k === 'byfile' ? '按文件' : meta?.label
              return (
                <button key={k} onClick={() => setTab(k)}
                  className={`flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-xs transition-colors ${
                    tab === k ? 'border-cyber text-cyber' : 'border-transparent text-slate-500 hover:text-slate-300'
                  }`}>
                  <Icon size={11} />
                  <span>{tabLabel}</span>
                  <span className={`rounded px-1 font-mono text-[10px] ${tab === k ? 'bg-cyber/20 text-cyber' : 'bg-base-600/60 text-slate-500'}`}>
                    {cnt}
                  </span>
                </button>
              )
            })}
          </div>

          {/* 按文件分组视图 */}
          {tab === 'byfile' ? (
            <div className="divide-y divide-line">
              {byFile.size === 0 && <div className="p-6 text-center text-sm text-slate-500">无数据</div>}
              {[...byFile.entries()].map(([jsUrl, flist]) => {
                const highCnt = flist.filter((f) => f.severity === 'high').length
                const isOpen = expanded === jsUrl
                return (
                  <div key={jsUrl}>
                    <button onClick={() => setExpanded(isOpen ? null : jsUrl)}
                      className="flex w-full items-center gap-2 px-4 py-2.5 hover:bg-base-600/30">
                      {isOpen ? <ChevronDown size={13} className="shrink-0 text-slate-500" /> : <ChevronRight size={13} className="shrink-0 text-slate-500" />}
                      <FileCode2 size={13} className="shrink-0 text-cyber" />
                      <span className="flex-1 truncate font-mono text-xs text-slate-300">{jsUrl}</span>
                      {highCnt > 0 && (
                        <span className="chip border border-sev-high/40 bg-sev-high/10 text-[10px] text-sev-high">{highCnt} 高危</span>
                      )}
                      <span className="chip border border-line bg-base-600/60 text-[10px] text-slate-400">{flist.length} 条</span>
                    </button>
                    {isOpen && (
                      <div className="divide-y divide-line/40 bg-base-800/40 pl-6">
                        {flist.map((f) => <FindingRow key={f.id} f={f} />)}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            /* 分类平铺视图 */
            <div className="divide-y divide-line">
              {visible.length === 0 && <div className="p-6 text-center text-sm text-slate-500">当前筛选无结果</div>}
              {visible.map((f) => <FindingRow key={f.id} f={f} />)}
            </div>
          )}
        </Panel>
      )}

      {/* 类别快速切换卡片 */}
      {findings.length > 0 && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {ALL_CATS.filter((c) => counts[c] > 0).map((cat) => {
            const cm = CAT_META[cat]
            const Icon = cm.Icon
            return (
              <button key={cat} onClick={() => setTab(cat)}
                className={`flex items-center gap-2 rounded-lg border p-3 text-left transition hover:opacity-90 ${
                  tab === cat ? 'border-cyber/50 bg-cyber/10' : 'border-line bg-base-700/40'
                }`}>
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${cm.color}`}>
                  <Icon size={14} />
                </span>
                <div>
                  <div className="text-xs text-slate-400">{cm.label}</div>
                  <div className="font-mono text-sm text-slate-200">{counts[cat]}</div>
                </div>
              </button>
            )
          })}
        </div>
      )}

      {/* 历史任务 */}
      <Panel title="历史任务" icon={<Clock size={16} />} bodyClass="p-3">
        <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload}
          emptyHint="暂无任务记录，发起一次提取后将登记到此。" />
      </Panel>
    </div>
  )
}

// ── FindingRow 子组件 ────────────────────────────────────────────────
function FindingRow({ f }: { f: JSFinding }) {
  const [open, setOpen] = useState(false)
  const catM = CAT_META[f.category]
  const sevM = SEV_META[f.severity]
  const CatIcon = catM?.Icon ?? Globe

  return (
    <div>
      <button onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-4 py-2.5 text-left hover:bg-base-600/30">
        {open ? <ChevronDown size={13} className="shrink-0 text-slate-500" />
               : <ChevronRight size={13} className="shrink-0 text-slate-500" />}

        {/* 严重程度 */}
        <span className={`chip shrink-0 border text-[10px] font-semibold ${sevM.cls}`}>
          {sevM.label}
        </span>

        {/* 高置信标记 */}
        {f.confident && (
          <BadgeCheck size={12} className="shrink-0 text-emerald-400" aria-label="服务专属高精度格式" />
        )}

        {/* 类别 */}
        <span className={`chip shrink-0 flex items-center gap-1 border text-[10px] ${catM?.color ?? ''}`}>
          <CatIcon size={9} />
          {catM?.label ?? f.category}
        </span>

        {/* 标签 */}
        <span className="shrink-0 text-xs text-slate-400">{f.label}</span>

        {/* 熵值（仅密钥类）*/}
        {f.category === 'secret' && f.entropy > 0 && (
          <span className={`shrink-0 font-mono text-[10px] ${entropyColor(f.entropy)}`}
            title={entropyLabel(f.entropy)}>
            ↯{f.entropy.toFixed(1)}
          </span>
        )}

        {/* 值 */}
        <span className="ml-1 flex-1 truncate font-mono text-xs text-slate-200">{f.value}</span>

        {/* JS 文件路径（小字尾部） */}
        <span className="ml-auto shrink-0 max-w-[200px] truncate font-mono text-[10px] text-slate-600"
          title={f.jsUrl}>
          {f.jsUrl.replace(/^https?:\/\/[^/]+/, '')}
        </span>
      </button>

      {open && (
        <div className="space-y-2 bg-base-800/60 px-10 pb-3 pt-2 text-xs">
          {/* 完整值 */}
          <div>
            <span className="text-slate-500">提取值：</span>
            <code className="ml-1 break-all rounded bg-base-900/60 px-1.5 py-0.5 font-mono text-cyber">
              {f.value}
            </code>
          </div>

          {/* 熵值条（密钥类） */}
          {f.category === 'secret' && f.entropy > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Shannon 熵：</span>
              <div className="flex-1 max-w-48 h-1.5 rounded bg-base-700">
                <div className={`h-full rounded transition-all ${
                  f.entropy >= 4.5 ? 'bg-sev-high' : f.entropy >= 3.5 ? 'bg-amber-400' : 'bg-slate-500'
                }`} style={{ width: `${Math.min(100, (f.entropy / 6) * 100)}%` }} />
              </div>
              <span className={`font-mono text-[11px] ${entropyColor(f.entropy)}`}>
                {f.entropy.toFixed(2)} — {entropyLabel(f.entropy)}
              </span>
            </div>
          )}

          {/* 上下文代码 */}
          {f.ctx && (
            <div>
              <span className="text-slate-500">代码上下文：</span>
              <pre className="mt-1 overflow-x-auto rounded border border-line bg-base-900/80 p-2 font-mono text-[11px] text-slate-300 leading-relaxed">
                {f.ctx}
              </pre>
            </div>
          )}

          {/* 来源信息 */}
          <div className="flex flex-wrap gap-4 text-slate-500">
            <span>
              JS 文件：
              <a href={f.jsUrl} target="_blank" rel="noreferrer"
                className="ml-1 font-mono text-cyber hover:underline inline-flex items-center gap-0.5">
                {f.jsUrl.length > 80 ? f.jsUrl.slice(0, 80) + '…' : f.jsUrl}
                <ExternalLink size={10} />
              </a>
            </span>
            {f.pageUrl && (
              <span>
                来源页：
                <a href={f.pageUrl} target="_blank" rel="noreferrer"
                  className="ml-1 font-mono text-slate-400 hover:underline inline-flex items-center gap-0.5">
                  {f.pageUrl.length > 60 ? f.pageUrl.slice(0, 60) + '…' : f.pageUrl}
                  <ExternalLink size={10} />
                </a>
              </span>
            )}
            <span>发现于 {f.foundAt}</span>
          </div>
        </div>
      )}
    </div>
  )
}
