import { useState, useEffect, useRef, useCallback, Fragment, KeyboardEvent } from 'react'
import {
  ScanSearch, AlertTriangle, ShieldAlert, Info, Play, Square,
  Download, RefreshCw, Trash2, ChevronDown, ChevronUp, X, FolderOpen, ChevronRight,
  FlaskConical, CheckCircle, History, Clock, Target, Bookmark, Shield,
  Eye, EyeOff, AlertCircle, MessageSquare, Loader2, ListOrdered,
  ShieldCheck, ShieldX, Ban, Globe, Copy, RotateCcw, Inbox,
  Network, Server, Layers, KeyRound, FileText,
} from 'lucide-react'
import { engineGet, enginePost, engineRequest, engineDownload, engineSSE } from '@/lib/engine'
import type { SSEEvent } from '@/lib/engine'

const CAP = 'vuln-scan'
const POLL_MS = 5000 // SSE 已提供实时推送，轮询仅作降级兜底

// ──────────── 类型 ────────────
type ScanMode = 'full' | 'fingerprint'
interface ScanProgress { scanned: number; total: number; percent: number; rps: number; eta?: string; phase?: string }
interface ScanStatus {
  running: boolean; taskId: string; taskName: string; targets: string[]
  templates: string; severity: string; total: number; capped?: boolean
  scanMode?: ScanMode; detectedTechs?: string[]
  startedAt?: string; stoppedAt?: string; error?: string
  progress?: ScanProgress; queueLen: number
}
interface VulnResult {
  id: string; templateId: string; name: string; severity: string; tags: string[]
  host: string; matchedAt: string; curlCmd: string; request: string
  response: string; ip: string; foundAt: string; taskId: string
  falsePositive?: boolean; analystNote?: string; status?: string
  duplicateOf?: string
}
interface ResultsResp {
  results: VulnResult[]; total: number; stats: Record<string, number>
  page: number; pageSize: number; totalPages: number
}
interface TemplateTreeResp {
  sources: Record<string, Record<string, string[]>>; roots: Record<string, string>
  counts?: Record<string, Record<string, number>>
}
interface Task {
  id: string; name: string; targets: string[]; targetCount: number
  templates: string; severity: string; total: number; capped?: boolean
  error?: string; startedAt: string; stoppedAt?: string; running: boolean; proxy?: string
}
interface TargetList { id: string; name: string; targets: string[]; count: number; createdAt: string; updatedAt: string }
interface NormStats { inputTokens: number; output: number; deduped: number; skipped: number; protoAdded: number }
interface QueueItem {
  id: string; name: string; targetCount: number; status: string
  createdAt: string; startedAt?: string; finishedAt?: string; taskId?: string; error?: string
}
interface ScopeConfig { cidrs: string[]; domains: string[]; mode: string }
interface Exclusion { id: string; pattern: string; note?: string; createdAt: string }
interface FilterStats { allowed: string[]; excluded: number; outOfScope: number; warned: number }

const RESULT_STATUS: Record<string, { label: string; cls: string }> = {
  '':         { label: '待确认', cls: 'text-slate-500 border-slate-500/30 bg-slate-500/5' },
  pending:    { label: '待确认', cls: 'text-slate-500 border-slate-500/30 bg-slate-500/5' },
  confirmed:  { label: '已确认', cls: 'text-emerald-400 border-emerald-400/30 bg-emerald-400/5' },
  fp:         { label: '假阳性', cls: 'text-red-400 border-red-400/30 bg-red-400/5' },
  follow_up:  { label: '待跟进', cls: 'text-yellow-400 border-yellow-400/30 bg-yellow-400/5' },
}
const QUEUE_STATUS: Record<string, string> = {
  pending: 'text-yellow-400', running: 'text-cyber animate-pulse',
  done: 'text-emerald-400', cancelled: 'text-slate-500',
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000) return '刚刚'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)} 分钟前`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)} 小时前`
  return `${Math.floor(diff / 86400_000)} 天前`
}
function fmtDuration(start: string, end?: string): string {
  const ms = (end ? new Date(end) : new Date()).getTime() - new Date(start).getTime()
  if (ms < 0) return ''
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m${s % 60}s`
}
function estimateTokens(raw: string): number {
  if (!raw.trim()) return 0
  return raw.split(/[\n,;\t ]+/).filter(t => t.trim() && !t.startsWith('#')).length
}

const SEV_CONFIG: Record<string, { label: string; cls: string; dot: string }> = {
  critical: { label: '严重', cls: 'text-red-400 bg-red-400/10 border-red-400/30', dot: 'bg-red-400' },
  high:     { label: '高危', cls: 'text-orange-400 bg-orange-400/10 border-orange-400/30', dot: 'bg-orange-400' },
  medium:   { label: '中危', cls: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30', dot: 'bg-yellow-400' },
  low:      { label: '低危', cls: 'text-blue-400 bg-blue-400/10 border-blue-400/30', dot: 'bg-blue-400' },
  info:     { label: '信息', cls: 'text-slate-400 bg-slate-400/10 border-slate-400/30', dot: 'bg-slate-400' },
}
function SevBadge({ sev }: { sev: string }) {
  const cfg = SEV_CONFIG[sev.toLowerCase()] ?? SEV_CONFIG.info
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold ${cfg.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

// ── 模板树选择器 ──────────────────────────────────────────────────────────────
function TemplateTreePicker({
  tree, selected, onSelect,
}: { tree: TemplateTreeResp | null; selected: Set<string>; onSelect: (k: string) => void }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  if (!tree || Object.keys(tree.sources).length === 0)
    return <div className="text-xs text-slate-500 py-2">模板目录加载中…</div>
  const toggle = (k: string) =>
    setExpanded(p => { const s = new Set(p); s.has(k) ? s.delete(k) : s.add(k); return s })

  // 按来源分组显示：自定义库 → 信创库 → 官方库
  const SOURCE_ORDER: Record<string, number> = { '自定义': 0, '信创': 1, '官方': 2 }
  const SOURCE_LABEL_CLS: Record<string, string> = {
    '自定义': 'text-purple-400/80',
    '信创':   'text-amber-400',
    '官方':   'text-cyan-500/60',
  }
  const grouped = new Map<string, Array<{ top: string; subsArr: string[]; fileCount: number }>>()
  for (const [src, tops] of Object.entries(tree.sources)) {
    const cats = Object.entries(tops).map(([top, subs]) => ({
      top,
      subsArr: (subs as string[]) ?? [],
      fileCount: tree.counts?.[src]?.[top] ?? 0,
    }))
    cats.sort((a, b) => a.top.localeCompare(b.top, 'zh-Hans'))
    grouped.set(src, cats)
  }
  const sortedSrcs = [...grouped.keys()].sort(
    (a, b) => (SOURCE_ORDER[a] ?? 99) - (SOURCE_ORDER[b] ?? 99),
  )

  return (
    <div className="max-h-64 overflow-y-auto pr-1 space-y-2">
      {sortedSrcs.map(src => {
        const cats = grouped.get(src)!
        const totalCount = cats.reduce((s, c) => s + c.fileCount, 0)
        return (
          <div key={src}>
            <div className={`flex items-center gap-1.5 px-1 pb-0.5 mb-0.5 border-b border-base-600/50 ${SOURCE_LABEL_CLS[src] ?? 'text-slate-500'}`}>
              <span className="text-[10px] font-semibold tracking-wide">{src}库</span>
              <span className="text-[9px] text-slate-600 font-normal ml-1">({totalCount.toLocaleString()} 个模板)</span>
            </div>
            <div className="space-y-0.5">
              {cats.map(({ top, subsArr, fileCount }) => {
                const tk = `${src}:${top}`
                const displayCount = fileCount > 0 ? fileCount : subsArr.length
                return (
                  <div key={tk}>
                    <div className="flex items-center gap-1">
                      <button onClick={() => toggle(tk)} className="text-slate-500 hover:text-slate-300 p-0.5">
                        {subsArr.length > 0 ? (expanded.has(tk) ? <ChevronDown size={10} /> : <ChevronRight size={10} />) : <span className="w-3" />}
                      </button>
                      <button onClick={() => onSelect(tk)}
                        className={`flex-1 text-left text-xs px-1.5 py-0.5 rounded truncate transition ${selected.has(tk) ? 'bg-cyber/15 text-cyber' : 'text-slate-300 hover:bg-base-600/60'}`}>
                        {top}
                        <span className="ml-1 text-slate-600 text-[10px]">({displayCount.toLocaleString()})</span>
                      </button>
                    </div>
                    {expanded.has(tk) && subsArr.length > 0 && (
                      <div className="ml-5 mt-0.5 space-y-0.5">
                        {subsArr.map(sub => {
                          const sk = `${src}:${top}/${sub}`
                          const subCount = tree.counts?.[src]?.[`${top}/${sub}`] ?? 0
                          return (
                            <button key={sub} onClick={() => onSelect(sk)}
                              className={`w-full text-left text-[10px] px-2 py-0.5 rounded truncate transition ${selected.has(sk) ? 'bg-cyber/10 text-cyber' : 'text-slate-400 hover:bg-base-600/40'}`}>
                              {sub}{subCount > 0 && <span className="ml-1 text-slate-600">({subCount.toLocaleString()})</span>}
                            </button>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── 审阅模式覆盖层 ────────────────────────────────────────────────────────────
function ReviewOverlay({
  results, onClose, onUpdate,
}: {
  results: VulnResult[]
  onClose: () => void
  onUpdate: (id: string, patch: { falsePositive?: boolean; status?: string; analystNote?: string }) => Promise<void>
}) {
  const [idx, setIdx] = useState(0)
  const [note, setNote] = useState('')
  const [saved, setSaved] = useState(false)
  const noteRef = useRef<HTMLTextAreaElement>(null)

  const cur = results[idx]

  useEffect(() => {
    setNote(cur?.analystNote ?? '')
    setSaved(false)
  }, [idx, cur?.analystNote])

  const next = () => setIdx(i => Math.min(i + 1, results.length - 1))
  const prev = () => setIdx(i => Math.max(i - 1, 0))

  async function mark(status: string) {
    if (!cur) return
    await onUpdate(cur.id, { status, falsePositive: status === 'fp' })
  }
  async function saveNote() {
    if (!cur) return
    await onUpdate(cur.id, { analystNote: note })
    setSaved(true)
    setTimeout(() => setSaved(false), 1500)
  }

  function handleKey(e: KeyboardEvent<HTMLDivElement>) {
    if (e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLInputElement) return
    switch (e.key) {
      case 'j': case 'ArrowRight': next(); break
      case 'k': case 'ArrowLeft': prev(); break
      case 'c': mark('confirmed'); break
      case 'f': mark('fp'); break
      case 'u': mark('follow_up'); break
      case 'p': mark('pending'); break
      case 'Escape': onClose(); break
      case 'n': noteRef.current?.focus(); break
    }
  }

  if (!cur) return null

  const statusCfg = RESULT_STATUS[cur.falsePositive ? 'fp' : (cur.status ?? 'pending')]

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
      onKeyDown={handleKey}
      tabIndex={0}
      style={{ outline: 'none' }}
      autoFocus
    >
      <div className="w-full max-w-2xl rounded-xl border border-line bg-base-800 shadow-2xl flex flex-col max-h-[90vh]">
        {/* 头部 */}
        <div className="flex items-center gap-3 border-b border-line px-5 py-3">
          <ShieldCheck size={16} className="text-cyber" />
          <span className="text-sm font-semibold text-slate-200">批量审阅模式</span>
          <span className="text-xs text-slate-500 ml-1">{idx + 1} / {results.length}</span>
          <div className="ml-auto flex items-center gap-2">
            <div className="w-32 h-1 rounded-full bg-base-700 overflow-hidden">
              <div className="h-full bg-cyber rounded-full transition-all" style={{ width: `${((idx + 1) / results.length) * 100}%` }} />
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-slate-200 p-1"><X size={16} /></button>
          </div>
        </div>

        {/* 当前结果 */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          <div className="flex items-start gap-3">
            <SevBadge sev={cur.severity} />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold text-slate-100">{cur.name}</div>
              <div className="text-xs text-slate-500 font-mono">{cur.templateId}</div>
            </div>
            <span className={`text-[10px] border rounded px-1.5 py-0.5 ${statusCfg.cls}`}>{statusCfg.label}</span>
          </div>
          <div className="rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-xs text-cyber break-all">
            {cur.matchedAt || cur.host}
          </div>
          {cur.ip && <div className="text-[10px] text-slate-500">IP: {cur.ip}</div>}
          {cur.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {cur.tags.map(t => <span key={t} className="rounded border border-line bg-base-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">#{t}</span>)}
            </div>
          )}
          {/* 备注 */}
          <div>
            <div className="text-[10px] text-slate-500 mb-1">分析师备注 <span className="text-slate-700">（按 n 聚焦）</span></div>
            <div className="flex gap-2">
              <textarea
                ref={noteRef}
                value={note}
                onChange={e => setNote(e.target.value)}
                rows={2}
                placeholder="记录分析结论…"
                className="flex-1 resize-none rounded border border-line bg-base-700/60 p-2 text-[10px] text-slate-200 outline-none focus:border-cyber placeholder:text-slate-700"
              />
              <button onClick={saveNote}
                className={`px-2 rounded border text-[10px] transition ${saved ? 'border-emerald-400/40 text-emerald-400' : 'border-line text-slate-400 hover:border-cyber hover:text-cyber'}`}>
                {saved ? '✓ 已保存' : '保存'}
              </button>
            </div>
          </div>
        </div>

        {/* 操作区 */}
        <div className="border-t border-line p-4 space-y-3">
          <div className="grid grid-cols-4 gap-2">
            {[
              { s: 'confirmed', label: '已确认', key: 'C', cls: 'border-emerald-400/40 bg-emerald-400/10 text-emerald-400 hover:bg-emerald-400/20' },
              { s: 'follow_up', label: '待跟进', key: 'U', cls: 'border-yellow-400/40 bg-yellow-400/10 text-yellow-400 hover:bg-yellow-400/20' },
              { s: 'fp',        label: '假阳性', key: 'F', cls: 'border-red-400/40 bg-red-400/10 text-red-400 hover:bg-red-400/20' },
              { s: 'pending',   label: '待确认', key: 'P', cls: 'border-line bg-base-600/60 text-slate-400 hover:bg-base-500/60' },
            ].map(({ s, label, key, cls }) => (
              <button key={s} onClick={() => mark(s)}
                className={`rounded border px-2 py-1.5 text-xs font-medium transition flex flex-col items-center gap-0.5 ${cls} ${(cur.falsePositive ? 'fp' : cur.status) === s ? 'ring-1 ring-offset-1 ring-offset-base-800 ring-current' : ''}`}>
                <span>{label}</span>
                <span className="text-[9px] opacity-50">[{key}]</span>
              </button>
            ))}
          </div>
          <div className="flex items-center justify-between">
            <button onClick={prev} disabled={idx === 0}
              className="chip border border-line bg-base-600/60 text-slate-300 disabled:opacity-30 text-xs">
              ← 上一条 [K]
            </button>
            <div className="text-[10px] text-slate-600 text-center">
              J/→ 下一 · K/← 上一 · ESC 退出 · N 备注
            </div>
            <button onClick={next} disabled={idx >= results.length - 1}
              className="chip border border-line bg-base-600/60 text-slate-300 disabled:opacity-30 text-xs">
              下一条 [J] →
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── 主组件 ────────────────────────────────────────────────────────────────────
export default function VulnScanView() {
  // 扫描配置
  const [targets, setTargets] = useState('')
  const [tokenCount, setTokenCount] = useState(0)
  const [selectedSevs, setSelectedSevs] = useState<Set<string>>(new Set(['critical', 'high', 'medium']))
  const [selectedTemplates, setSelectedTemplates] = useState<Set<string>>(new Set())
  const [rateLimit, setRateLimit] = useState(150)
  const [timeoutSec, setTimeoutSec] = useState(10)
  const [insecure, setInsecure] = useState(false)
  const [proxy, setProxy] = useState('')
  const [headers, setHeaders] = useState('')  // 自定义请求头，每行一条 "Key: Value"
  const [scanMode, setScanMode] = useState<ScanMode>('full')
  const [showAdvanced, setShowAdvanced] = useState(false)

  // 数据状态
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [results, setResults] = useState<VulnResult[]>([])
  const [stats, setStats] = useState<Record<string, number>>({})
  const [templateTree, setTemplateTree] = useState<TemplateTreeResp | null>(null)
  const [tasks, setTasks] = useState<Task[]>([])
  const [targetLists, setTargetLists] = useState<TargetList[]>([])
  const [queue, setQueue] = useState<QueueItem[]>([])
  const [scope, setScope] = useState<ScopeConfig>({ cidrs: [], domains: [], mode: 'disabled' })
  const [exclusions, setExclusions] = useState<Exclusion[]>([])
  const [lastNormStats, setLastNormStats] = useState<NormStats | null>(null)
  const [lastFilterStats, setLastFilterStats] = useState<FilterStats | null>(null)

  // UI 状态
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [selectedTask, setSelectedTask] = useState<Task | null>(null)
  const [showHistory, setShowHistory] = useState(true)
  const [showTargetLists, setShowTargetLists] = useState(false)
  const [showQueue, setShowQueue] = useState(false)
  const [showScope, setShowScope] = useState(false)
  const [showExclusions, setShowExclusions] = useState(false)
  const [newListName, setNewListName] = useState('')
  const [savingList, setSavingList] = useState(false)
  const [newScopeCidr, setNewScopeCidr] = useState('')
  const [newScopeDomain, setNewScopeDomain] = useState('')
  const [newExclPattern, setNewExclPattern] = useState('')
  const [newExclNote, setNewExclNote] = useState('')
  const [importingFrom, setImportingFrom] = useState<string | null>(null)

  // 结果面板
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [importMsg, setImportMsg] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showFP, setShowFP] = useState(false)
  const [showDup, setShowDup] = useState(false)
  const [sortBy, setSortBy] = useState<'time' | 'severity'>('time')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [totalCount, setTotalCount] = useState(0)
  const [reviewMode, setReviewMode] = useState(false)
  const [localNotes, setLocalNotes] = useState<Record<string, string>>({})

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const fetchStatusRef = useRef<() => Promise<ScanStatus | null>>(() => Promise.resolve(null))
  const fetchResultsRef = useRef<(pg?: number) => Promise<void>>(() => Promise.resolve())

  // token 估算防抖
  useEffect(() => {
    const t = setTimeout(() => setTokenCount(estimateTokens(targets)), 200)
    return () => clearTimeout(t)
  }, [targets])

  // 初始加载
  useEffect(() => {
    engineGet<TemplateTreeResp>(CAP, '/templates').then(setTemplateTree).catch(() => {})
  }, [])

  const fetchTargetLists = useCallback(async () => {
    try { const r = await engineGet<{ lists: TargetList[] }>(CAP, '/target-lists'); setTargetLists(r.lists ?? []) } catch {}
  }, [])
  const fetchTasks = useCallback(async () => {
    try { const r = await engineGet<{ tasks: Task[] }>(CAP, '/tasks'); setTasks(r.tasks ?? []) } catch {}
  }, [])
  const fetchQueue = useCallback(async () => {
    try { const r = await engineGet<{ queue: QueueItem[] }>(CAP, '/queue'); setQueue(r.queue ?? []) } catch {}
  }, [])
  const fetchScope = useCallback(async () => {
    try {
      const s = await engineGet<ScopeConfig>(CAP, '/scope')
      setScope({ cidrs: s.cidrs ?? [], domains: s.domains ?? [], mode: s.mode ?? 'disabled' })
    } catch {}
  }, [])
  const fetchExclusions = useCallback(async () => {
    try { const r = await engineGet<{ exclusions: Exclusion[] }>(CAP, '/exclusions'); setExclusions(r.exclusions ?? []) } catch {}
  }, [])

  useEffect(() => {
    fetchTargetLists(); fetchTasks(); fetchQueue(); fetchScope(); fetchExclusions()
  }, [fetchTargetLists, fetchTasks, fetchQueue, fetchScope, fetchExclusions])

  // 轮询
  const fetchStatus = useCallback(async () => {
    try { const s = await engineGet<ScanStatus>(CAP, '/status'); setStatus(s); return s }
    catch { return null }
  }, [])

  const fetchResults = useCallback(async (pg = page) => {
    try {
      const q: Record<string, string> = { page: String(pg), pageSize: '100', sort: sortBy }
      if (sevFilter) q.severity = sevFilter
      if (search) q.search = search
      if (selectedTask) q.taskId = selectedTask.id
      if (showFP) q.showFP = 'true'
      if (showDup) q.showDup = 'true'
      if (statusFilter) q.status = statusFilter
      const resp = await engineGet<ResultsResp>(CAP, '/results', q)
      setResults(resp.results ?? [])
      setStats(resp.stats ?? {})
      setTotalPages(resp.totalPages ?? 1)
      setTotalCount(resp.total ?? 0)
    } catch {}
  }, [sevFilter, search, sortBy, page, selectedTask, showFP, showDup, statusFilter])

  useEffect(() => { fetchStatus(); fetchResults(1); setPage(1) }, [fetchStatus, fetchResults])

  useEffect(() => {
    if (status?.running) {
      pollRef.current = setInterval(async () => {
        const s = await fetchStatus()
        await fetchResults()
        await fetchQueue()
        if (!s?.running) {
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
          fetchTasks()
        }
      }, POLL_MS)
    }
    return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null } }
  }, [status?.running, fetchStatus, fetchResults, fetchTasks, fetchQueue])

  // 保持 refs 与最新回调同步（供 SSE effect 使用，避免 stale closure）
  useEffect(() => { fetchStatusRef.current = fetchStatus }, [fetchStatus])
  useEffect(() => { fetchResultsRef.current = fetchResults }, [fetchResults])

  // SSE 实时推送：建立持久连接，随扫描状态变化实时更新 UI
  useEffect(() => {
    const ctrl = new AbortController()
    let retryTimer: ReturnType<typeof setTimeout> | null = null

    async function connect() {
      setSseConnected(false)
      try {
        let firstEvt = true
        for await (const evt of engineSSE(CAP, ctrl.signal)) {
          if (firstEvt) { setSseConnected(true); firstEvt = false }
          const e = evt as SSEEvent
          if (e.type === 'status') {
            setStatus(e.data as ScanStatus)
          } else if (e.type === 'progress') {
            setStatus(prev => prev ? { ...prev, progress: e.data as ScanProgress } : prev)
          } else if (e.type === 'phase') {
            // 指纹阶段切换：更新 progress.phase + detectedTechs
            const d = e.data as ScanStatus
            setStatus(prev => prev ? {
              ...prev,
              progress: d.progress ?? prev.progress,
              detectedTechs: d.detectedTechs ?? prev.detectedTechs,
              scanMode: d.scanMode ?? prev.scanMode,
            } : d)
          } else if (e.type === 'result') {
            // 新结果：触发一次结果列表刷新
            fetchResultsRef.current()
          } else if (e.type === 'start') {
            fetchStatusRef.current()
            fetchTasks()
          } else if (e.type === 'end') {
            fetchStatusRef.current()
            fetchResultsRef.current()
            fetchTasks()
          }
        }
      } catch { /* AbortError 正常退出 */ }
      setSseConnected(false)
      if (!ctrl.signal.aborted) {
        retryTimer = setTimeout(connect, 3000) // 断线3秒后重连
      }
    }

    connect()
    return () => {
      ctrl.abort()
      if (retryTimer) clearTimeout(retryTimer)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // 模板更新
  async function handleUpdateTemplates() {
    try {
      await enginePost(CAP, '/templates/update')
      alert('模板更新已在后台启动，完成后请刷新模板列表')
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : '更新失败')
    }
  }

  // 模板路径解析
  function resolveTemplatePaths(): string {
    if (!templateTree || selectedTemplates.size === 0) return ''
    return [...selectedTemplates].map(key => {
      const idx = key.indexOf(':')
      if (idx < 0) return key
      const src = key.slice(0, idx); const rel = key.slice(idx + 1)
      const root = templateTree.roots[src]
      return root ? `${root}/${rel}` : rel
    }).join(',')
  }

  // ── 扫描操作 ──
  async function handleStart() {
    if (!targets.trim()) { setErr('请填写至少一个目标'); return }
    setErr(null); setLoading(true); setLastNormStats(null); setLastFilterStats(null)
    try {
      const resp = await enginePost<{
        taskId: string; taskName: string; targets: number
        normStats: NormStats; filterStats: FilterStats
      }>(CAP, '/start', {
        targets: [targets],
        templates: resolveTemplatePaths(),
        severity: [...selectedSevs].join(','),
        rateLimit, timeout: timeoutSec, insecure, proxy,
        headers: headers.split('\n').map(h => h.trim()).filter(h => h.includes(':')),
        scanMode,
      })
      setLastNormStats(resp.normStats ?? null)
      setLastFilterStats(resp.filterStats ?? null)
      setSelectedTask(null)
      await fetchStatus(); await fetchTasks()
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '启动失败') }
    finally { setLoading(false) }
  }

  async function handleEnqueue() {
    if (!targets.trim()) { setErr('请填写至少一个目标'); return }
    setErr(null); setLoading(true)
    try {
      await enginePost(CAP, '/queue', {
        targets: [targets],
        templates: resolveTemplatePaths(),
        severity: [...selectedSevs].join(','),
        rateLimit, timeout: timeoutSec, insecure, proxy,
        headers: headers.split('\n').map(h => h.trim()).filter(h => h.includes(':')),
        scanMode,
      })
      await fetchQueue(); await fetchStatus()
      setShowQueue(true)
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '加入队列失败') }
    finally { setLoading(false) }
  }

  async function handleStop() {
    try { await enginePost(CAP, '/stop'); await fetchStatus() }
    catch (e: unknown) { setErr(e instanceof Error ? e.message : '停止失败') }
  }

  async function handleClear() {
    if (!window.confirm(`确认清空全部 ${totalCount} 条结果？`)) return
    try {
      await engineRequest(CAP, '/results', { method: 'DELETE' })
      setResults([]); setStats({}); setTotalCount(0); setPage(1); setTotalPages(1)
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '清空失败') }
  }

  async function handleDeleteOne(id: string) {
    try {
      await engineRequest(CAP, `/result?id=${id}`, { method: 'DELETE' })
      setResults(prev => prev.filter(r => r.id !== id)); setTotalCount(prev => prev - 1)
    } catch {}
  }

  async function handleUpdateResult(id: string, patch: { falsePositive?: boolean; analystNote?: string; status?: string }) {
    try {
      await engineRequest(CAP, `/result?id=${id}`, { method: 'PATCH', body: JSON.stringify(patch) })
      setResults(prev => prev.map(r => r.id === id ? { ...r, ...patch } : r))
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '更新失败') }
  }

  async function handleBatchUpdate(fp?: boolean, st?: string) {
    if (selectedIds.size === 0) return
    const ids = [...selectedIds]
    try {
      await enginePost(CAP, '/results/batch', { ids, falsePositive: fp, status: st })
      setResults(prev => prev.map(r => {
        if (!selectedIds.has(r.id)) return r
        const upd: Partial<VulnResult> = {}
        if (fp !== undefined) { upd.falsePositive = fp; upd.status = fp ? 'fp' : (r.status === 'fp' ? 'pending' : r.status) }
        if (st !== undefined) { upd.status = st; upd.falsePositive = st === 'fp' }
        return { ...r, ...upd }
      }))
      setSelectedIds(new Set())
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '批量更新失败') }
  }

  async function handleDeleteTask(id: string) {
    if (!window.confirm('确认删除该任务及其所有结果？')) return
    try {
      await engineRequest(CAP, `/task?id=${id}`, { method: 'DELETE' })
      if (selectedTask?.id === id) setSelectedTask(null)
      await fetchTasks(); await fetchResults(1)
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '删除失败') }
  }

  async function handleResume(taskId: string, mode: 'all' | 'unscanned' = 'all') {
    try {
      await enginePost(CAP, `/resume?taskId=${taskId}&mode=${mode}`, {})
      await fetchStatus(); await fetchTasks(); await fetchQueue()
      setShowQueue(true)
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '续扫失败') }
  }

  async function handleDownloadReport(taskId: string) {
    try {
      await engineDownload(CAP, '/report', `vuln-report-${taskId.slice(0, 8)}.html`, { taskId })
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '报告生成失败') }
  }

  // 目标列表
  async function handleSaveTargetList() {
    if (!targets.trim() || !newListName.trim()) return
    setSavingList(true)
    try { await enginePost(CAP, '/target-lists', { name: newListName.trim(), raw: targets }); setNewListName(''); await fetchTargetLists() }
    catch (e: unknown) { setErr(e instanceof Error ? e.message : '保存失败') }
    finally { setSavingList(false) }
  }

  // 从其他模块导入目标
  async function importFromModule(moduleId: string) {
    setImportingFrom(moduleId)
    try {
      type AnyResp = Record<string, unknown>
      const resp = await engineGet<AnyResp>(moduleId, '/results')
      const items: AnyResp[] = (resp.results as AnyResp[]) ?? (resp.entries as AnyResp[]) ?? (resp.assets as AnyResp[]) ?? []
      const collected: string[] = []
      for (const item of items) {
        // 尝试多种字段名
        const url = (item.url ?? item.target ?? item.host ?? item.asset ?? item.address ?? '') as string
        if (url) collected.push(url)
        // scan-port 特有：host + port
        else if (item.host && item.port) collected.push(`${item.host}:${item.port}`)
      }
      if (collected.length > 0) {
        setTargets(prev => (prev.trim() ? prev.trim() + '\n' : '') + collected.join('\n'))
        setImportMsg(`从 ${moduleId} 导入 ${collected.length} 个目标`)
      } else {
        setImportMsg(`${moduleId} 暂无可导入的目标`)
      }
      setTimeout(() => setImportMsg(null), 4000)
    } catch {
      setErr(`从 ${moduleId} 导入失败（该模块可能未启用）`)
    }
    setImportingFrom(null)
  }

  // 导出
  async function handleExport(fmt: 'csv' | 'json') {
    const p = new URLSearchParams({ format: fmt })
    if (sevFilter) p.set('severity', sevFilter)
    if (search) p.set('search', search)
    if (selectedTask) p.set('taskId', selectedTask.id)
    try { await engineDownload(CAP, `/export?${p}`, `vuln-scan.${fmt}`) }
    catch (e: unknown) { setErr(e instanceof Error ? e.message : '导出失败') }
  }

  async function handleImportToPoc() {
    const toImport = results.filter(r => selectedIds.has(r.id))
    if (!toImport.length) return
    try {
      await enginePost('vuln-poc', '/import', toImport.map(r => ({
        name: r.name, target: r.matchedAt || r.host, template: r.templateId,
        severity: r.severity, tags: r.tags, sourceScan: r.taskId, sourceHit: r.id,
      })))
      setImportMsg(`已导入 ${toImport.length} 条到 PoC 验证`)
      setSelectedIds(new Set()); setTimeout(() => setImportMsg(null), 4000)
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '导入失败') }
  }

  // Scope 操作
  async function handleScopeUpdate(updates: Partial<ScopeConfig>) {
    const newScope = { ...scope, ...updates }
    try {
      await engineRequest(CAP, '/scope', { method: 'PUT', body: JSON.stringify(newScope) })
      setScope(newScope)
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : 'Scope 更新失败') }
  }

  async function addScopeCidr() {
    if (!newScopeCidr.trim()) return
    await handleScopeUpdate({ cidrs: [...scope.cidrs, newScopeCidr.trim()] })
    setNewScopeCidr('')
  }
  async function removeScopeCidr(v: string) {
    await handleScopeUpdate({ cidrs: scope.cidrs.filter(c => c !== v) })
  }
  async function addScopeDomain() {
    if (!newScopeDomain.trim()) return
    await handleScopeUpdate({ domains: [...scope.domains, newScopeDomain.trim()] })
    setNewScopeDomain('')
  }
  async function removeScopeDomain(v: string) {
    await handleScopeUpdate({ domains: scope.domains.filter(d => d !== v) })
  }

  // 排除列表
  async function handleAddExclusion() {
    if (!newExclPattern.trim()) return
    try {
      await enginePost(CAP, '/exclusions', { pattern: newExclPattern.trim(), note: newExclNote.trim() })
      setNewExclPattern(''); setNewExclNote(''); await fetchExclusions()
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '添加失败') }
  }
  async function handleDeleteExclusion(id: string) {
    try { await engineRequest(CAP, `/exclusion?id=${id}`, { method: 'DELETE' }); await fetchExclusions() } catch {}
  }

  // 队列操作
  async function handleCancelQueue(id?: string) {
    try {
      await engineRequest(CAP, id ? `/queue?id=${id}` : '/queue', { method: 'DELETE' })
      await fetchQueue()
    } catch {}
  }

  function toggleSev(s: string) { setSelectedSevs(p => { const n = new Set(p); n.has(s) ? n.delete(s) : n.add(s); return n }) }
  function toggleTemplate(k: string) { setSelectedTemplates(p => { const n = new Set(p); n.has(k) ? n.delete(k) : n.add(k); return n }) }
  function toggleSelect(id: string) { setSelectedIds(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n }) }
  function toggleSelectAll() { setSelectedIds(p => p.size === results.length ? new Set() : new Set(results.map(r => r.id))) }

  const running = status?.running ?? false
  const progress = status?.progress
  const crit = stats.critical ?? 0; const high_ = stats.high ?? 0
  const med = stats.medium ?? 0; const low_ = (stats.low ?? 0) + (stats.info ?? 0)
  const fpCount = stats.fp ?? 0; const confirmedCount = stats.confirmed ?? 0
  const dupCount = stats.duplicate ?? 0
  const activeTaskId = running ? (status?.taskId ?? '') : ''
  const pendingQueueLen = queue.filter(qi => qi.status === 'pending').length

  return (
    <div className="space-y-4 animate-fade-in">

      {/* 审阅模式覆盖层 */}
      {reviewMode && results.length > 0 && (
        <ReviewOverlay
          results={results}
          onClose={() => setReviewMode(false)}
          onUpdate={handleUpdateResult}
        />
      )}

      {/* ── 统计卡片 ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          {
            label: selectedTask ? selectedTask.name.slice(0, 12) + '…' : '命中总数',
            val: totalCount,
            sub: fpCount > 0 || confirmedCount > 0 ? `已确认 ${confirmedCount} · FP ${fpCount}${dupCount > 0 ? ` · 重复 ${dupCount}` : ''}` : undefined,
            icon: <ScanSearch size={16} />,
          },
          { label: '严重/高危', val: crit + high_, icon: <AlertTriangle size={16} className="text-red-400" /> },
          { label: '中危', val: med, icon: <ShieldAlert size={16} className="text-yellow-400" /> },
          {
            label: '低危/信息',
            val: low_,
            sub: pendingQueueLen > 0 ? `队列等待 ${pendingQueueLen} 个` : undefined,
            icon: <Info size={16} className="text-slate-400" />,
          },
        ].map(({ label, val, sub, icon }) => (
          <div key={label} className="flex items-center gap-3 rounded-lg border border-line bg-base-700/50 px-4 py-3">
            <span className="text-cyber/70">{icon}</span>
            <div>
              <div className="text-lg font-bold text-slate-100">{val || '—'}</div>
              <div className="text-xs text-slate-500">{label}</div>
              {sub && <div className="text-[10px] text-slate-600">{sub}</div>}
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-12 gap-4">

        {/* ── 左：配置 ── */}
        <div className="col-span-12 lg:col-span-5 space-y-3">

          {/* 从模块导入 */}
          <div className="rounded-lg border border-line bg-base-800/60 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-medium text-slate-400">
              <Layers size={12} className="text-slate-500" /> 从其他模块导入目标
            </div>
            <div className="flex flex-wrap gap-2">
              {[
                { id: 'asset-collect', label: '资产发现', icon: <Globe size={11} /> },
                { id: 'scan-port', label: '端口扫描', icon: <Network size={11} /> },
              ].map(({ id, label, icon }) => (
                <button key={id} onClick={() => importFromModule(id)} disabled={importingFrom === id}
                  className="chip border border-line bg-base-700/40 text-slate-400 hover:border-cyber/40 hover:text-cyber text-[10px] disabled:opacity-50 transition">
                  {importingFrom === id ? <Loader2 size={10} className="animate-spin" /> : icon}
                  {label}
                </button>
              ))}
            </div>
            {importMsg && (
              <div className="mt-2 text-[10px] text-emerald-400 flex items-center gap-1">
                <CheckCircle size={10} /> {importMsg}
              </div>
            )}
          </div>

          {/* 目标输入 */}
          <div className="rounded-lg border border-line bg-base-800/60 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium text-slate-200">
              <Target size={14} className="text-cyber" /> 扫描目标
              {tokenCount > 0 && !running && (
                <span className="ml-auto text-[10px] text-slate-500">~{tokenCount} 条</span>
              )}
            </div>
            <textarea
              value={targets} onChange={e => setTargets(e.target.value)} disabled={running} rows={5}
              placeholder={'支持任意混合格式（换行/逗号/空格均可）：\n192.168.1.1\n192.168.1.1:8080\n192.168.1.0/24\nexample.com\nhttps://app.target.com:8443'}
              className="w-full resize-none rounded border border-line bg-base-700/60 p-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50"
            />
            {lastNormStats && (
              <div className="mt-2 flex flex-wrap gap-2 text-[10px]">
                <span className="text-cyber">✓ {lastNormStats.output} 个有效目标</span>
                {lastNormStats.deduped > 0 && <span className="text-slate-500">去重 {lastNormStats.deduped}</span>}
                {lastNormStats.protoAdded > 0 && <span className="text-slate-500">补全协议 {lastNormStats.protoAdded}</span>}
                {lastNormStats.skipped > 0 && <span className="text-yellow-500/70">跳过 {lastNormStats.skipped}</span>}
              </div>
            )}
            {lastFilterStats && (lastFilterStats.excluded > 0 || lastFilterStats.outOfScope > 0 || lastFilterStats.warned > 0) && (
              <div className="mt-1 flex flex-wrap gap-2 text-[10px]">
                {lastFilterStats.excluded > 0 && <span className="text-red-400">排除列表拦截 {lastFilterStats.excluded}</span>}
                {lastFilterStats.outOfScope > 0 && <span className="text-red-400">超范围阻断 {lastFilterStats.outOfScope}</span>}
                {lastFilterStats.warned > 0 && <span className="text-yellow-400">超范围警告 {lastFilterStats.warned}</span>}
              </div>
            )}
          </div>

          {/* 模板选择 */}
          <div className="rounded-lg border border-line bg-base-800/60 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium text-slate-200">
              <FolderOpen size={14} className="text-cyber" /> 模板选择
              {selectedTemplates.size > 0 && (
                <span className="text-[10px] text-cyber bg-cyber/10 border border-cyber/30 rounded px-1.5 py-0.5">已选 {selectedTemplates.size} 项</span>
              )}
              <button onClick={handleUpdateTemplates} disabled={running}
                title="后台运行 nuclei -update-templates 更新模板库"
                className="ml-auto text-[10px] text-slate-500 hover:text-cyber border border-line hover:border-cyber/40 rounded px-1.5 py-0.5 transition disabled:opacity-40">
                <RefreshCw size={9} className="inline mr-0.5" /> 更新模板库
              </button>
            </div>
            <TemplateTreePicker tree={templateTree} selected={selectedTemplates} onSelect={toggleTemplate} />
            {selectedTemplates.size > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {[...selectedTemplates].map(k => (
                  <span key={k} className="flex items-center gap-1 rounded border border-cyber/30 bg-cyber/5 px-1.5 py-0.5 text-[10px] text-cyber">
                    {k.split(':')[1]}
                    <button onClick={() => toggleTemplate(k)} className="hover:text-red-400"><X size={9} /></button>
                  </span>
                ))}
                <button onClick={() => setSelectedTemplates(new Set())} className="text-[10px] text-slate-500 hover:text-red-400 ml-1">全清</button>
              </div>
            )}
            <div className="mt-1 text-[10px] text-slate-600">{selectedTemplates.size === 0 ? '未选择 = 默认扫官方 http/ 全量' : ''}</div>
          </div>

          {/* 严重度 + 参数 */}
          <div className="rounded-lg border border-line bg-base-800/60 p-4 space-y-3">
            <div>
              <div className="mb-1.5 text-xs text-slate-400">严重度过滤</div>
              <div className="flex flex-wrap gap-1">
                {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                  <button key={s} onClick={() => toggleSev(s)} disabled={running}
                    className={`chip border text-[10px] transition disabled:opacity-50 ${selectedSevs.has(s) ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs text-slate-300">
              <label className="flex items-center justify-between">
                <span>速率(req/s)</span>
                <input type="number" min={10} max={1000} value={rateLimit}
                  onChange={e => setRateLimit(+e.target.value)} disabled={running}
                  className="w-20 rounded border border-line bg-base-700/60 px-2 py-0.5 font-mono text-right disabled:opacity-50" />
              </label>
              <label className="flex items-center justify-between">
                <span>超时(秒)</span>
                <input type="number" min={5} max={120} value={timeoutSec}
                  onChange={e => setTimeoutSec(+e.target.value)} disabled={running}
                  className="w-20 rounded border border-line bg-base-700/60 px-2 py-0.5 font-mono text-right disabled:opacity-50" />
              </label>
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
              <input type="checkbox" checked={insecure} onChange={e => setInsecure(e.target.checked)} disabled={running} className="accent-cyber" />
              <span>跳过 TLS 验证 (-insecure)</span>
            </label>
            {/* 高级配置 */}
            <button onClick={() => setShowAdvanced(v => !v)} className="text-[10px] text-slate-500 hover:text-slate-300 flex items-center gap-1">
              {showAdvanced ? <ChevronUp size={10} /> : <ChevronDown size={10} />} 高级配置
            </button>
            {showAdvanced && (
              <div className="space-y-2 pt-1">
                <label className="flex items-center justify-between text-xs text-slate-400">
                  <span className="flex items-center gap-1"><Server size={11} /> 代理</span>
                  <input value={proxy} onChange={e => setProxy(e.target.value)} disabled={running}
                    placeholder="socks5://127.0.0.1:1080"
                    className="w-44 rounded border border-line bg-base-700/60 px-2 py-0.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50 placeholder:text-slate-700" />
                </label>
                <div className="text-xs text-slate-400">
                  <div className="flex items-center gap-1 mb-1"><KeyRound size={11} /> 自定义请求头（每行 Key: Value）</div>
                  <textarea value={headers} onChange={e => setHeaders(e.target.value)} disabled={running}
                    placeholder={"Authorization: Bearer token\nX-Api-Key: secret"}
                    rows={3}
                    className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50 placeholder:text-slate-700 resize-none" />
                </div>
              </div>
            )}
          </div>

          {/* 扫描模式 */}
          {!running && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500 shrink-0">扫描模式</span>
              <div className="flex rounded-lg border border-line bg-base-800/60 p-0.5 gap-0.5">
                {([
                  { id: 'full',        label: '全量扫描',   desc: '跑所有选中模板' },
                  { id: 'fingerprint', label: '自动指纹',   desc: '先探指纹，按产品缩减模板' },
                ] as {id: ScanMode; label: string; desc: string}[]).map(m => (
                  <button key={m.id} onClick={() => setScanMode(m.id)} title={m.desc}
                    className={`rounded px-3 py-1 text-xs font-medium transition ${scanMode === m.id
                      ? m.id === 'fingerprint' ? 'bg-emerald-500/20 text-emerald-400 shadow-sm' : 'bg-base-700 text-cyber shadow-sm'
                      : 'text-slate-500 hover:text-slate-300'}`}>
                    {m.label}
                  </button>
                ))}
              </div>
              {scanMode === 'fingerprint' && (
                <span className="text-[10px] text-emerald-500/70">
                  自动探测目标技术栈 → 只跑匹配产品的 PoC（2916 种产品，3043 条规则）
                </span>
              )}
            </div>
          )}

          {/* 控制按钮 */}
          <div className="flex flex-wrap gap-2">
            {running ? (
              <button onClick={handleStop} className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={13} /> 停止扫描
              </button>
            ) : (
              <>
                <button onClick={handleStart} disabled={loading}
                  className="chip border border-cyber/40 bg-cyber/10 text-cyber disabled:opacity-50">
                  {loading ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />} 开始扫描
                </button>
                <button onClick={handleEnqueue} disabled={loading}
                  title="将任务加入队列（当前空闲时直接启动）"
                  className="chip border border-slate-500/40 bg-slate-500/10 text-slate-400 hover:border-cyber/40 hover:text-cyber disabled:opacity-50">
                  <ListOrdered size={13} /> 加入队列
                </button>
              </>
            )}
            <button onClick={() => { fetchStatus(); fetchResults() }}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <RefreshCw size={13} /> 刷新
            </button>
          </div>

          {/* 状态 + 进度条 */}
          {status && (
            <div className={`rounded-lg border p-3 text-xs space-y-2 ${running ? 'border-cyber/30 bg-cyber/5' : 'border-line bg-base-800/40'}`}>
              <div className="flex items-center gap-2">
                {running && <span className="h-2 w-2 rounded-full bg-cyber animate-pulse" />}
                <span className={running ? 'text-cyber' : 'text-slate-400'}>
                  {running
                    ? progress?.phase === 'fingerprint'
                      ? '指纹探测中… 识别目标技术栈'
                      : `扫描中… 已命中 ${status.total} 个漏洞`
                    : (status.error ? `已停止: ${status.error}` : '空闲')}
                </span>
                {running && status.scanMode === 'fingerprint' && (
                  <span className="text-[10px] rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5">
                    指纹模式
                  </span>
                )}
                <span className="ml-auto flex items-center gap-1">
                  {!running && pendingQueueLen > 0 && (
                    <span className="text-[10px] text-yellow-400">队列 {pendingQueueLen} 个待执行</span>
                  )}
                  <span title={sseConnected ? 'SSE 实时推送已连接' : 'SSE 未连接，使用轮询'}
                    className={`text-[9px] px-1 rounded ${sseConnected ? 'text-emerald-400 bg-emerald-400/10' : 'text-slate-600 bg-slate-700/30'}`}>
                    {sseConnected ? '● 实时' : '○ 轮询'}
                  </span>
                </span>
              </div>

              {/* 指纹检测到的产品 */}
              {status.detectedTechs && status.detectedTechs.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-0.5">
                  <span className="text-[10px] text-slate-500 shrink-0 mt-0.5">识别产品：</span>
                  {status.detectedTechs.slice(0, 12).map(t => (
                    <span key={t} className="inline-flex items-center rounded border border-emerald-500/30 bg-emerald-500/5 px-1.5 py-0.5 text-[10px] text-emerald-400">{t}</span>
                  ))}
                  {status.detectedTechs.length > 12 && (
                    <span className="text-[10px] text-slate-600">+{status.detectedTechs.length - 12}</span>
                  )}
                </div>
              )}

              {running && status.taskName && (
                <div className="text-slate-500 text-[10px]">
                  {status.taskName}
                  {status.startedAt && ` · ${fmtDuration(status.startedAt)}`}
                  {status.targets?.length ? ` · ${status.targets.length} 目标` : ''}
                  {proxy && ` · 代理 ${proxy}`}
                </div>
              )}

              {/* 进度条：指纹阶段用黄色，扫描阶段用 cyber 色 */}
              {running && progress && progress.phase === 'fingerprint' && (
                <div className="space-y-1 pt-1">
                  <div className="flex items-center gap-2 text-[10px] text-yellow-400">
                    <Loader2 size={10} className="animate-spin" />
                    <span>正在探测 {status.targets?.length ?? '?'} 个目标的技术指纹…</span>
                  </div>
                  <div className="h-1 rounded-full bg-base-700 overflow-hidden">
                    <div className="h-full rounded-full bg-yellow-400/60 animate-pulse" style={{ width: '100%' }} />
                  </div>
                </div>
              )}
              {running && progress && progress.phase !== 'fingerprint' && progress.total > 0 && (
                <div className="space-y-1 pt-1">
                  <div className="flex justify-between text-[10px]">
                    <span className="text-slate-400">{progress.scanned.toLocaleString()} / {progress.total.toLocaleString()} 目标</span>
                    <span className="text-cyber">{progress.percent.toFixed(1)}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-base-700 overflow-hidden">
                    <div className="h-full rounded-full bg-cyber transition-all duration-700" style={{ width: `${Math.min(progress.percent, 100)}%` }} />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-600">
                    {progress.rps > 0 && <span>{progress.rps} req/s</span>}
                    {progress.eta && <span>ETA {progress.eta}</span>}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 错误 */}
          {err && (
            <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              <span>{err}</span>
              <button onClick={() => setErr(null)} className="ml-auto"><X size={12} /></button>
            </div>
          )}

          {/* 扫描队列 */}
          <div className="rounded-lg border border-line bg-base-800/60">
            <button onClick={() => setShowQueue(v => !v)}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-xs font-medium text-slate-300 hover:text-slate-100 transition">
              <ListOrdered size={13} className="text-slate-500" />
              扫描队列
              <span className="text-slate-600 font-normal">({queue.filter(qi => qi.status === 'pending').length} 等待)</span>
              {pendingQueueLen > 0 && <span className="h-2 w-2 rounded-full bg-yellow-400 animate-pulse" />}
              <span className="ml-auto text-slate-600">{showQueue ? <ChevronUp size={12} /> : <ChevronDown size={12} />}</span>
            </button>
            {showQueue && (
              <div className="border-t border-line p-3 space-y-2">
                {queue.length === 0 ? (
                  <div className="text-[10px] text-slate-600 text-center py-1">队列为空</div>
                ) : (
                  <>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                      {queue.slice().reverse().map(qi => (
                        <div key={qi.id} className="flex items-center gap-2 rounded px-2 py-1.5 bg-base-700/30">
                          <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${
                            qi.status === 'running' ? 'bg-cyber animate-pulse' :
                            qi.status === 'done' ? 'bg-emerald-400' :
                            qi.status === 'cancelled' ? 'bg-slate-600' : 'bg-yellow-400'
                          }`} />
                          <div className="flex-1 min-w-0">
                            <div className="text-[10px] text-slate-300 truncate">{qi.name}</div>
                            <div className={`text-[9px] ${QUEUE_STATUS[qi.status] ?? 'text-slate-500'}`}>
                              {qi.status === 'pending' ? '等待中' : qi.status === 'running' ? '执行中' : qi.status === 'done' ? '已完成' : '已取消'}
                              {' · '}{qi.targetCount} 目标
                            </div>
                          </div>
                          {qi.status === 'pending' && (
                            <button onClick={() => handleCancelQueue(qi.id)}
                              className="text-slate-600 hover:text-red-400 p-0.5"><X size={10} /></button>
                          )}
                        </div>
                      ))}
                    </div>
                    {queue.some(qi => qi.status !== 'running') && (
                      <button onClick={() => handleCancelQueue()} className="text-[10px] text-slate-600 hover:text-red-400">
                        清空非运行项
                      </button>
                    )}
                  </>
                )}
              </div>
            )}
          </div>

          {/* 目标列表 */}
          <div className="rounded-lg border border-line bg-base-800/60">
            <button onClick={() => setShowTargetLists(v => !v)}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-xs font-medium text-slate-300 hover:text-slate-100 transition">
              <Bookmark size={13} className="text-slate-500" />
              目标列表 <span className="text-slate-600 font-normal">({targetLists.length})</span>
              <span className="ml-auto text-slate-600">{showTargetLists ? <ChevronUp size={12} /> : <ChevronDown size={12} />}</span>
            </button>
            {showTargetLists && (
              <div className="border-t border-line p-3 space-y-3">
                <div className="flex gap-2">
                  <input value={newListName} onChange={e => setNewListName(e.target.value)}
                    placeholder="列表名称…"
                    className="flex-1 rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyber" />
                  <button onClick={handleSaveTargetList} disabled={!targets.trim() || !newListName.trim() || savingList}
                    className="chip border border-cyber/40 bg-cyber/10 text-cyber text-[10px] disabled:opacity-40">
                    {savingList ? <Loader2 size={10} className="animate-spin" /> : <Bookmark size={10} />} 保存
                  </button>
                </div>
                {targetLists.length === 0 ? (
                  <div className="text-[10px] text-slate-600 text-center py-1">暂无保存的目标列表</div>
                ) : (
                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {targetLists.map(tl => (
                      <div key={tl.id} className="flex items-center gap-2 rounded px-2 py-1 hover:bg-base-600/30">
                        <div className="flex-1 min-w-0">
                          <div className="text-xs text-slate-200 truncate">{tl.name}</div>
                          <div className="text-[10px] text-slate-600">{tl.count} 目标</div>
                        </div>
                        <button onClick={() => setTargets(tl.targets.join('\n'))}
                          className="text-[10px] text-cyber border border-cyber/30 rounded px-1.5 py-0.5 hover:bg-cyber/10">加载</button>
                        <button onClick={() => engineRequest(CAP, `/target-list?id=${tl.id}`, { method: 'DELETE' }).then(fetchTargetLists)}
                          className="text-slate-600 hover:text-red-400 p-0.5"><Trash2 size={10} /></button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Scope */}
          <div className="rounded-lg border border-line bg-base-800/60">
            <button onClick={() => setShowScope(v => !v)}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-xs font-medium text-slate-300 hover:text-slate-100 transition">
              <ShieldCheck size={13} className="text-slate-500" />
              授权扫描范围
              <span className={`text-[10px] rounded px-1 py-0.5 ml-1 ${
                scope.mode === 'enforce' ? 'text-emerald-400 bg-emerald-400/10' :
                scope.mode === 'warn' ? 'text-yellow-400 bg-yellow-400/10' :
                'text-slate-600 bg-base-600/40'
              }`}>{scope.mode === 'enforce' ? '强制' : scope.mode === 'warn' ? '警告' : '关闭'}</span>
              <span className="ml-auto text-slate-600">{showScope ? <ChevronUp size={12} /> : <ChevronDown size={12} />}</span>
            </button>
            {showScope && (
              <div className="border-t border-line p-3 space-y-3">
                <div className="flex gap-2">
                  {(['disabled', 'warn', 'enforce'] as const).map(m => (
                    <button key={m} onClick={() => handleScopeUpdate({ mode: m })}
                      className={`flex-1 rounded border py-1 text-[10px] transition ${scope.mode === m ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-500 hover:border-slate-400/40 hover:text-slate-300'}`}>
                      {m === 'disabled' ? '关闭' : m === 'warn' ? '警告模式' : '强制模式'}
                    </button>
                  ))}
                </div>
                <div className="space-y-1.5">
                  <div className="text-[10px] text-slate-500">授权 IP 段（CIDR）</div>
                  <div className="flex gap-1">
                    <input value={newScopeCidr} onChange={e => setNewScopeCidr(e.target.value)}
                      placeholder="192.168.0.0/16"
                      onKeyDown={e => e.key === 'Enter' && addScopeCidr()}
                      className="flex-1 rounded border border-line bg-base-700/60 px-2 py-1 text-[10px] text-slate-200 outline-none focus:border-cyber" />
                    <button onClick={addScopeCidr} className="chip border border-cyber/40 bg-cyber/10 text-cyber text-[10px]">+</button>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {scope.cidrs.map(c => (
                      <span key={c} className="flex items-center gap-1 rounded border border-line bg-base-700/40 px-1.5 py-0.5 text-[10px] text-slate-300">
                        {c}<button onClick={() => removeScopeCidr(c)} className="hover:text-red-400"><X size={8} /></button>
                      </span>
                    ))}
                  </div>
                </div>
                <div className="space-y-1.5">
                  <div className="text-[10px] text-slate-500">授权域名后缀</div>
                  <div className="flex gap-1">
                    <input value={newScopeDomain} onChange={e => setNewScopeDomain(e.target.value)}
                      placeholder="example.com"
                      onKeyDown={e => e.key === 'Enter' && addScopeDomain()}
                      className="flex-1 rounded border border-line bg-base-700/60 px-2 py-1 text-[10px] text-slate-200 outline-none focus:border-cyber" />
                    <button onClick={addScopeDomain} className="chip border border-cyber/40 bg-cyber/10 text-cyber text-[10px]">+</button>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {scope.domains.map(d => (
                      <span key={d} className="flex items-center gap-1 rounded border border-line bg-base-700/40 px-1.5 py-0.5 text-[10px] text-slate-300">
                        {d}<button onClick={() => removeScopeDomain(d)} className="hover:text-red-400"><X size={8} /></button>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* 排除列表 */}
          <div className="rounded-lg border border-line bg-base-800/60">
            <button onClick={() => setShowExclusions(v => !v)}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-xs font-medium text-slate-300 hover:text-slate-100 transition">
              <Ban size={13} className="text-slate-500" />
              永久排除列表 <span className="text-slate-600 font-normal">({exclusions.length})</span>
              <span className="ml-auto text-slate-600">{showExclusions ? <ChevronUp size={12} /> : <ChevronDown size={12} />}</span>
            </button>
            {showExclusions && (
              <div className="border-t border-line p-3 space-y-2">
                <div className="flex gap-1">
                  <input value={newExclPattern} onChange={e => setNewExclPattern(e.target.value)}
                    placeholder="IP / CIDR / 域名后缀"
                    onKeyDown={e => e.key === 'Enter' && handleAddExclusion()}
                    className="flex-1 rounded border border-line bg-base-700/60 px-2 py-1 text-[10px] text-slate-200 outline-none focus:border-cyber" />
                  <input value={newExclNote} onChange={e => setNewExclNote(e.target.value)}
                    placeholder="备注"
                    className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 text-[10px] text-slate-200 outline-none focus:border-cyber" />
                  <button onClick={handleAddExclusion} className="chip border border-red-400/40 bg-red-400/10 text-red-400 text-[10px]">
                    <Ban size={10} /> 添加
                  </button>
                </div>
                {exclusions.length === 0 ? (
                  <div className="text-[10px] text-slate-600 text-center py-1">排除列表为空</div>
                ) : (
                  <div className="space-y-1 max-h-36 overflow-y-auto">
                    {exclusions.map(ex => (
                      <div key={ex.id} className="flex items-center gap-2 rounded px-2 py-1 bg-base-700/30">
                        <Ban size={10} className="text-red-400/60 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="text-[10px] text-slate-300 font-mono truncate">{ex.pattern}</div>
                          {ex.note && <div className="text-[9px] text-slate-600">{ex.note}</div>}
                        </div>
                        <button onClick={() => handleDeleteExclusion(ex.id)}
                          className="text-slate-600 hover:text-red-400 p-0.5"><X size={10} /></button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 任务历史 */}
          <div className="rounded-lg border border-line bg-base-800/60">
            <button onClick={() => setShowHistory(v => !v)}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-xs font-medium text-slate-300 hover:text-slate-100 transition">
              <History size={13} className="text-slate-500" />
              历史任务 <span className="text-slate-600 font-normal">({tasks.length})</span>
              <span className="ml-auto text-slate-600">{showHistory ? <ChevronUp size={12} /> : <ChevronDown size={12} />}</span>
            </button>
            {showHistory && (
              <div className="border-t border-line">
                {tasks.length === 0 ? (
                  <div className="px-3 py-4 text-center text-xs text-slate-600">暂无历史任务</div>
                ) : (
                  <div className="max-h-64 overflow-y-auto divide-y divide-line">
                    <button onClick={() => setSelectedTask(null)}
                      className={`w-full flex items-center gap-2 px-3 py-2 text-xs transition hover:bg-base-600/30 ${!selectedTask ? 'bg-cyber/5 border-l-2 border-cyber text-cyber' : 'text-slate-400 border-l-2 border-transparent'}`}>
                      <ScanSearch size={11} /><span>全部结果</span>
                    </button>
                    {tasks.map(t => (
                      <div key={t.id} onClick={() => setSelectedTask(t)}
                        className={`flex items-start gap-2 px-3 py-2 cursor-pointer hover:bg-base-600/30 transition ${selectedTask?.id === t.id ? 'bg-cyber/5 border-l-2 border-cyber' : 'border-l-2 border-transparent'}`}>
                        <span className={`mt-1 h-2 w-2 flex-shrink-0 rounded-full ${t.id === activeTaskId ? 'bg-cyber animate-pulse' : t.error ? 'bg-red-400/70' : 'bg-slate-600'}`} />
                        <div className="flex-1 min-w-0">
                          <div className="text-[11px] text-slate-200 truncate">{t.name}</div>
                          <div className="text-[10px] text-slate-500 mt-0.5 flex gap-2">
                            <span><Target size={8} className="inline mr-0.5" />{t.targetCount}</span>
                            <span className="text-cyber/70">{t.total} 命中</span>
                            {t.startedAt && <span><Clock size={8} className="inline mr-0.5" />{relativeTime(t.startedAt)}</span>}
                          </div>
                          {t.error && <div className="text-[10px] text-red-400/60 mt-0.5 truncate">{t.error}</div>}
                          {t.proxy && <div className="text-[9px] text-slate-600 truncate">代理: {t.proxy}</div>}
                        </div>
                        <div className="flex flex-col items-end gap-1 flex-shrink-0">
                          <button onClick={e => { e.stopPropagation(); handleDeleteTask(t.id) }}
                            className="p-0.5 text-slate-700 hover:text-red-400"><Trash2 size={10} /></button>
                          {!t.running && (
                            <>
                              <button onClick={e => { e.stopPropagation(); handleResume(t.id, 'unscanned') }}
                                title="断点续扫（只扫未出现结果的目标）"
                                className="p-0.5 text-slate-700 hover:text-cyber"><RotateCcw size={10} /></button>
                              <button onClick={e => { e.stopPropagation(); handleDownloadReport(t.id) }}
                                title="下载 HTML 报告"
                                className="p-0.5 text-slate-700 hover:text-emerald-400"><FileText size={10} /></button>
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── 右：结果 ── */}
        <div className="col-span-12 lg:col-span-7">
          <div className="rounded-lg border border-line bg-base-800/60">

            {/* 结果头 */}
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
              <ShieldAlert size={15} className="text-cyber" />
              <div>
                <span className="text-sm font-medium text-slate-200">
                  {selectedTask ? selectedTask.name : '全部扫描结果'}
                </span>
                <span className="ml-1.5 text-slate-500 text-xs">({totalCount})</span>
                {selectedTask && (
                  <div className="text-[10px] text-slate-600">
                    {selectedTask.targetCount} 目标 ·
                    {selectedTask.startedAt && ` ${new Date(selectedTask.startedAt).toLocaleString('zh-CN')}`}
                    {selectedTask.startedAt && selectedTask.stoppedAt && ` · ${fmtDuration(selectedTask.startedAt, selectedTask.stoppedAt)}`}
                  </div>
                )}
              </div>
              {selectedTask && (
                <button onClick={() => setSelectedTask(null)}
                  className="chip border border-line bg-base-600/60 text-slate-400 text-[10px]">
                  <X size={10} /> 查看全部
                </button>
              )}
              {selectedIds.size > 0 && (
                <div className="flex items-center gap-1 flex-wrap">
                  <span className="text-[10px] text-slate-400">{selectedIds.size} 条已选</span>
                  <button onClick={() => handleBatchUpdate(undefined, 'confirmed')}
                    className="chip border border-emerald-400/40 bg-emerald-400/10 text-emerald-400 text-[10px]">
                    <ShieldCheck size={10} /> 批量确认
                  </button>
                  <button onClick={() => handleBatchUpdate(true, 'fp')}
                    className="chip border border-red-400/40 bg-red-400/10 text-red-400 text-[10px]">
                    <ShieldX size={10} /> 批量 FP
                  </button>
                  <button onClick={handleImportToPoc}
                    className="chip border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-[10px]">
                    <FlaskConical size={11} /> 导入 PoC
                  </button>
                </div>
              )}

              {/* 工具栏 */}
              <div className="ml-auto flex flex-wrap items-center gap-1.5">
                <input value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
                  placeholder="搜索…"
                  className="rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyber w-24" />
                <select value={sevFilter} onChange={e => { setSevFilter(e.target.value); setPage(1) }}
                  className="rounded border border-line bg-base-700/60 px-1.5 py-1 text-xs text-slate-300 outline-none focus:border-cyber">
                  <option value="">全部等级</option>
                  {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                    <option key={s} value={s}>{SEV_CONFIG[s]?.label}</option>
                  ))}
                </select>
                <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}
                  className="rounded border border-line bg-base-700/60 px-1.5 py-1 text-xs text-slate-300 outline-none focus:border-cyber">
                  <option value="">全部状态</option>
                  <option value="pending">待确认</option>
                  <option value="confirmed">已确认</option>
                  <option value="follow_up">待跟进</option>
                  <option value="fp">假阳性</option>
                </select>
                <select value={sortBy} onChange={e => { setSortBy(e.target.value as 'time' | 'severity'); setPage(1) }}
                  className="rounded border border-line bg-base-700/60 px-1.5 py-1 text-xs text-slate-300 outline-none focus:border-cyber">
                  <option value="time">最新优先</option>
                  <option value="severity">严重优先</option>
                </select>
                <button onClick={() => { setShowFP(v => !v); setPage(1) }}
                  title={showFP ? '隐藏假阳性' : '显示假阳性'}
                  className={`chip border text-[10px] ${showFP ? 'border-red-400/30 bg-red-400/5 text-red-400' : 'border-line bg-base-600/60 text-slate-500'}`}>
                  {showFP ? <Eye size={11} /> : <EyeOff size={11} />} FP
                </button>
                {dupCount > 0 && (
                  <button onClick={() => { setShowDup(v => !v); setPage(1) }}
                    title={showDup ? '隐藏重复结果' : `显示跨任务重复（${dupCount}）`}
                    className={`chip border text-[10px] ${showDup ? 'border-yellow-400/30 bg-yellow-400/5 text-yellow-400' : 'border-line bg-base-600/60 text-slate-500'}`}>
                    <Copy size={11} /> 重复 {dupCount}
                  </button>
                )}
                {results.length > 0 && (
                  <>
                    <button onClick={() => setReviewMode(true)}
                      className="chip border border-purple-400/40 bg-purple-400/10 text-purple-400 text-[10px]">
                      <Inbox size={11} /> 审阅
                    </button>
                    <button onClick={() => handleExport('csv')} className="chip border border-line bg-base-600/60 text-slate-400 text-[10px]"><Download size={11} /> CSV</button>
                    <button onClick={() => handleExport('json')} className="chip border border-line bg-base-600/60 text-slate-400 text-[10px]"><Download size={11} /> JSON</button>
                    {!selectedTask && (
                      <button onClick={handleClear} className="chip border border-red-500/30 bg-red-500/5 text-red-400 text-[10px]"><Trash2 size={11} /> 清空</button>
                    )}
                  </>
                )}
              </div>
            </div>

            {/* 批量操作横幅 / 导入成功横幅 */}
            {importMsg && (
              <div className="flex items-center gap-2 border-b border-emerald-500/20 bg-emerald-500/5 px-4 py-2 text-xs text-emerald-400">
                <CheckCircle size={12} />{importMsg}
              </div>
            )}

            {/* 结果表 */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-xs text-slate-500">
                    <th className="px-3 py-2 w-8">
                      <input type="checkbox"
                        checked={results.length > 0 && selectedIds.size === results.length}
                        onChange={toggleSelectAll} className="rounded accent-cyber" />
                    </th>
                    <th className="px-3 py-2 font-medium">等级</th>
                    <th className="px-3 py-2 font-medium">名称/模板</th>
                    <th className="px-3 py-2 font-medium">主机</th>
                    <th className="px-3 py-2 font-medium">状态</th>
                    <th className="px-2 py-2" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {results.length === 0 && (
                    <tr><td colSpan={6} className="p-8 text-center text-sm text-slate-500">
                      {running ? '扫描中，等待结果…' : selectedTask ? '该任务暂无结果' : '暂无结果，配置目标后发起扫描'}
                    </td></tr>
                  )}
                  {results.map(r => (
                    <Fragment key={r.id}>
                      <tr onClick={() => setExpandedId(expandedId === r.id ? null : r.id)}
                        className={`cursor-pointer transition ${r.falsePositive ? 'opacity-40' : 'hover:bg-base-600/30'} ${r.duplicateOf ? 'border-l-2 border-yellow-400/30' : ''}`}>
                        <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
                          <input type="checkbox" checked={selectedIds.has(r.id)}
                            onChange={() => toggleSelect(r.id)} className="rounded accent-cyber" />
                        </td>
                        <td className="px-3 py-2.5">
                          <SevBadge sev={r.severity} />
                          {r.duplicateOf && <span className="ml-1 text-[9px] text-yellow-400 border border-yellow-400/30 rounded px-0.5">重复</span>}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="text-slate-200 text-xs font-medium">{r.name}</div>
                          <div className="text-slate-600 font-mono text-[10px]">{r.templateId}</div>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-cyber text-xs max-w-28 truncate">{r.host}</td>
                        <td className="px-3 py-2.5">
                          {(r.status || r.falsePositive) && (
                            <span className={`text-[10px] border rounded px-1 py-0.5 ${RESULT_STATUS[r.falsePositive ? 'fp' : (r.status ?? '')].cls}`}>
                              {RESULT_STATUS[r.falsePositive ? 'fp' : (r.status ?? '')].label}
                            </span>
                          )}
                          {r.analystNote && <MessageSquare size={10} className="inline ml-1 text-slate-500" />}
                        </td>
                        <td className="px-2 py-2.5 text-right">
                          <div className="flex items-center justify-end gap-1">
                            {expandedId === r.id ? <ChevronUp size={12} className="text-slate-500" /> : <ChevronDown size={12} className="text-slate-500" />}
                            <button onClick={e => { e.stopPropagation(); handleDeleteOne(r.id) }}
                              className="p-0.5 text-slate-600 hover:text-red-400"><Trash2 size={12} /></button>
                          </div>
                        </td>
                      </tr>
                      {expandedId === r.id && (
                        <tr className="bg-base-900/40">
                          <td colSpan={6} className="px-4 pb-4 pt-2">
                            <div className="space-y-2 text-xs">
                              {r.matchedAt && <div className="text-slate-400 font-mono text-[10px] break-all">{r.matchedAt}</div>}
                              {r.duplicateOf && <div className="text-[10px] text-yellow-400">⚠ 与结果 {r.duplicateOf} 跨任务重复</div>}
                              {/* 分析师工作流 */}
                              <div className="flex items-center gap-2 pt-1 border-t border-line/50">
                                <Shield size={11} className="text-slate-500 flex-shrink-0" />
                                <select
                                  value={r.falsePositive ? 'fp' : (r.status || 'pending')}
                                  onChange={e => handleUpdateResult(r.id, { status: e.target.value })}
                                  onClick={e => e.stopPropagation()}
                                  className="rounded border border-line bg-base-700/60 px-1.5 py-0.5 text-[10px] text-slate-300 outline-none focus:border-cyber">
                                  <option value="pending">待确认</option>
                                  <option value="confirmed">已确认</option>
                                  <option value="follow_up">待跟进</option>
                                  <option value="fp">假阳性</option>
                                </select>
                                <button
                                  onClick={e => { e.stopPropagation(); handleUpdateResult(r.id, { falsePositive: !r.falsePositive }) }}
                                  className={`chip border text-[10px] transition ${r.falsePositive ? 'border-red-400/40 bg-red-400/10 text-red-400' : 'border-line bg-base-600/60 text-slate-500'}`}>
                                  <AlertCircle size={10} />
                                  {r.falsePositive ? '取消 FP' : '标记 FP'}
                                </button>
                              </div>
                              <div className="flex items-start gap-2">
                                <MessageSquare size={11} className="text-slate-500 mt-1 flex-shrink-0" />
                                <textarea
                                  value={localNotes[r.id] ?? r.analystNote ?? ''}
                                  onChange={e => setLocalNotes(p => ({ ...p, [r.id]: e.target.value }))}
                                  onBlur={e => handleUpdateResult(r.id, { analystNote: e.target.value })}
                                  onClick={e => e.stopPropagation()}
                                  placeholder="分析师备注（失去焦点自动保存）…"
                                  rows={2}
                                  className="flex-1 resize-none rounded border border-line bg-base-700/60 p-1.5 text-[10px] text-slate-300 outline-none focus:border-cyber/50 placeholder:text-slate-700"
                                />
                              </div>
                              {r.tags.length > 0 && (
                                <div className="flex flex-wrap gap-1">
                                  {r.tags.map(t => <span key={t} className="rounded border border-line bg-base-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">#{t}</span>)}
                                </div>
                              )}
                              {r.ip && <div className="text-slate-500">IP: <span className="font-mono text-slate-300">{r.ip}</span></div>}
                              {r.curlCmd && (
                                <details><summary className="cursor-pointer text-cyber/70 hover:text-cyber">curl 命令</summary>
                                  <pre className="mt-1 overflow-x-auto rounded bg-base-700/60 p-2 font-mono text-[10px] text-slate-300 whitespace-pre-wrap">{r.curlCmd}</pre>
                                </details>
                              )}
                              {r.request && (
                                <details><summary className="cursor-pointer text-slate-500 hover:text-slate-300">请求详情</summary>
                                  <pre className="mt-1 max-h-40 overflow-auto rounded bg-base-700/60 p-2 font-mono text-[10px] text-slate-400 whitespace-pre-wrap">{r.request}</pre>
                                </details>
                              )}
                              {r.response && (
                                <details><summary className="cursor-pointer text-slate-500 hover:text-slate-300">响应详情</summary>
                                  <pre className="mt-1 max-h-40 overflow-auto rounded bg-base-700/60 p-2 font-mono text-[10px] text-slate-400 whitespace-pre-wrap">{r.response}</pre>
                                </details>
                              )}
                              <div className="text-slate-600 text-[10px]">发现时间: {new Date(r.foundAt).toLocaleString('zh-CN')}</div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            {/* 分页 */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between border-t border-line px-4 py-2.5">
                <span className="text-xs text-slate-500">第 {page} / {totalPages} 页，共 {totalCount} 条</span>
                <div className="flex items-center gap-1">
                  <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                    className="chip border border-line bg-base-600/60 text-slate-300 disabled:opacity-40 text-[10px]">上一页</button>
                  <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}
                    className="chip border border-line bg-base-600/60 text-slate-300 disabled:opacity-40 text-[10px]">下一页</button>
                </div>
              </div>
            )}

            {status?.capped && (
              <div className="border-t border-yellow-500/20 bg-yellow-500/5 px-4 py-2 text-xs text-yellow-400">
                结果数已达 50,000 条上限，后续命中已丢弃。请缩小扫描范围或清空后重扫。
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
