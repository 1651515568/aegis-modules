import { useEffect, useRef, useState, type ReactNode } from 'react'
import {
  Crosshair, Play, Square, RefreshCw, Download, Save,
  CheckCircle2, Eye, EyeOff, Copy, Globe, Server,
  Building2, Layers, AppWindow, List, KeyRound, Search,
  ChevronUp, ChevronDown, ChevronsUpDown, Clock, History,
} from 'lucide-react'
import { StatCard, Progress } from '@/components/ui'
import { engineGet, enginePost } from '@/lib/engine'
import { createTask, updateTask, pollTask, listTasks, type TaskRecord } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'asset-collect'
const MAX_ROWS = 2000  // 超出此数量时截断，提示用户用过滤缩小范围

// ── 类型 ─────────────────────────────────────────────────────────────────────

interface CollectedAsset {
  type: string; value: string; org: string
  source: string; meta: string; foundAt: string
}

interface SavedKeys {
  hunterKey: string; zoomeyeKey: string; quakeKey: string; zerozoneKey: string
  fofaEmail: string; fofaKey: string; shodanKey: string
  securitytrailsKey: string; censysId: string; censysSecret: string
  virusTotalKey: string; chaosKey: string; threatbookKey: string
  tianyanchaKey: string; qccKey: string; aiqichaKey: string
  xiaolanbenKey: string; qimaiKey: string; fengniaKey: string
}

const EMPTY_KEYS: SavedKeys = {
  hunterKey: '', zoomeyeKey: '', quakeKey: '', zerozoneKey: '',
  fofaEmail: '', fofaKey: '', shodanKey: '',
  securitytrailsKey: '', censysId: '', censysSecret: '',
  virusTotalKey: '', chaosKey: '', threatbookKey: '',
  tianyanchaKey: '', qccKey: '', aiqichaKey: '',
  xiaolanbenKey: '', qimaiKey: '', fengniaKey: '',
}

type SortKey = 'type' | 'value' | 'port' | 'org' | 'source' | 'foundAt'

// ── 情报源定义 ────────────────────────────────────────────────────────────────

interface SourceField { key: keyof SavedKeys; label: string }
interface SourceDef   { id: string; label: string; fields: SourceField[]; desc?: string }

const NET_SOURCES: SourceDef[] = [
  { id: 'hunter',         label: 'Hunter',         fields: [{ key: 'hunterKey',         label: 'API Key' }] },
  { id: 'fofa',           label: 'FOFA',           fields: [{ key: 'fofaEmail', label: 'Email' }, { key: 'fofaKey', label: 'API Key' }] },
  { id: 'zoomeye',        label: 'ZoomEye',        fields: [{ key: 'zoomeyeKey',        label: 'API Key' }] },
  { id: 'quake',          label: '360 Quake',      fields: [{ key: 'quakeKey',          label: 'Token'   }] },
  { id: 'zerozone',       label: '零零信安',        fields: [{ key: 'zerozoneKey',       label: 'API Key' }] },
  { id: 'shodan',         label: 'Shodan',         fields: [{ key: 'shodanKey',         label: 'API Key' }] },
  { id: 'securitytrails', label: 'SecurityTrails', fields: [{ key: 'securitytrailsKey', label: 'API Key' }] },
  { id: 'censys',         label: 'Censys',         fields: [{ key: 'censysId', label: 'API ID' }, { key: 'censysSecret', label: 'Secret' }] },
  { id: 'virustotal',     label: 'VirusTotal',     fields: [{ key: 'virusTotalKey',     label: 'API Key' }] },
  { id: 'chaos',          label: 'Chaos',          fields: [{ key: 'chaosKey',          label: 'API Key' }] },
  { id: 'threatbook',     label: '微步',            fields: [{ key: 'threatbookKey',     label: 'API Key' }] },
  { id: 'crtsh',        label: 'crt.sh',        fields: [],
    desc: '免费 · SSL 证书透明度日志 · domain 模式自动调用' },
  { id: 'otx',          label: 'AlienVault OTX', fields: [],
    desc: '免费 · 被动 DNS · 全球威胁情报社区 · domain 模式自动调用' },
  { id: 'hackertarget', label: 'HackerTarget',   fields: [],
    desc: '免费 · 主机搜索 · 最多 100 条 · domain 模式自动调用' },
]

const BIZ_SOURCES: SourceDef[] = [
  { id: 'tianyancha', label: '天眼查', fields: [{ key: 'tianyanchaKey', label: 'Token'   }] },
  { id: 'qcc',        label: '企查查', fields: [{ key: 'qccKey',        label: 'Token'   }] },
  { id: 'aiqicha',    label: '爱企查', fields: [{ key: 'aiqichaKey',    label: 'API Key' }] },
  { id: 'xiaolanben', label: '小蓝本', fields: [{ key: 'xiaolanbenKey', label: 'API Key' }] },
  { id: 'qimai',      label: '七麦',   fields: [{ key: 'qimaiKey',      label: 'API Key' }] },
  { id: 'fengniao',   label: '风鸟',   fields: [{ key: 'fengniaKey',    label: 'API Key' }] },
]

const ALL_SOURCES = [...NET_SOURCES, ...BIZ_SOURCES]

// ── 样式映射 ──────────────────────────────────────────────────────────────────

const SOURCE_LABEL: Record<string, string> = {
  ...Object.fromEntries(ALL_SOURCES.map(s => [s.id, s.label])),
  subsidiary: '子公司',
}

const SOURCE_CLS: Record<string, string> = {
  hunter:         'border-amber-500/40 bg-amber-500/10 text-amber-400',
  fofa:           'border-blue-400/40 bg-blue-400/10 text-blue-400',
  zoomeye:        'border-purple-500/40 bg-purple-500/10 text-purple-400',
  quake:          'border-orange-500/40 bg-orange-500/10 text-orange-400',
  zerozone:       'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
  shodan:         'border-red-400/40 bg-red-400/10 text-red-400',
  securitytrails: 'border-teal-400/40 bg-teal-400/10 text-teal-400',
  censys:         'border-indigo-400/40 bg-indigo-400/10 text-indigo-400',
  virustotal:     'border-sky-400/40 bg-sky-400/10 text-sky-400',
  chaos:          'border-yellow-400/40 bg-yellow-400/10 text-yellow-400',
  threatbook:     'border-rose-400/40 bg-rose-400/10 text-rose-400',
  crtsh:          'border-green-400/40 bg-green-400/10 text-green-400',
  otx:            'border-orange-400/40 bg-orange-400/10 text-orange-400',
  hackertarget:   'border-lime-500/40 bg-lime-500/10 text-lime-400',
  tianyancha:     'border-cyan-400/40 bg-cyan-400/10 text-cyan-400',
  qcc:            'border-lime-400/40 bg-lime-400/10 text-lime-400',
  aiqicha:        'border-blue-500/40 bg-blue-500/10 text-blue-300',
  xiaolanben:     'border-sky-500/40 bg-sky-500/10 text-sky-300',
  qimai:          'border-pink-400/40 bg-pink-400/10 text-pink-400',
  fengniao:       'border-violet-400/40 bg-violet-400/10 text-violet-400',
  subsidiary:     'border-slate-400/40 bg-slate-400/10 text-slate-300',
}

const TYPE_CLS: Record<string, string> = {
  domain:  'border-cyber/40 bg-cyber/10 text-cyber',
  ip:      'border-purple-400/40 bg-purple-400/10 text-purple-400',
  app:     'border-emerald-400/40 bg-emerald-400/10 text-emerald-400',
  icp:     'border-amber-400/40 bg-amber-400/10 text-amber-400',
  company: 'border-slate-400/40 bg-slate-400/10 text-slate-300',
}

const TARGET_TYPES = [
  { value: 'company' as const, label: '企业名称' },
  { value: 'domain'  as const, label: '域名'     },
  { value: 'ip'      as const, label: 'IP · CIDR' },
  { value: 'keyword' as const, label: '关键词'    },
]

type Tab = 'hunt' | 'results' | 'sources'

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

function isConfigured(src: SourceDef, keys: SavedKeys) {
  return src.fields.every(f => Boolean(keys[f.key]))
}

function parsePort(meta: string): number | null {
  try {
    const m = JSON.parse(meta)
    return typeof m.port === 'number' && m.port > 0 ? m.port : null
  } catch { return null }
}

function triggerDownload(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url  = URL.createObjectURL(blob)
  const el   = document.createElement('a')
  // 去除文件名里的中文和特殊字符，避免部分系统不支持
  el.download = filename.replace(/[^\w.\-]/g, '_')
  el.href = url
  el.click()
  URL.revokeObjectURL(url)
}

// ── 子组件 ───────────────────────────────────────────────────────────────────

interface BadgeMeta { text: string; tone: 'high' | 'ok' | 'neutral' }

function TabButton({ active, onClick, icon, label, badge }: {
  active: boolean; onClick: () => void
  icon: ReactNode; label: string; badge?: BadgeMeta
}) {
  const badgeCls: Record<string, string> = {
    high:    'bg-sev-high/20 text-sev-high',
    ok:      'bg-emerald-500/15 text-emerald-400',
    neutral: 'bg-base-600 text-slate-500',
  }
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
        active
          ? 'border-cyber text-cyber'
          : 'border-transparent text-slate-400 hover:text-slate-200'
      }`}
    >
      {icon}
      {label}
      {badge && (
        <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium ${badgeCls[badge.tone]}`}>
          {badge.text}
        </span>
      )}
    </button>
  )
}

function SortableTh({ label, col, current, dir, onSort, className = '' }: {
  label: string; col: SortKey
  current: SortKey | null; dir: 'asc' | 'desc'
  onSort: (k: SortKey) => void; className?: string
}) {
  const active = current === col
  return (
    <th
      onClick={() => onSort(col)}
      className={`cursor-pointer select-none px-4 py-2.5 font-medium text-xs text-slate-500 hover:text-slate-300 transition-colors ${className}`}
    >
      <div className="flex items-center gap-1">
        {label}
        <span className={active ? 'text-cyber' : 'text-slate-700'}>
          {active
            ? dir === 'asc' ? <ChevronUp size={11} /> : <ChevronDown size={11} />
            : <ChevronsUpDown size={11} />
          }
        </span>
      </div>
    </th>
  )
}

interface SourceCardProps {
  src: SourceDef; keys: SavedKeys; savedKeys: SavedKeys
  reveal: boolean; setKey: (k: keyof SavedKeys, v: string) => void
}

function SourceCard({ src, keys, savedKeys, reveal, setKey }: SourceCardProps) {
  const configured = src.fields.every(f => Boolean(savedKeys[f.key]))
  const isFree = src.fields.length === 0
  return (
    <div className={`rounded-xl border p-3.5 space-y-2.5 transition-colors ${
      configured ? 'border-emerald-500/25 bg-emerald-500/5' : 'border-line/50 bg-base-700/20'
    }`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full shrink-0 ${configured ? 'bg-emerald-400' : 'bg-slate-700'}`} />
          <span className="text-sm font-medium text-slate-200">{src.label}</span>
          {isFree && (
            <span className="rounded px-1 py-0.5 text-[9px] font-semibold uppercase tracking-wide bg-green-400/15 text-green-400">
              免费
            </span>
          )}
        </div>
        {configured && (
          <span className="flex items-center gap-1 text-[10px] text-emerald-400">
            <CheckCircle2 size={10} /> {isFree ? '始终可用' : '已配置'}
          </span>
        )}
      </div>
      {src.desc && (
        <p className="text-[10px] text-slate-600 leading-relaxed">{src.desc}</p>
      )}
      {src.fields.map(f => (
        <div key={f.key} className="space-y-1">
          <label className="text-[10px] text-slate-600">{f.label}</label>
          <input
            type={reveal ? 'text' : 'password'}
            value={keys[f.key]}
            onChange={e => setKey(f.key, e.target.value)}
            placeholder={savedKeys[f.key] ? '已配置（留空保留）' : '未填写'}
            className="w-full rounded-lg border border-line/60 bg-base-800/60 px-2.5 py-1.5 font-mono text-xs text-slate-300 outline-none transition-colors focus:border-cyber"
          />
        </div>
      ))}
    </div>
  )
}

// ── 主组件 ───────────────────────────────────────────────────────────────────

export default function AssetCollectView() {
  const [tab,         setTab]         = useState<Tab>('hunt')
  const [target,      setTarget]      = useState('')
  const [targetType,  setTargetType]  = useState<'company' | 'domain' | 'ip' | 'keyword'>('company')

  const [keys,       setKeys]       = useState<SavedKeys>(EMPTY_KEYS)
  const [savedKeys,  setSavedKeys]  = useState<SavedKeys>(EMPTY_KEYS)
  const [savingKeys, setSavingKeys] = useState(false)
  const [saveMsg,    setSaveMsg]    = useState<string | null>(null)
  const [revealKeys, setRevealKeys] = useState(false)

  const [running,     setRunning]     = useState(false)
  const [results,     setResults]     = useState<CollectedAsset[]>([])
  const [progress,    setProgress]    = useState<string | null>(null)
  const [progressPct, setProgressPct] = useState(0)
  const [err,         setErr]         = useState<string | null>(null)

  const [filterType, setFilterType] = useState('all')
  const [filterSrc,  setFilterSrc]  = useState('all')
  const [filterQ,    setFilterQ]    = useState('')
  const [sortKey,    setSortKey]    = useState<SortKey | null>(null)
  const [sortDir,    setSortDir]    = useState<'asc' | 'desc'>('asc')
  const [copied,     setCopied]     = useState<string | null>(null)
  const [taskReload, setTaskReload] = useState(0)

  const [historyTasks,     setHistoryTasks]     = useState<TaskRecord[]>([])
  const [showHistory,      setShowHistory]      = useState(false)
  const [currentTaskId,    setCurrentTaskId]    = useState<string | null>(null)
  const [currentTaskLabel, setCurrentTaskLabel] = useState<string | null>(null)

  const stoppedRef = useRef(false)
  const mountedRef = useRef(true)

  function setKey(k: keyof SavedKeys, v: string) {
    setKeys(prev => ({ ...prev, [k]: v }))
  }

  function toggleSort(k: SortKey) {
    if (sortKey === k) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(k)
      setSortDir('asc')
    }
  }

  function taskLabel(t: TaskRecord): string {
    const target = (t.params as Record<string, string> | null)?.target ?? '未知目标'
    const date = t.finishedAt?.replace('T', ' ').slice(0, 16) ?? ''
    return date ? `${target} · ${date}` : target
  }

  async function openHistory() {
    try {
      const tasks = await listTasks({ capabilityKey: CAP, status: 'succeeded', limit: 20 })
      setHistoryTasks(tasks)
      setShowHistory(v => !v)
    } catch { /* 静默 */ }
  }

  async function switchToTask(t: TaskRecord) {
    try {
      const r = await engineGet<{ items: CollectedAsset[] }>(CAP, '/findings', { taskId: t.id })
      const items = r.items ?? []
      setResults(items)
      setCurrentTaskId(t.id)
      setCurrentTaskLabel(taskLabel(t))
      setShowHistory(false)
      setFilterType('all'); setFilterSrc('all'); setFilterQ(''); setSortKey(null)
      if (items.length > 0) setTab('results')
    } catch { /* 静默 */ }
  }

  // ── 初始化 ───────────────────────────────────────────────────────────────
  useEffect(() => {
    mountedRef.current = true
    async function init() {
      const [settingsRes, statusRes] = await Promise.allSettled([
        engineGet<SavedKeys>(CAP, '/settings'),
        engineGet<{ running: boolean }>(CAP, '/status'),
      ])
      if (!mountedRef.current) return
      if (settingsRes.status === 'fulfilled') setSavedKeys(settingsRes.value)

      if (statusRes.status === 'fulfilled' && statusRes.value.running) {
        const [rt, pt] = await Promise.all([
          listTasks({ capabilityKey: CAP, status: 'running', limit: 1 }),
          listTasks({ capabilityKey: CAP, status: 'pending', limit: 1 }),
        ])
        const active = rt[0] ?? pt[0]
        if (active && mountedRef.current) {
          setRunning(true); setProgress('重连收集任务…'); setTaskReload(n => n + 1)
          pollTask(active.id, {
            intervalMs: 2000, timeoutMs: 20 * 60 * 1000,
            onProgress: t => {
              if (mountedRef.current) { setProgress(t.message ?? '收集中…'); setProgressPct(t.progress) }
            },
          }).then(async fin => {
            if (!mountedRef.current) return
            const items = await loadFinished(fin, stoppedRef, setResults, setErr, CAP)
            if (items.length > 0) setTab('results')
            if (fin.status === 'succeeded') { setCurrentTaskId(fin.id); setCurrentTaskLabel(taskLabel(fin)) }
            setRunning(false); setProgress(null); setProgressPct(0)
            setTaskReload(n => n + 1); stoppedRef.current = false
          }).catch(() => { if (mountedRef.current) setRunning(false) })
          return // 有运行中任务，不加载历史结果
        }
      }

      // 无运行中任务时，加载最近一次已完成任务的 findings（页面刷新后恢复结果）
      try {
        const recent = await listTasks({ capabilityKey: CAP, status: 'succeeded', limit: 1 })
        if (recent[0] && mountedRef.current) {
          const r = await engineGet<{ items: CollectedAsset[] }>(CAP, '/findings', { taskId: recent[0].id })
          const items = r.items ?? []
          if (items.length > 0 && mountedRef.current) {
            setResults(items)
            setTab('results')
            setCurrentTaskId(recent[0].id)
            setCurrentTaskLabel(taskLabel(recent[0]))
          }
        }
      } catch { /* 无历史结果，静默忽略 */ }
    }
    init().catch(console.error)
    return () => { mountedRef.current = false }
  }, [])

  // ── 保存 Key ─────────────────────────────────────────────────────────────
  async function saveApiKeys() {
    setSavingKeys(true); setSaveMsg(null)
    try {
      // 空字段 = 保留已保存值，非空字段 = 更新（兑现 placeholder "留空保留" 的承诺）
      const merged = { ...keys }
      for (const k of Object.keys(merged) as (keyof SavedKeys)[]) {
        if (!merged[k] && savedKeys[k]) merged[k] = savedKeys[k]
      }
      await enginePost(CAP, '/settings', merged)
      const fresh = await engineGet<SavedKeys>(CAP, '/settings')
      setSavedKeys(fresh); setSaveMsg('已保存')
    } catch {
      setSaveMsg('保存失败')
    } finally {
      setSavingKeys(false)
      setTimeout(() => setSaveMsg(null), 3000)
    }
  }

  // ── 开始收集 ─────────────────────────────────────────────────────────────
  async function startCollect() {
    if (!target.trim() || running) return
    stoppedRef.current = false
    setErr(null); setResults([]); setProgressPct(0)
    setFilterType('all'); setFilterSrc('all'); setFilterQ(''); setSortKey(null)

    const params = { target: target.trim(), targetType, ...keys }
    let task: Awaited<ReturnType<typeof createTask>> | null = null
    let finished: TaskRecord | null = null

    setRunning(true); setProgress('启动收集…'); setTaskReload(n => n + 1)
    try {
      task = await createTask({ capabilityKey: CAP, action: 'collect', params })
      setTaskReload(n => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'collect', params })
      finished = await pollTask(task.id, {
        intervalMs: 2000, timeoutMs: 20 * 60 * 1000,
        onProgress: t => {
          if (mountedRef.current) { setProgress(t.message ?? '收集中…'); setProgressPct(t.progress) }
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
        if (finished) {
          const items = await loadFinished(finished, stoppedRef, setResults, setErr, CAP)
          if (items.length > 0) setTab('results')
          if (finished.status === 'succeeded') { setCurrentTaskId(finished.id); setCurrentTaskLabel(taskLabel(finished)) }
        }
        setRunning(false); setProgress(null); setProgressPct(0)
        setTaskReload(n => n + 1); stoppedRef.current = false
      }
    }
  }

  async function stopCollect() {
    stoppedRef.current = true
    try { await enginePost(CAP, '/stop', {}) } catch { /* ignore */ }
    setRunning(false); setProgress(null); setProgressPct(0)
  }

  function copyValue(v: string) {
    navigator.clipboard.writeText(v).then(() => {
      setCopied(v); setTimeout(() => setCopied(null), 2000)
    }).catch(() => {})
  }

  // ── 导出 ─────────────────────────────────────────────────────────────────
  function exportCSV() {
    const header = 'type,value,org,port,source,foundAt'
    const rows = sortedFiltered.map(a => {
      const port = parsePort(a.meta)
      return [a.type, a.value, a.org, String(port ?? ''), a.source, a.foundAt]
        .map(v => `"${v.replace(/"/g, '""')}"`)
        .join(',')
    })
    triggerDownload([header, ...rows].join('\n'), `assets-${target}.csv`, 'text/csv')
  }

  function exportJSON() {
    triggerDownload(
      JSON.stringify(sortedFiltered.map(a => ({ ...a, port: parsePort(a.meta) })), null, 2),
      `assets-${target}.json`, 'application/json'
    )
  }

  // ── 衍生数据 ─────────────────────────────────────────────────────────────
  const typeCount = (t: string) => results.filter(a => a.type === t).length

  const configuredNet = NET_SOURCES.filter(s => isConfigured(s, savedKeys)).length
  const configuredBiz = BIZ_SOURCES.filter(s => isConfigured(s, savedKeys)).length
  const totalConfigured = configuredNet + configuredBiz
  const bizRelevant = targetType === 'company' || targetType === 'keyword'

  // 来源贡献度：跟随 filterType（不跟随 filterSrc，避免自循环），让用户发现"在域名维度上哪个平台最强"
  const baseForBreakdown = filterType === 'all' ? results : results.filter(a => a.type === filterType)
  const sourceBreakdown = [...new Set(baseForBreakdown.map(a => a.source))]
    .map(id => ({ id, label: SOURCE_LABEL[id] ?? id, count: baseForBreakdown.filter(a => a.source === id).length }))
    .sort((a, b) => b.count - a.count)

  // 过滤（搜索范围包含 value、org、来源名称）
  const filtered = results.filter(a => {
    if (filterType !== 'all' && a.type !== filterType) return false
    if (filterSrc  !== 'all' && a.source !== filterSrc) return false
    if (filterQ) {
      const q = filterQ.toLowerCase()
      const srcLabel = (SOURCE_LABEL[a.source] ?? a.source).toLowerCase()
      if (!a.value.toLowerCase().includes(q) &&
          !a.org.toLowerCase().includes(q) &&
          !srcLabel.includes(q)) return false
    }
    return true
  })

  // 排序
  const sortedFiltered = sortKey ? [...filtered].sort((a, b) => {
    let av: string | number, bv: string | number
    if (sortKey === 'port') {
      av = parsePort(a.meta) ?? -1
      bv = parsePort(b.meta) ?? -1
    } else if (sortKey === 'source') {
      av = SOURCE_LABEL[a.source] ?? a.source
      bv = SOURCE_LABEL[b.source] ?? b.source
    } else {
      av = a[sortKey] ?? ''
      bv = b[sortKey] ?? ''
    }
    const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv), 'zh-CN')
    return sortDir === 'asc' ? cmp : -cmp
  }) : filtered

  // 截断超长结果集，防止渲染卡顿
  const visibleRows = sortedFiltered.slice(0, MAX_ROWS)
  const hiddenCount = sortedFiltered.length - MAX_ROWS

  // ── 渲染 ─────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4 animate-fade-in">

      {/* ━━ 标签页导航 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      <div className="flex items-center border-b border-line">
        <TabButton
          active={tab === 'hunt'} onClick={() => setTab('hunt')}
          icon={<Crosshair size={14} />} label="收集"
          badge={running ? { text: '运行中', tone: 'high' } : undefined}
        />
        <TabButton
          active={tab === 'results'} onClick={() => setTab('results')}
          icon={<List size={14} />} label="结果"
          badge={results.length > 0 ? { text: String(results.length), tone: 'neutral' } : undefined}
        />
        <TabButton
          active={tab === 'sources'} onClick={() => setTab('sources')}
          icon={<KeyRound size={14} />} label="情报源"
          badge={{ text: `${totalConfigured} / ${NET_SOURCES.length + BIZ_SOURCES.length}`, tone: totalConfigured > 0 ? 'ok' : 'neutral' }}
        />
      </div>

      {/* ━━ 标签页：收集 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {tab === 'hunt' && (
        <div className="space-y-4">
          <div className="panel p-5 space-y-4">

            {/* 目标输入 */}
            <div className="relative">
              <Crosshair size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && startCollect()}
                placeholder="输入企业名称、域名、IP 段或关键词…"
                className="w-full rounded-xl border border-line bg-base-700/60 py-3 pl-10 pr-4 text-sm text-slate-200 outline-none transition-colors focus:border-cyber"
              />
            </div>

            {/* 类型 pill 选择 */}
            <div className="flex flex-wrap gap-2">
              {TARGET_TYPES.map(t => (
                <button
                  key={t.value}
                  onClick={() => setTargetType(t.value)}
                  className={`rounded-lg border px-3.5 py-1.5 text-xs font-medium transition-colors ${
                    targetType === t.value
                      ? 'border-cyber/50 bg-cyber/15 text-cyber'
                      : 'border-line bg-base-700/40 text-slate-400 hover:border-slate-500 hover:text-slate-300'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* 操作按钮 */}
            <div className="flex items-center gap-3">
              {!running ? (
                <button
                  onClick={startCollect}
                  disabled={!target.trim() || totalConfigured === 0}
                  className="flex items-center gap-2 rounded-xl border border-cyber/40 bg-cyber/10 px-6 py-2.5 text-sm font-semibold text-cyber transition-all hover:bg-cyber/20 active:scale-95 disabled:opacity-40"
                >
                  <Play size={14} /> 开始收集
                </button>
              ) : (
                <button
                  onClick={stopCollect}
                  className="flex items-center gap-2 rounded-xl border border-sev-high/40 bg-sev-high/10 px-6 py-2.5 text-sm font-semibold text-sev-high transition-all hover:bg-sev-high/20 active:scale-95"
                >
                  <Square size={14} /> 停止收集
                </button>
              )}
              {totalConfigured === 0 && (
                <button onClick={() => setTab('sources')} className="text-xs text-slate-500 underline underline-offset-2 hover:text-cyber transition-colors">
                  前往配置情报源 →
                </button>
              )}
            </div>

            {/* 进度 */}
            {running && progress && (
              <div className="space-y-1.5 pt-1">
                <Progress value={progressPct} />
                <p className="flex items-center gap-1.5 text-xs text-slate-400">
                  <RefreshCw size={11} className="animate-spin" /> {progress}
                </p>
              </div>
            )}

            {/* 错误 */}
            {err && (
              <div className="rounded-xl border border-sev-high/30 bg-sev-high/10 px-4 py-2.5 text-sm text-sev-high">
                {err}
              </div>
            )}
          </div>

          {/* 情报源预览 */}
          {totalConfigured > 0 && (
            <div className="panel p-4 space-y-4">
              <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                本次收集将调用
              </p>
              <div className="space-y-2">
                <div className="flex items-baseline gap-2">
                  <span className="text-xs font-medium text-slate-400">网络测绘</span>
                  <span className="text-[10px] text-slate-600">{configuredNet} / {NET_SOURCES.length} 已就绪</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {NET_SOURCES.map(s => {
                    const ok = isConfigured(s, savedKeys)
                    return (
                      <span key={s.id} className={`chip border text-xs transition-colors ${
                        ok ? SOURCE_CLS[s.id] ?? 'border-line text-slate-300' : 'border-line/25 bg-transparent text-slate-700'
                      }`}>
                        {ok && <span className="h-1 w-1 rounded-full bg-current" />}
                        {s.label}
                      </span>
                    )
                  })}
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-baseline gap-2">
                  <span className="text-xs font-medium text-slate-400">企业情报</span>
                  <span className="text-[10px] text-slate-600">{configuredBiz} / {BIZ_SOURCES.length} 已就绪</span>
                  {!bizRelevant && configuredBiz > 0 && (
                    <span className="text-[10px] text-slate-700">当前类型不生效</span>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {BIZ_SOURCES.map(s => {
                    const hasCreds = isConfigured(s, savedKeys)
                    const willRun  = hasCreds && bizRelevant
                    return (
                      <span key={s.id} className={`chip border text-xs transition-colors ${
                        willRun  ? SOURCE_CLS[s.id] ?? 'border-line text-slate-300' :
                        hasCreds ? 'border-line/30 bg-transparent text-slate-600' :
                                   'border-line/15 bg-transparent text-slate-700'
                      }`}>
                        {willRun && <span className="h-1 w-1 rounded-full bg-current" />}
                        {s.label}
                      </span>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          <TaskList params={{ capabilityKey: CAP }} reloadToken={taskReload} />
        </div>
      )}

      {/* ━━ 标签页：结果 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {tab === 'results' && (
        <div className="space-y-4">

          {/* 历史任务切换栏 */}
          <div className="panel px-4 py-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 min-w-0 text-xs text-slate-400">
                <Clock size={12} className="shrink-0 text-slate-500" />
                {currentTaskLabel
                  ? <span className="truncate">{currentTaskLabel}</span>
                  : <span className="text-slate-600">尚无已完成任务</span>
                }
              </div>
              <button
                onClick={openHistory}
                className="shrink-0 chip border border-line/50 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <History size={11} />
                历史记录
                <ChevronDown size={11} className={`transition-transform duration-150 ${showHistory ? 'rotate-180' : ''}`} />
              </button>
            </div>
            {showHistory && (
              <div className="mt-3">
                {historyTasks.length === 0 ? (
                  <p className="py-2 text-center text-xs text-slate-600">暂无历史记录</p>
                ) : (
                  <div className="space-y-1 max-h-52 overflow-y-auto">
                    {historyTasks.map(t => {
                      const tgt   = (t.params as Record<string, string> | null)?.target ?? '—'
                      const ttype = (t.params as Record<string, string> | null)?.targetType ?? ''
                      const fin   = t.finishedAt?.replace('T', ' ').slice(0, 16) ?? ''
                      const isCurrent = currentTaskId === t.id
                      return (
                        <button
                          key={t.id}
                          onClick={() => switchToTask(t)}
                          className={`w-full flex items-center justify-between rounded-lg px-3 py-2 text-left text-xs transition-colors gap-2 ${
                            isCurrent
                              ? 'bg-cyber/10 border border-cyber/30 text-cyber'
                              : 'bg-base-700/40 hover:bg-base-600/40 border border-transparent text-slate-300 hover:text-slate-200'
                          }`}
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            {ttype && (
                              <span className={`shrink-0 chip border text-[10px] ${isCurrent ? 'border-cyber/30 text-cyber/70' : 'border-line/50 text-slate-500'}`}>
                                {ttype}
                              </span>
                            )}
                            <span className="font-mono truncate">{tgt}</span>
                            {isCurrent && <span className="shrink-0 text-[10px] opacity-60">当前</span>}
                          </div>
                          <span className="shrink-0 text-slate-500 text-[11px]">{fin}</span>
                        </button>
                      )
                    })}
                  </div>
                )}
              </div>
            )}
          </div>

          {results.length === 0 ? (
            <div className="panel flex flex-col items-center justify-center gap-3 py-16">
              <div className="rounded-xl border border-line/50 bg-base-700/40 p-4 text-slate-600">
                <List size={28} />
              </div>
              {running ? (
                <div className="space-y-1.5 text-center">
                  <p className="text-sm text-slate-400">正在收集中…</p>
                  <Progress value={progressPct} className="w-48" />
                </div>
              ) : (
                <>
                  <p className="text-sm text-slate-500">尚无收集结果</p>
                  <button onClick={() => setTab('hunt')} className="text-xs text-cyber underline underline-offset-2 hover:opacity-80 transition-opacity">
                    前往收集 →
                  </button>
                  <button onClick={openHistory} className="text-xs text-slate-500 underline underline-offset-2 hover:text-slate-400 transition-opacity">
                    或查看历史记录
                  </button>
                </>
              )}
            </div>
          ) : (
            <>
              {/* 统计卡片 */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                <StatCard label="总资产"     value={results.length}                           icon={<Layers    size={18} />} />
                <StatCard label="域名"       value={typeCount('domain')}                      icon={<Globe     size={18} />} />
                <StatCard label="IP"         value={typeCount('ip')}                          icon={<Server    size={18} />} />
                <StatCard label="App"        value={typeCount('app')}                         icon={<AppWindow size={18} />} />
                <StatCard label="ICP · 公司" value={typeCount('icp') + typeCount('company')} icon={<Building2 size={18} />} />
              </div>

              {/* 来源贡献分布 — 可点击快速过滤 */}
              <div className="panel px-4 py-3">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                  <span className="shrink-0 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                    来源贡献
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {sourceBreakdown.map(s => (
                      <button
                        key={s.id}
                        onClick={() => setFilterSrc(filterSrc === s.id ? 'all' : s.id)}
                        title={filterSrc === s.id ? '点击取消筛选' : `仅显示 ${s.label}`}
                        className={`chip border text-xs transition-all ${
                          filterSrc === s.id
                            ? SOURCE_CLS[s.id] ?? 'border-line text-slate-300'
                            : 'border-line/50 bg-base-700/30 text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        {s.label}
                        <span className={`font-mono tabular-nums ${filterSrc === s.id ? '' : 'opacity-50'}`}>
                          {s.count}
                        </span>
                      </button>
                    ))}
                    {filterSrc !== 'all' && (
                      <button
                        onClick={() => setFilterSrc('all')}
                        className="text-[10px] text-slate-600 underline underline-offset-2 hover:text-slate-400 transition-colors"
                      >
                        显示全部
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* 结果表格 */}
              <section className="panel">
                <header className="panel-head flex-wrap gap-y-2">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                    <List size={15} />
                    收集结果
                    <span className="text-xs font-normal text-slate-500">
                      {filtered.length !== results.length ? `${filtered.length} / ${results.length}` : results.length}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {/* 搜索 */}
                    <div className="relative">
                      <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-slate-500" />
                      <input
                        value={filterQ}
                        onChange={e => setFilterQ(e.target.value)}
                        placeholder="值 / 组织 / 来源…"
                        className="w-36 rounded-lg border border-line bg-base-700/60 py-1 pl-6 pr-2 text-xs text-slate-300 outline-none transition-colors focus:border-cyber"
                      />
                    </div>
                    {/* 类型快筛 */}
                    <div className="flex gap-1">
                      {(['all', 'domain', 'ip', 'app', 'icp', 'company'] as const).map(t => (
                        <button key={t} onClick={() => setFilterType(t)}
                          className={`chip border text-xs transition-colors ${
                            filterType === t
                              ? 'border-cyber/40 bg-cyber/10 text-cyber'
                              : 'border-line bg-base-700/40 text-slate-400 hover:text-slate-300'
                          }`}
                        >
                          {t === 'all' ? '全部' : t}
                        </button>
                      ))}
                    </div>
                    {/* 导出 */}
                    <button onClick={exportCSV}  className="chip border border-line bg-base-600/40 text-slate-400 text-xs hover:text-slate-200 transition-colors"><Download size={12} /> CSV</button>
                    <button onClick={exportJSON} className="chip border border-line bg-base-600/40 text-slate-400 text-xs hover:text-slate-200 transition-colors"><Download size={12} /> JSON</button>
                  </div>
                </header>

                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-line text-left">
                        <SortableTh label="类型"     col="type"    current={sortKey} dir={sortDir} onSort={toggleSort} className="w-[90px]" />
                        <SortableTh label="资产"     col="value"   current={sortKey} dir={sortDir} onSort={toggleSort} />
                        <SortableTh label="端口"     col="port"    current={sortKey} dir={sortDir} onSort={toggleSort} className="w-16 text-center" />
                        <SortableTh label="归属组织" col="org"     current={sortKey} dir={sortDir} onSort={toggleSort} />
                        <SortableTh label="来源"     col="source"  current={sortKey} dir={sortDir} onSort={toggleSort} className="w-28" />
                        <SortableTh label="发现时间" col="foundAt" current={sortKey} dir={sortDir} onSort={toggleSort} className="w-32" />
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {visibleRows.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-12 text-center">
                            <div className="space-y-2">
                              <p className="text-sm text-slate-500">无匹配结果</p>
                              <button
                                onClick={() => { setFilterType('all'); setFilterSrc('all'); setFilterQ('') }}
                                className="text-xs text-cyber underline underline-offset-2"
                              >
                                清除筛选
                              </button>
                            </div>
                          </td>
                        </tr>
                      ) : visibleRows.map((a, i) => {
                        const port = parsePort(a.meta)
                        return (
                          <tr key={`${a.source}:${a.type}:${a.value}:${i}`} className="group transition-colors hover:bg-base-600/20">
                            <td className="px-4 py-2">
                              <span className={`chip border text-xs ${TYPE_CLS[a.type] ?? 'border-line text-slate-400'}`}>
                                {a.type}
                              </span>
                            </td>
                            <td className="px-4 py-2 max-w-xs">
                              <div className="flex items-center gap-1.5 min-w-0">
                                <span className="font-mono text-xs text-slate-200 truncate" title={a.value}>
                                  {a.value}
                                </span>
                                <button
                                  onClick={() => copyValue(a.value)}
                                  className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                                  title="复制"
                                >
                                  {copied === a.value
                                    ? <CheckCircle2 size={12} className="text-emerald-400" />
                                    : <Copy size={12} className="text-slate-500 hover:text-slate-300 transition-colors" />
                                  }
                                </button>
                              </div>
                            </td>
                            <td className="px-4 py-2 text-center">
                              {port != null
                                ? <span className="font-mono text-xs text-slate-500">{port}</span>
                                : <span className="text-slate-700">—</span>
                              }
                            </td>
                            <td className="px-4 py-2 max-w-[160px] truncate text-xs text-slate-400" title={a.org}>
                              {a.org || '—'}
                            </td>
                            <td className="px-4 py-2">
                              <span className={`chip border text-xs ${SOURCE_CLS[a.source] ?? 'border-line text-slate-400'}`}>
                                {SOURCE_LABEL[a.source] ?? a.source}
                              </span>
                            </td>
                            <td className="whitespace-nowrap px-4 py-2 text-xs text-slate-500">
                              {a.foundAt ? a.foundAt.replace('T', ' ').slice(0, 16) : '—'}
                            </td>
                          </tr>
                        )
                      })}

                      {/* 截断提示 */}
                      {hiddenCount > 0 && (
                        <tr>
                          <td colSpan={6} className="px-4 py-3 text-center text-xs text-slate-600">
                            还有 <span className="text-slate-400 font-medium">{hiddenCount}</span> 条未显示，请使用过滤条件缩小范围
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}
        </div>
      )}

      {/* ━━ 标签页：情报源 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {tab === 'sources' && (
        <div className="space-y-4">
          <section className="panel">
            <header className="panel-head">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <Globe size={15} /> 网络测绘
              </div>
              <span className="text-xs text-slate-500">{configuredNet} / {NET_SOURCES.length} 已配置</span>
            </header>
            <div className="p-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {NET_SOURCES.map(s => (
                <SourceCard key={s.id} src={s} keys={keys} savedKeys={savedKeys} reveal={revealKeys} setKey={setKey} />
              ))}
            </div>
          </section>

          <section className="panel">
            <header className="panel-head">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <Building2 size={15} /> 企业情报
              </div>
              <div className="flex items-center gap-2">
                <span className="chip border border-line/40 bg-base-600/40 text-slate-600 text-[10px]">
                  company / keyword 模式生效
                </span>
                <span className="text-xs text-slate-500">{configuredBiz} / {BIZ_SOURCES.length} 已配置</span>
              </div>
            </header>
            <div className="p-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {BIZ_SOURCES.map(s => (
                <SourceCard key={s.id} src={s} keys={keys} savedKeys={savedKeys} reveal={revealKeys} setKey={setKey} />
              ))}
            </div>
          </section>

          <div className="flex flex-wrap items-center gap-4 rounded-xl border border-line/40 bg-base-700/20 px-4 py-3">
            <button
              onClick={saveApiKeys}
              disabled={savingKeys}
              className="flex items-center gap-2 rounded-lg border border-cyber/40 bg-cyber/10 px-4 py-2 text-xs font-semibold text-cyber transition-colors hover:bg-cyber/20 active:scale-95 disabled:opacity-50"
            >
              <Save size={13} />
              {savingKeys ? '保存中…' : '保存所有配置'}
            </button>
            <button
              onClick={() => setRevealKeys(v => !v)}
              className="flex items-center gap-1.5 rounded-lg border border-line/50 bg-base-700/40 px-3 py-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              {revealKeys ? <><EyeOff size={12} /> 隐藏明文</> : <><Eye size={12} /> 显示明文</>}
            </button>
            {saveMsg && (
              <span className={`text-xs ${saveMsg === '已保存' ? 'text-emerald-400' : 'text-sev-high'}`}>
                {saveMsg}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── loadFinished ──────────────────────────────────────────────────────────────

async function loadFinished(
  finished: TaskRecord,
  stoppedRef: { current: boolean },
  setResults: (r: CollectedAsset[]) => void,
  setErr: (e: string | null) => void,
  cap: string,
): Promise<CollectedAsset[]> {
  if (finished.status === 'succeeded') {
    try {
      const r = await engineGet<{ items: CollectedAsset[] }>(cap, `/findings?taskId=${finished.id}`)
      const items = r.items ?? []
      setResults(items); setErr(null)
      return items
    } catch {
      setErr('加载结果失败')
    }
  } else if (finished.status === 'failed' && !stoppedRef.current) {
    setErr(finished.error ?? '收集失败')
  }
  return []
}
