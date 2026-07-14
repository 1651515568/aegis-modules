import { useState, useEffect, useCallback, useRef, Fragment } from 'react'
import {
  FlaskConical, AlertTriangle, Play, Square, Trash2, Plus,
  ChevronDown, ChevronUp, X, CheckCircle, Clock, Wrench, ShieldOff,
  RefreshCw, Search, Database, BookOpen, ChevronRight,
  ExternalLink, Filter, Loader2,
} from 'lucide-react'
import { engineGet, enginePost, engineRequest } from '@/lib/engine'

const CAP = 'vuln-poc'
const POLL_MS = 2500

// ──────────── 类型 ────────────
type Status = 'unconfirmed' | 'confirmed' | 'fixing' | 'fixed'
type TabId = 'library' | 'entries'

interface RunResult {
  runAt: string; found: boolean; output: string
  curlCmd: string; request: string; response: string; errMsg: string
}
interface Entry {
  id: string; name: string; target: string; template: string
  severity: string; tags: string[]; status: Status; note: string
  runs: RunResult[]; createdAt: string; updatedAt: string
  sourceScan?: string; sourceHit?: string
}
interface ListResp { entries: Entry[]; total: number; stats: Record<string, number>; runningIds?: string[] }

interface TemplateInfo {
  id: string; name: string; severity: string; description?: string
  author?: string; tags: string[]; cveId?: string; filePath: string
  category: string; source: string
}
interface LibraryPage {
  items: TemplateInfo[]; total: number; page: number; pageSize: number
  indexed: boolean; progress: number
}
interface LibraryStats {
  total: number; bySeverity: Record<string, number>; byCategory: Record<string, number>
  bySource: Record<string, number>; indexed: boolean; progress: number
}

// ──────────── 配置 ────────────
const STATUS_CFG: Record<Status, { label: string; icon: React.ReactNode; cls: string; iconCls: string }> = {
  unconfirmed: { label: '待确认', icon: <Clock size={11} />,        cls: 'text-slate-400 bg-slate-400/10 border-slate-400/30',       iconCls: 'text-slate-400' },
  confirmed:   { label: '已确认', icon: <AlertTriangle size={11} />, cls: 'text-red-400 bg-red-400/10 border-red-400/30',            iconCls: 'text-red-400' },
  fixing:      { label: '修复中', icon: <Wrench size={11} />,        cls: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',   iconCls: 'text-yellow-400' },
  fixed:       { label: '已修复', icon: <CheckCircle size={11} />,   cls: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30', iconCls: 'text-emerald-400' },
}
const STATUS_FLOW: Status[] = ['unconfirmed', 'confirmed', 'fixing', 'fixed']

const SEV_CLS: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400',
  medium: 'text-yellow-400', low: 'text-blue-400', info: 'text-slate-400',
}
const SEV_BG: Record<string, string> = {
  critical: 'bg-red-500/10 border-red-500/30 text-red-400',
  high:     'bg-orange-500/10 border-orange-500/30 text-orange-400',
  medium:   'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  low:      'bg-blue-500/10 border-blue-500/30 text-blue-400',
  info:     'bg-slate-500/10 border-slate-500/30 text-slate-400',
}

function SevBadge({ s }: { s: string }) {
  return <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${SEV_BG[s] ?? SEV_BG.info}`}>{s || 'info'}</span>
}
function StatusBadge({ status }: { status: Status }) {
  const cfg = STATUS_CFG[status] ?? STATUS_CFG.unconfirmed
  return <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold ${cfg.cls}`}>{cfg.icon}{cfg.label}</span>
}

// ══════════════════════════════════════════════════════════════════
//  漏洞库视图
// ══════════════════════════════════════════════════════════════════
function LibraryView({ onRunEntry }: { onRunEntry: (entryId: string) => void }) {
  const [stats, setStats]       = useState<LibraryStats | null>(null)
  const [page, setPage]         = useState<LibraryPage | null>(null)
  const [loading, setLoading]   = useState(false)
  const [search, setSearch]     = useState('')
  const [severity, setSeverity] = useState('')
  const [category, setCategory] = useState('')
  const [source, setSource]     = useState('')
  const [curPage, setCurPage]   = useState(1)
  const [runTarget, setRunTarget] = useState('')
  const [runItem, setRunItem]   = useState<TemplateInfo | null>(null)
  const [runErr, setRunErr]     = useState('')
  const [runLoading, setRunLoading] = useState(false)
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const PAGE_SIZE = 50

  const fetchStats = useCallback(async () => {
    try {
      const s = await engineGet<LibraryStats>(CAP, '/library/stats')
      setStats(s)
    } catch {}
  }, [])

  const fetchPage = useCallback(async (pg: number, q?: string, sev?: string, cat?: string, src?: string) => {
    setLoading(true)
    try {
      const params: Record<string, string> = { page: String(pg), pageSize: String(PAGE_SIZE) }
      if (q)   params.search   = q
      if (sev) params.severity = sev
      if (cat) params.category = cat
      if (src) params.source   = src
      const p = await engineGet<LibraryPage>(CAP, '/library', params)
      setPage(p)
    } catch {
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchStats() }, [fetchStats])
  useEffect(() => {
    setCurPage(1)
    fetchPage(1, search, severity, category, source)
  }, [fetchPage, severity, category, source])

  // 搜索防抖
  function handleSearch(v: string) {
    setSearch(v)
    if (searchTimer.current) clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => {
      setCurPage(1)
      fetchPage(1, v, severity, category, source)
    }, 400)
  }

  function handlePageChange(p: number) {
    setCurPage(p)
    fetchPage(p, search, severity, category, source)
  }

  async function handleRun() {
    if (!runItem || !runTarget.trim()) return
    setRunLoading(true); setRunErr('')
    try {
      const r = await enginePost<{ entryId: string }>(CAP, '/library/run', {
        target: runTarget.trim(),
        filePath: runItem.filePath,
        name: runItem.name,
        severity: runItem.severity,
      })
      setRunItem(null); setRunTarget('')
      onRunEntry(r.entryId)
    } catch (e: unknown) {
      setRunErr(e instanceof Error ? e.message : '启动失败')
    } finally {
      setRunLoading(false)
    }
  }

  async function handleRebuild() {
    try {
      await enginePost(CAP, '/library/rebuild')
      setStats(s => s ? { ...s, indexed: false, progress: 0 } : s)
      // 每2秒刷新进度
      const timer = setInterval(async () => {
        await fetchStats()
        const s2 = await engineGet<LibraryStats>(CAP, '/library/stats').catch(() => null)
        if (s2?.indexed) { clearInterval(timer); fetchPage(1) }
      }, 2000)
    } catch {}
  }

  const indexed = stats?.indexed ?? page?.indexed ?? false
  const progress = stats?.progress ?? page?.progress ?? 0
  const totalTemplates = stats?.total ?? 0

  const severities = ['critical', 'high', 'medium', 'low', 'info']
  const categories = stats ? Object.entries(stats.byCategory).sort((a, b) => b[1] - a[1]) : []
  const totalPages = page ? Math.ceil(page.total / PAGE_SIZE) : 0

  return (
    <div className="space-y-4">

      {/* 索引进度条 */}
      {!indexed && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-4 py-3">
          <div className="flex items-center gap-2 mb-2">
            <Loader2 size={14} className="text-yellow-400 animate-spin" />
            <span className="text-xs text-yellow-300 font-medium">
              正在建立漏洞库索引… {progress}%（共 {totalTemplates.toLocaleString()} 个模板，约需 30~60 秒）
            </span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-base-700">
            <div className="h-full rounded-full bg-yellow-400 transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {/* 统计概览 */}
      {stats && (
        <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
          <div className="rounded-lg border border-line bg-base-800/60 px-3 py-2.5 col-span-3 sm:col-span-2">
            <div className="text-xl font-bold text-slate-100">{totalTemplates.toLocaleString()}</div>
            <div className="text-xs text-slate-500">模板总数</div>
          </div>
          {severities.map(s => (
            <button key={s} onClick={() => setSeverity(severity === s ? '' : s)}
              className={`rounded-lg border px-3 py-2.5 text-left transition ${severity === s ? 'border-current/30 bg-current/5' : 'border-line bg-base-800/60 hover:bg-base-700/60'} ${SEV_CLS[s]}`}>
              <div className="text-lg font-bold">{(stats.bySeverity[s] ?? 0).toLocaleString()}</div>
              <div className="text-[10px] uppercase font-semibold opacity-70">{s}</div>
            </button>
          ))}
        </div>
      )}

      <div className="flex gap-3">
        {/* 左侧：分类过滤 */}
        <div className="w-48 shrink-0 rounded-lg border border-line bg-base-800/60 p-2 h-fit">
          <div className="px-1 pb-1.5 text-[10px] font-semibold text-slate-500 uppercase tracking-wide">分类筛选</div>
          <button onClick={() => setCategory('')}
            className={`w-full text-left rounded px-2 py-1 text-xs transition mb-0.5 ${!category ? 'text-cyber bg-cyber/10' : 'text-slate-400 hover:text-slate-200 hover:bg-base-700/60'}`}>
            全部 <span className="text-slate-600">({totalTemplates.toLocaleString()})</span>
          </button>
          {categories.map(([cat, cnt]) => (
            <button key={cat} onClick={() => setCategory(category === cat ? '' : cat)}
              className={`w-full text-left rounded px-2 py-1 text-xs truncate transition mb-0.5 ${category === cat ? 'text-emerald-400 bg-emerald-400/10' : 'text-slate-400 hover:text-slate-200 hover:bg-base-700/60'}`}>
              {cat} <span className="text-slate-600">({cnt.toLocaleString()})</span>
            </button>
          ))}
          <div className="mt-2 pt-2 border-t border-line">
            <button onClick={() => setSource(source === '自定义' ? '' : '自定义')}
              className={`w-full text-left rounded px-2 py-1 text-xs transition mb-0.5 ${source === '自定义' ? 'text-emerald-400 bg-emerald-400/10' : 'text-slate-400 hover:text-slate-200 hover:bg-base-700/60'}`}>
              仅自定义 PoC
            </button>
            <button onClick={() => setSource(source === '官方' ? '' : '官方')}
              className={`w-full text-left rounded px-2 py-1 text-xs transition mb-0.5 ${source === '官方' ? 'text-cyber bg-cyber/10' : 'text-slate-400 hover:text-slate-200 hover:bg-base-700/60'}`}>
              仅官方模板
            </button>
            <button onClick={() => setSource(source === '解密POC' ? '' : '解密POC')}
              className={`w-full text-left rounded px-2 py-1 text-xs transition mb-0.5 ${source === '解密POC' ? 'text-violet-400 bg-violet-400/10' : 'text-slate-400 hover:text-slate-200 hover:bg-base-700/60'}`}>
              🔓 解密 POC 库 <span className='text-slate-600'>({(stats?.bySource?.['解密POC'] ?? 0).toLocaleString()})</span>
            </button>
          </div>
          <div className="mt-2 pt-2 border-t border-line">
            <button onClick={handleRebuild} className="w-full text-left rounded px-2 py-1 text-[10px] text-slate-600 hover:text-yellow-400 transition">
              重建索引
            </button>
          </div>
        </div>

        {/* 右侧：模板列表 */}
        <div className="flex-1 min-w-0">
          {/* 搜索栏 */}
          <div className="flex gap-2 mb-3">
            <div className="flex items-center gap-1.5 rounded-lg border border-line bg-base-700/60 px-2.5 py-1.5 flex-1">
              <Search size={13} className="text-slate-500 shrink-0" />
              <input value={search} onChange={e => handleSearch(e.target.value)}
                placeholder="搜索模板名称、CVE ID、标签…"
                className="bg-transparent text-xs text-slate-200 outline-none w-full" />
              {search && <button onClick={() => { setSearch(''); handleSearch('') }}><X size={12} className="text-slate-500" /></button>}
            </div>
            <button onClick={() => fetchPage(curPage, search, severity, category, source)}
              className="chip border border-line bg-base-600/60 text-slate-300 shrink-0">
              <RefreshCw size={13} />
            </button>
          </div>

          {/* 活动筛选标签 */}
          {(severity || category || source) && (
            <div className="flex flex-wrap gap-1.5 mb-2">
              {severity && <span className="inline-flex items-center gap-1 rounded border border-line bg-base-700/60 px-2 py-0.5 text-[10px] text-slate-400">
                严重度: {severity} <button onClick={() => setSeverity('')}><X size={9} /></button></span>}
              {category && <span className="inline-flex items-center gap-1 rounded border border-line bg-base-700/60 px-2 py-0.5 text-[10px] text-slate-400">
                分类: {category} <button onClick={() => setCategory('')}><X size={9} /></button></span>}
              {source && <span className="inline-flex items-center gap-1 rounded border border-line bg-base-700/60 px-2 py-0.5 text-[10px] text-slate-400">
                来源: {source} <button onClick={() => setSource('')}><X size={9} /></button></span>}
            </div>
          )}

          {/* 模板表格 */}
          <div className="rounded-lg border border-line bg-base-800/60 overflow-hidden">
            <div className="px-4 py-2 border-b border-line flex items-center gap-2">
              <Database size={13} className="text-emerald-400" />
              <span className="text-xs font-medium text-slate-300">
                {loading ? '加载中…' : `共 ${(page?.total ?? 0).toLocaleString()} 条结果`}
              </span>
              {loading && <Loader2 size={12} className="text-slate-500 animate-spin ml-1" />}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line text-left text-[10px] text-slate-500 uppercase tracking-wide">
                    <th className="px-4 py-2 font-medium">模板名称</th>
                    <th className="px-3 py-2 font-medium w-20">级别</th>
                    <th className="px-3 py-2 font-medium">分类/来源</th>
                    <th className="px-3 py-2 font-medium">标签/CVE</th>
                    <th className="px-3 py-2 font-medium w-20">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/50">
                  {!page?.items?.length && !loading && (
                    <tr><td colSpan={5} className="py-10 text-center text-sm text-slate-500">
                      {indexed ? '暂无结果' : '索引建立中，请稍候…'}
                    </td></tr>
                  )}
                  {(page?.items ?? []).map(t => (
                    <tr key={t.id} className="hover:bg-base-700/20 group">
                      <td className="px-4 py-2 max-w-60">
                        <div className="text-xs font-medium text-slate-200 truncate" title={t.name}>{t.name}</div>
                        <div className="font-mono text-[10px] text-slate-600 truncate" title={t.filePath}>
                          {t.filePath.split('/').slice(-2).join('/')}
                        </div>
                      </td>
                      <td className="px-3 py-2"><SevBadge s={t.severity} /></td>
                      <td className="px-3 py-2">
                        <div className="text-[10px] text-slate-400 truncate">{t.category}</div>
                        <div className={`text-[10px] ${t.source === '解密POC' ? 'text-violet-400' : t.source === '自定义' ? 'text-emerald-500' : 'text-cyan-500'}`}>{t.source}</div>
                      </td>
                      <td className="px-3 py-2 max-w-40">
                        {t.cveId && (
                          <div className="text-[10px] text-orange-400 font-mono mb-0.5">{t.cveId}</div>
                        )}
                        <div className="flex flex-wrap gap-0.5">
                          {(t.tags ?? []).slice(0, 4).map(tag => (
                            <span key={tag} className="rounded bg-base-700/80 px-1 py-0.5 text-[9px] text-slate-500">{tag}</span>
                          ))}
                          {(t.tags ?? []).length > 4 && (
                            <span className="text-[9px] text-slate-600">+{t.tags.length - 4}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <button
                          onClick={() => { setRunItem(t); setRunErr('') }}
                          className="chip border border-cyber/30 bg-cyber/5 text-cyber text-[10px] opacity-0 group-hover:opacity-100 transition-opacity">
                          <Play size={10} /> 验证
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* 分页 */}
            {totalPages > 1 && (
              <div className="border-t border-line px-4 py-2 flex items-center justify-between">
                <span className="text-[10px] text-slate-500">第 {curPage}/{totalPages} 页</span>
                <div className="flex gap-1">
                  <button disabled={curPage <= 1} onClick={() => handlePageChange(1)}
                    className="chip border border-line bg-base-700/40 text-slate-400 disabled:opacity-30 text-[10px]">首页</button>
                  <button disabled={curPage <= 1} onClick={() => handlePageChange(curPage - 1)}
                    className="chip border border-line bg-base-700/40 text-slate-400 disabled:opacity-30 text-[10px]">上一页</button>
                  <button disabled={curPage >= totalPages} onClick={() => handlePageChange(curPage + 1)}
                    className="chip border border-line bg-base-700/40 text-slate-400 disabled:opacity-30 text-[10px]">下一页</button>
                  <button disabled={curPage >= totalPages} onClick={() => handlePageChange(totalPages)}
                    className="chip border border-line bg-base-700/40 text-slate-400 disabled:opacity-30 text-[10px]">末页</button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 运行目标对话框 */}
      {runItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-[480px] rounded-xl border border-line bg-base-800 shadow-2xl">
            <div className="flex items-center justify-between border-b border-line px-5 py-3">
              <span className="text-sm font-medium text-slate-200">验证模板</span>
              <button onClick={() => { setRunItem(null); setRunErr('') }} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
            </div>
            <div className="p-5 space-y-3">
              <div className="rounded-lg border border-line bg-base-700/40 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <SevBadge s={runItem.severity} />
                  <span className="text-sm font-medium text-slate-200">{runItem.name}</span>
                </div>
                <div className="font-mono text-[10px] text-slate-500">{runItem.filePath}</div>
              </div>
              <div>
                <label className="mb-1 block text-xs text-slate-400">目标 URL / IP *</label>
                <input value={runTarget} onChange={e => setRunTarget(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleRun()}
                  placeholder="http://192.168.1.100:8080"
                  autoFocus
                  className="w-full rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
              </div>
              {runErr && <div className="text-xs text-red-400">{runErr}</div>}
            </div>
            <div className="flex justify-end gap-2 border-t border-line px-5 py-3">
              <button onClick={() => { setRunItem(null); setRunErr('') }}
                className="chip border border-line bg-base-700/40 text-slate-300">取消</button>
              <button onClick={handleRun} disabled={!runTarget.trim() || runLoading}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber disabled:opacity-40">
                {runLoading ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
                开始验证
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ──────────── PoC 条目新建/编辑对话框 ────────────
function EntryDialog({ initial, onSave, onClose }: {
  initial?: Partial<Entry>; onSave: (e: Partial<Entry>) => void; onClose: () => void
}) {
  const [name, setName]         = useState(initial?.name ?? '')
  const [target, setTarget]     = useState(initial?.target ?? '')
  const [template, setTemplate] = useState(initial?.template ?? '')
  const [severity, setSeverity] = useState(initial?.severity ?? 'high')
  const [note, setNote]         = useState(initial?.note ?? '')
  const [suggestions, setSugg]  = useState<string[]>([])
  const [tmplSearch, setTmplSearch] = useState(template)
  const tmplTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  function handleTmplInput(v: string) {
    setTmplSearch(v); setTemplate(v)
    if (tmplTimer.current) clearTimeout(tmplTimer.current)
    if (v.length < 2) { setSugg([]); return }
    tmplTimer.current = setTimeout(async () => {
      try {
        const r = await engineGet<{ templates: string[] }>(CAP, '/search/template', { q: v, limit: 15 })
        setSugg(r.templates ?? [])
      } catch { setSugg([]) }
    }, 300)
  }

  function submit() {
    if (!target.trim() || !template.trim()) return
    onSave({ name: name || template, target, template, severity, note })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-[520px] rounded-xl border border-line bg-base-800 shadow-2xl">
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <span className="text-sm font-medium text-slate-200">{initial?.id ? '编辑条目' : '新建 PoC 条目'}</span>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
        </div>
        <div className="space-y-3 p-5">
          <div>
            <label className="mb-1 block text-xs text-slate-400">目标 URL / IP *</label>
            <input value={target} onChange={e => setTarget(e.target.value)}
              placeholder="http://192.168.1.100:8080"
              className="w-full rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
          </div>
          <div className="relative">
            <label className="mb-1 block text-xs text-slate-400">模板路径 / 关键词 *</label>
            <input value={tmplSearch} onChange={e => handleTmplInput(e.target.value)}
              placeholder="http/cves/2021/CVE-2021-44228.yaml 或输入关键词搜索"
              className="w-full rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
            {suggestions.length > 0 && (
              <div className="absolute z-10 w-full rounded-lg border border-line bg-base-700 shadow-xl mt-0.5 max-h-48 overflow-y-auto">
                {suggestions.map(s => (
                  <button key={s} onClick={() => { setTemplate(s); setTmplSearch(s); setSugg([]) }}
                    className="w-full text-left px-3 py-1.5 font-mono text-[10px] text-slate-300 hover:bg-base-600/60 truncate">{s}</button>
                ))}
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs text-slate-400">名称（可选）</label>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder="CVE-2021-44228 Log4Shell"
                className="w-full rounded border border-line bg-base-700/60 px-3 py-2 text-xs text-slate-200 outline-none focus:border-cyber" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-400">严重度</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="w-full rounded border border-line bg-base-700/60 px-2 py-2 text-xs text-slate-200 outline-none focus:border-cyber">
                {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">备注</label>
            <textarea value={note} onChange={e => setNote(e.target.value)} rows={2}
              className="w-full resize-none rounded border border-line bg-base-700/60 px-3 py-2 text-xs text-slate-200 outline-none focus:border-cyber" />
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-line px-5 py-3">
          <button onClick={onClose} className="chip border border-line bg-base-700/40 text-slate-300">取消</button>
          <button onClick={submit} className="chip border border-cyber/40 bg-cyber/10 text-cyber">
            {initial?.id ? '保存' : '创建'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ══════════════════════════════════════════════════════════════════
//  PoC 条目视图
// ══════════════════════════════════════════════════════════════════
function EntriesView() {
  const [entries, setEntries]   = useState<Entry[]>([])
  const [stats, setStats]       = useState<Record<string, number>>({})
  const [running, setRunning]   = useState<Set<string>>(new Set())
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [expandedId, setExpanded] = useState<string | null>(null)
  const [search, setSearch]     = useState('')
  const [statusF, setStatusF]   = useState<string>('')
  const [showDialog, setDialog] = useState(false)
  const [editEntry, setEdit]    = useState<Entry | null>(null)
  const [err, setErr]           = useState<string | null>(null)

  const fetchEntries = useCallback(async () => {
    try {
      const q: Record<string, string> = {}
      if (statusF) q.status = statusF
      if (search) q.search = search
      const r = await engineGet<ListResp>(CAP, '/entries', q)
      setEntries(r.entries ?? [])
      setStats(r.stats ?? {})
      setRunning(new Set(r.runningIds ?? []))
    } catch {}
  }, [statusF, search])

  useEffect(() => { fetchEntries() }, [fetchEntries])

  const isPolling = running.size > 0
  useEffect(() => {
    if (!isPolling) return
    const timer = setInterval(fetchEntries, POLL_MS)
    return () => clearInterval(timer)
  }, [isPolling, fetchEntries])

  async function handleCreate(data: Partial<Entry>) {
    try {
      await enginePost(CAP, '/entries', data)
      setDialog(false)
      await fetchEntries()
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '创建失败') }
  }
  async function handleUpdate(id: string, data: Partial<Entry>) {
    try {
      await engineRequest(CAP, `/entry?id=${id}`, { method: 'PUT', body: JSON.stringify(data) })
      setEdit(null)
      await fetchEntries()
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '更新失败') }
  }
  async function handleDelete(id: string) {
    try {
      await engineRequest(CAP, `/entry?id=${id}`, { method: 'DELETE' })
      setEntries(prev => prev.filter(e => e.id !== id))
    } catch {}
  }
  async function handleRun(id: string) {
    try {
      await enginePost(CAP, `/entry/run?id=${id}`)
      setRunning(prev => new Set([...prev, id]))
    } catch (e: unknown) { setErr(e instanceof Error ? e.message : '启动失败') }
  }
  async function handleStop(id: string) {
    try {
      await enginePost(CAP, `/entry/stop?id=${id}`)
      setRunning(prev => { const n = new Set(prev); n.delete(id); return n })
    } catch {}
  }
  function toggleSelect(id: string) {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }
  function toggleSelectAll() {
    setSelectedIds(prev => prev.size === entries.length ? new Set() : new Set(entries.map(e => e.id)))
  }
  async function handleBulkDelete() {
    if (!window.confirm(`确认删除选中的 ${selectedIds.size} 条条目？`)) return
    await Promise.all([...selectedIds].map(id => handleDelete(id)))
    setSelectedIds(new Set())
  }
  async function handleBulkRun() {
    const ids = [...selectedIds].filter(id => !running.has(id))
    for (const id of ids) await handleRun(id)
    setSelectedIds(new Set())
  }
  async function handleSetStatus(id: string, status: Status) {
    try {
      await enginePost(CAP, `/entry/status?id=${id}`, { status })
      setEntries(prev => prev.map(e => e.id === id ? { ...e, status } : e))
    } catch {}
  }

  const total = entries.length

  return (
    <div className="space-y-4">
      {/* 统计卡 */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(Object.keys(STATUS_CFG) as Status[]).map(s => (
          <button key={s} onClick={() => setStatusF(statusF === s ? '' : s)}
            className={`flex items-center gap-3 rounded-lg border px-4 py-3 text-left transition ${statusF === s ? 'border-cyber/40 bg-cyber/5' : 'border-line bg-base-700/50 hover:bg-base-700/80'}`}>
            <span className={STATUS_CFG[s].iconCls}>{STATUS_CFG[s].icon}</span>
            <div>
              <div className="text-lg font-bold text-slate-100">{stats[s] ?? 0}</div>
              <div className="text-xs text-slate-500">{STATUS_CFG[s].label}</div>
            </div>
          </button>
        ))}
      </div>

      {/* 工具栏 */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-line bg-base-700/60 px-2.5 py-1.5 flex-1 min-w-40">
          <Search size={13} className="text-slate-500 shrink-0" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="搜索目标/模板/名称…"
            className="bg-transparent text-xs text-slate-200 outline-none w-full" />
        </div>
        <button onClick={() => fetchEntries()}
          className="chip border border-line bg-base-600/60 text-slate-300">
          <RefreshCw size={13} /> 刷新
        </button>
        {selectedIds.size > 0 && (
          <>
            <button onClick={handleBulkRun}
              className="chip border border-cyber/30 bg-cyber/5 text-cyber text-[10px]">
              <Play size={11} /> 批量验证 ({selectedIds.size})
            </button>
            <button onClick={handleBulkDelete}
              className="chip border border-red-500/30 bg-red-500/5 text-red-400 text-[10px]">
              <Trash2 size={11} /> 批量删除 ({selectedIds.size})
            </button>
          </>
        )}
        <button onClick={() => { setEdit(null); setDialog(true) }}
          className="chip border border-cyber/40 bg-cyber/10 text-cyber">
          <Plus size={13} /> 新建条目
        </button>
      </div>

      {err && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          <AlertTriangle size={12} /><span>{err}</span>
          <button onClick={() => setErr(null)} className="ml-auto"><X size={12} /></button>
        </div>
      )}

      {/* 条目列表 */}
      <div className="rounded-lg border border-line bg-base-800/60">
        <div className="border-b border-line px-4 py-2.5 flex items-center gap-2">
          <FlaskConical size={14} className="text-cyber" />
          <span className="text-sm font-medium text-slate-200">条目列表 ({total})</span>
          {statusF && (
            <span className="ml-2 text-[10px] rounded border border-line bg-base-700/60 px-1.5 py-0.5 text-slate-400">
              筛选: {STATUS_CFG[statusF as Status]?.label}
              <button onClick={() => setStatusF('')} className="ml-1 hover:text-red-400"><X size={9} /></button>
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-slate-500">
                <th className="px-3 py-2 w-8">
                  <input type="checkbox"
                    checked={entries.length > 0 && selectedIds.size === entries.length}
                    onChange={toggleSelectAll} className="rounded accent-cyber" />
                </th>
                <th className="px-4 py-2 font-medium">状态</th>
                <th className="px-4 py-2 font-medium">名称 / 模板</th>
                <th className="px-4 py-2 font-medium">目标</th>
                <th className="px-4 py-2 font-medium">最近结果</th>
                <th className="px-4 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {entries.length === 0 && (
                <tr><td colSpan={6} className="p-8 text-center text-sm text-slate-500">
                  暂无条目，可从「漏洞库」选模板并验证，或点击「新建条目」手动添加
                </td></tr>
              )}
              {entries.map(e => {
                const isRunning = running.has(e.id)
                const lastRun = e.runs?.length ? e.runs[e.runs.length - 1] : null
                const isExpanded = expandedId === e.id
                return (
                  <Fragment key={e.id}>
                    <tr className="hover:bg-base-600/20">
                      <td className="px-3 py-2.5">
                        <input type="checkbox" checked={selectedIds.has(e.id)}
                          onChange={() => toggleSelect(e.id)} className="rounded accent-cyber" />
                      </td>
                      <td className="px-4 py-2.5"><StatusBadge status={e.status} /></td>
                      <td className="px-4 py-2.5 max-w-48">
                        <div className={`text-xs font-medium truncate ${SEV_CLS[e.severity] ?? 'text-slate-200'}`}>
                          {e.name || e.template.split('/').pop()}
                        </div>
                        <div className="font-mono text-[10px] text-slate-600 truncate">{e.template}</div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-cyber text-xs max-w-36 truncate">{e.target}</td>
                      <td className="px-4 py-2.5">
                        {isRunning ? (
                          <span className="flex items-center gap-1 text-[10px] text-cyber">
                            <span className="h-1.5 w-1.5 rounded-full bg-cyber animate-pulse" /> 验证中…
                          </span>
                        ) : lastRun ? (
                          <span className={`text-[10px] font-medium ${lastRun.found ? 'text-red-400' : 'text-slate-500'}`}>
                            {lastRun.found ? '✓ 存在' : '✗ 未命中'}
                            {lastRun.errMsg ? ` (${lastRun.errMsg.slice(0, 20)})` : ''}
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-600">未运行</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          {isRunning ? (
                            <button onClick={() => handleStop(e.id)}
                              className="chip border border-sev-high/30 bg-sev-high/5 text-sev-high text-[10px]">
                              <Square size={10} /> 停止
                            </button>
                          ) : (
                            <button onClick={() => handleRun(e.id)}
                              className="chip border border-cyber/30 bg-cyber/5 text-cyber text-[10px]">
                              <Play size={10} /> 验证
                            </button>
                          )}
                          <select value={e.status}
                            onChange={ev => handleSetStatus(e.id, ev.target.value as Status)}
                            className="rounded border border-line bg-base-700/60 px-1 py-0.5 text-[10px] text-slate-300 outline-none focus:border-cyber">
                            {STATUS_FLOW.map(s => <option key={s} value={s}>{STATUS_CFG[s].label}</option>)}
                          </select>
                          <button onClick={() => setExpanded(isExpanded ? null : e.id)}
                            className="text-slate-500 hover:text-slate-300">
                            {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                          </button>
                          <button onClick={() => { setEdit(e); setDialog(true) }}
                            className="text-slate-500 hover:text-cyber text-[10px]">编辑</button>
                          <button onClick={() => handleDelete(e.id)}
                            className="text-slate-600 hover:text-red-400">
                            <Trash2 size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-base-900/40">
                        <td colSpan={6} className="px-5 pb-3 pt-1">
                          {e.note && <div className="mb-2 text-xs text-slate-400 italic">{e.note}</div>}
                          {(!e.runs || e.runs.length === 0) ? (
                            <div className="text-xs text-slate-600">暂无运行记录</div>
                          ) : (
                            <div className="space-y-2">
                              <div className="text-[10px] text-slate-500 mb-1">运行历史（最近 {e.runs.length} 次）</div>
                              {[...e.runs].reverse().map((run, i) => (
                                <div key={i} className={`rounded border p-2 text-xs ${run.found ? 'border-red-500/30 bg-red-500/5' : 'border-line bg-base-800/40'}`}>
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className={run.found ? 'text-red-400 font-medium' : 'text-slate-500'}>
                                      {run.found ? '✓ 命中' : '✗ 未命中'}
                                    </span>
                                    <span className="text-slate-600">{new Date(run.runAt).toLocaleString('zh-CN')}</span>
                                    {run.errMsg && <span className="text-yellow-400">{run.errMsg}</span>}
                                  </div>
                                  {run.output && <div className="text-slate-300 mb-1">{run.output}</div>}
                                  {run.curlCmd && (
                                    <details>
                                      <summary className="cursor-pointer text-cyber/70 hover:text-cyber text-[10px]">curl 命令</summary>
                                      <pre className="mt-1 overflow-x-auto rounded bg-base-700/60 p-2 font-mono text-[10px] text-slate-300 whitespace-pre-wrap">{run.curlCmd}</pre>
                                    </details>
                                  )}
                                  {run.request && (
                                    <details>
                                      <summary className="cursor-pointer text-slate-500 hover:text-slate-300 text-[10px]">请求</summary>
                                      <pre className="mt-1 max-h-32 overflow-auto rounded bg-base-700/60 p-2 font-mono text-[10px] text-slate-400 whitespace-pre-wrap">{run.request}</pre>
                                    </details>
                                  )}
                                  {run.response && (
                                    <details>
                                      <summary className="cursor-pointer text-slate-500 hover:text-slate-300 text-[10px]">响应</summary>
                                      <pre className="mt-1 max-h-32 overflow-auto rounded bg-base-700/60 p-2 font-mono text-[10px] text-slate-400 whitespace-pre-wrap">{run.response}</pre>
                                    </details>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {showDialog && (
        <EntryDialog
          initial={editEntry ?? undefined}
          onSave={editEntry ? (data) => handleUpdate(editEntry.id, data) : handleCreate}
          onClose={() => { setDialog(false); setEdit(null) }}
        />
      )}
    </div>
  )
}

// ══════════════════════════════════════════════════════════════════
//  主组件 — 双标签
// ══════════════════════════════════════════════════════════════════
export default function VulnPocView() {
  const [tab, setTab] = useState<TabId>('library')
  const [jumpToEntries, setJumpToEntries] = useState(false)

  function handleRunEntry(_entryId: string) {
    // 切换到 PoC条目 标签查看进度
    setTab('entries')
    setJumpToEntries(true)
  }

  useEffect(() => {
    if (jumpToEntries) setJumpToEntries(false)
  }, [jumpToEntries])

  return (
    <div className="space-y-4 animate-fade-in">
      {/* 标签切换 */}
      <div className="flex items-center gap-1 rounded-lg border border-line bg-base-800/60 p-1 w-fit">
        <button onClick={() => setTab('library')}
          className={`flex items-center gap-1.5 rounded px-4 py-2 text-sm font-medium transition ${tab === 'library' ? 'bg-base-700 text-emerald-400 shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}>
          <Database size={14} /> 漏洞库
        </button>
        <button onClick={() => setTab('entries')}
          className={`flex items-center gap-1.5 rounded px-4 py-2 text-sm font-medium transition ${tab === 'entries' ? 'bg-base-700 text-cyber shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}>
          <FlaskConical size={14} /> PoC 验证
        </button>
      </div>

      {tab === 'library' && <LibraryView onRunEntry={handleRunEntry} />}
      {tab === 'entries' && <EntriesView />}
    </div>
  )
}
