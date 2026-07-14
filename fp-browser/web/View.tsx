import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Search, Fingerprint, Tag, ChevronLeft, ChevronRight,
  SlidersHorizontal, Hash, ChevronDown, ChevronUp, Shield, AlertTriangle,
} from 'lucide-react'
import { engineGet } from '@/lib/engine'

const CAP = 'fp-browser'

interface Matcher {
  type: string
  keywords?: string[]
  status?: number
  favicon?: string[]
}
interface Probe {
  path: string
  method: string
  matchers: Matcher[]
}
interface FPRule {
  name: string
  category: string
  tags: string[]
  priority: number
  probes: Probe[]
}
interface FPItem {
  name: string
  category: string
  tags: string[]
  favCount: number
  probeCount: number
  priority: number
}
interface FPPage {
  total: number
  page: number
  pageSize: number
  items: FPItem[]
}
interface Category {
  name: string
  count: number
}

const CAT_COLOR: Record<string, string> = {
  '1-网站CMS':  'bg-violet-500/20 text-violet-300 border-violet-500/30',
  '2-办公OA':   'bg-blue-500/20 text-blue-300 border-blue-500/30',
  '3-框架组件':  'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  '4-应用服务':  'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  '5-网络设备':  'bg-amber-500/20 text-amber-300 border-amber-500/30',
  '6-安全设备':  'bg-red-500/20 text-red-300 border-red-500/30',
  '7-安防监控':  'bg-orange-500/20 text-orange-300 border-orange-500/30',
  '8-其他PoC':  'bg-slate-500/20 text-slate-300 border-slate-500/30',
  '9-工控系统':  'bg-rose-500/20 text-rose-300 border-rose-500/30',
  '10-教育医疗': 'bg-teal-500/20 text-teal-300 border-teal-500/30',
  '11-金融行业': 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
}
function catColor(cat: string) {
  return CAT_COLOR[cat] ?? 'bg-slate-500/20 text-slate-300 border-slate-500/30'
}

const MATCH_COLOR: Record<string, string> = {
  favicon: 'bg-amber-500/20 text-amber-300',
  body:    'bg-emerald-500/20 text-emerald-300',
  title:   'bg-blue-500/20 text-blue-300',
  header:  'bg-purple-500/20 text-purple-300',
  status:  'bg-slate-500/20 text-slate-400',
}

const PRIORITY_LABEL: Record<number, { label: string; cls: string }> = {
  1: { label: '高', cls: 'text-red-400 bg-red-500/10 border-red-500/30' },
  2: { label: '中', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  3: { label: '低', cls: 'text-slate-400 bg-slate-500/10 border-slate-500/30' },
}

// ── 探针详情组件 ─────────────────────────────────────────────────────────────

function ProbeDetail({ rule }: { rule: FPRule }) {
  const p = PRIORITY_LABEL[rule.priority] ?? PRIORITY_LABEL[3]
  return (
    <div className="space-y-2 py-1">
      <div className="flex items-center gap-2 mb-3">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${p.cls}`}>
          优先级{p.label}
        </span>
        <span className="text-xs text-slate-500">{rule.probes.length} 个探针</span>
        {rule.tags.map(t => (
          <span key={t} className="rounded bg-base-700 px-1.5 py-0.5 text-[10px] text-slate-400">{t}</span>
        ))}
      </div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {rule.probes.map((probe, i) => (
          <div key={i} className="rounded-lg border border-base-600 bg-base-900 p-2.5 text-xs">
            <div className="flex items-center gap-1.5 mb-2">
              <span className="rounded bg-cyber/10 border border-cyber/30 px-1.5 py-0.5 text-[10px] font-mono text-cyber">
                {probe.method}
              </span>
              <span className="font-mono text-slate-300 break-all">{probe.path}</span>
            </div>
            <div className="space-y-1">
              {(probe.matchers ?? []).map((m, j) => (
                <div key={j} className="flex flex-wrap items-start gap-1">
                  <span className={`shrink-0 rounded px-1 py-0.5 text-[10px] font-medium ${MATCH_COLOR[m.type] ?? 'bg-slate-700 text-slate-400'}`}>
                    {m.type}
                  </span>
                  {m.type === 'status' && (
                    <span className="font-mono text-slate-400">{m.status}</span>
                  )}
                  {m.keywords?.map(k => (
                    <span key={k} className="rounded bg-base-700 px-1 py-0.5 font-mono text-[10px] text-slate-300 break-all">{k}</span>
                  ))}
                  {m.favicon?.map(h => (
                    <span key={h} className="rounded bg-amber-500/10 border border-amber-500/20 px-1 py-0.5 font-mono text-[10px] text-amber-300">{h}</span>
                  ))}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── 主视图 ────────────────────────────────────────────────────────────────────

export default function FpBrowserView() {
  const [search, setSearch]         = useState('')
  const [category, setCategory]     = useState('')
  const [hasFav, setHasFav]         = useState(false)
  const [weakOnly, setWeakOnly]     = useState(false)
  const [priority, setPriority]     = useState('')
  const [page, setPage]             = useState(1)
  const [data, setData]             = useState<FPPage | null>(null)
  const [categories, setCategories] = useState<Category[]>([])
  const [favTotal, setFavTotal]     = useState<number | null>(null)
  const [totalAll, setTotalAll]     = useState<number | null>(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState('')
  const [expandedName, setExpandedName] = useState<string | null>(null)
  const [detailCache, setDetailCache]   = useState<Record<string, FPRule>>({})
  const [detailLoading, setDetailLoading] = useState<string | null>(null)
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  // 初始化：分类 + favicon总数 + 全库总数
  useEffect(() => {
    engineGet<{ categories: Category[] }>(CAP, '/fingerprints/categories')
      .then(r => setCategories(r.categories ?? []))
      .catch(() => {})
    engineGet<{ total: number }>(CAP, '/fingerprints?hasFav=true&pageSize=1')
      .then(r => setFavTotal(r.total))
      .catch(() => {})
    engineGet<{ total: number }>(CAP, '/fingerprints?pageSize=1')
      .then(r => setTotalAll(r.total))
      .catch(() => {})
  }, [])

  const doFetch = useCallback((s: string, cat: string, fav: boolean, weak: boolean, pri: string, pg: number) => {
    setLoading(true)
    setError('')
    const params = new URLSearchParams({
      search: s, category: cat,
      hasFav: fav ? 'true' : 'false',
      weak: weak ? 'true' : 'false',
      priority: pri,
      page: String(pg), pageSize: '50',
    })
    engineGet<FPPage>(CAP, `/fingerprints?${params}`)
      .then(r => { setData(r); setLoading(false) })
      .catch(e => { setError(String(e)); setLoading(false) })
  }, [])

  // 搜索/过滤变化 → 防抖重置到第 1 页
  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current)
    debounce.current = setTimeout(() => {
      setPage(1)
      doFetch(search, category, hasFav, weakOnly, priority, 1)
    }, 300)
    return () => { if (debounce.current) clearTimeout(debounce.current) }
  }, [search, category, hasFav, weakOnly, priority, doFetch])

  // 翻页
  useEffect(() => { doFetch(search, category, hasFav, weakOnly, priority, page) }, [page]) // eslint-disable-line

  // 点击行展开/折叠详情
  const handleRowClick = async (name: string) => {
    if (expandedName === name) { setExpandedName(null); return }
    setExpandedName(name)
    if (detailCache[name]) return
    setDetailLoading(name)
    try {
      const rule = await engineGet<FPRule>(CAP, `/fingerprints/detail?name=${encodeURIComponent(name)}`)
      setDetailCache(prev => ({ ...prev, [name]: rule }))
    } catch { /* ignore */ }
    finally { setDetailLoading(null) }
  }

  // 点击标签快捷搜索
  const handleTagClick = (tag: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setSearch(tag)
    setPage(1)
  }

  const totalPages = data ? Math.ceil(data.total / data.pageSize) : 0

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* 统计卡 */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: '全库指纹', value: totalAll ?? '—', icon: Fingerprint, color: 'text-cyber' },
          { label: '当前筛选', value: data?.total ?? '—', icon: SlidersHorizontal, color: 'text-violet-400' },
          { label: '产品分类', value: categories.length || '—', icon: Tag, color: 'text-emerald-400' },
          { label: '含 favicon hash', value: favTotal ?? '—', icon: Hash, color: 'text-amber-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg border border-base-600 bg-base-800 p-3">
            <div className="flex items-center gap-2">
              <Icon size={14} className={color} />
              <span className="text-xs text-slate-400">{label}</span>
            </div>
            <div className={`mt-1 text-xl font-bold ${color}`}>{value}</div>
          </div>
        ))}
      </div>

      {/* 过滤栏 */}
      <div className="flex flex-wrap items-center gap-2">
        {/* 搜索框 */}
        <div className="relative flex-1 min-w-52">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="搜索产品名称或标签…"
            className="w-full rounded-lg border border-base-600 bg-base-800 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyber/60"
          />
        </div>

        {/* 分类 */}
        <select
          value={category}
          onChange={e => setCategory(e.target.value)}
          className="rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyber/60"
        >
          <option value="">全部分类</option>
          {categories.map(c => (
            <option key={c.name} value={c.name}>{c.name} ({c.count})</option>
          ))}
        </select>

        {/* 优先级 */}
        <select
          value={priority}
          onChange={e => setPriority(e.target.value)}
          className="rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyber/60"
        >
          <option value="">全部优先级</option>
          <option value="1">高优先级</option>
          <option value="2">中优先级</option>
          <option value="3">低优先级</option>
        </select>

        {/* 复选框组 */}
        <div className="flex items-center gap-3">
          <label className="flex cursor-pointer items-center gap-1.5 rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-sm text-slate-300 select-none">
            <input type="checkbox" checked={hasFav} onChange={e => { setHasFav(e.target.checked); if (e.target.checked) setWeakOnly(false) }} className="accent-amber-400" />
            <Hash size={12} className="text-amber-400" /> 有 favicon
          </label>
          <label className="flex cursor-pointer items-center gap-1.5 rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-sm text-slate-300 select-none">
            <input type="checkbox" checked={weakOnly} onChange={e => { setWeakOnly(e.target.checked); if (e.target.checked) setHasFav(false) }} className="accent-red-400" />
            <AlertTriangle size={12} className="text-red-400" /> 弱覆盖
          </label>
        </div>
      </div>

      {/* 结果表格 */}
      <div className="rounded-lg border border-base-600 bg-base-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-base-600 bg-base-700/50">
                <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-400 w-6"></th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-400 w-8">#</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">产品名称</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">分类</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">标签 <span className="text-slate-600 font-normal">（可点击）</span></th>
                <th className="px-4 py-2.5 text-right text-xs font-medium text-slate-400">探针</th>
                <th className="px-4 py-2.5 text-right text-xs font-medium text-slate-400">favicon</th>
                <th className="px-4 py-2.5 text-center text-xs font-medium text-slate-400">优先级</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={8} className="py-12 text-center text-slate-500">加载中…</td></tr>
              )}
              {!loading && error && (
                <tr><td colSpan={8} className="py-12 text-center text-red-400">{error}</td></tr>
              )}
              {!loading && !error && data?.items.length === 0 && (
                <tr><td colSpan={8} className="py-12 text-center text-slate-500">无匹配结果</td></tr>
              )}
              {!loading && !error && data?.items.map((item, idx) => {
                const rowNum = (data.page - 1) * data.pageSize + idx + 1
                const isExpanded = expandedName === item.name
                const isWeak = item.probeCount <= 1 && item.favCount === 0
                const p = PRIORITY_LABEL[item.priority] ?? PRIORITY_LABEL[3]
                return (
                  <>
                    <tr
                      key={item.name}
                      onClick={() => handleRowClick(item.name)}
                      className={`border-b border-base-700/50 cursor-pointer transition-colors ${
                        isExpanded ? 'bg-base-700/40' : 'hover:bg-base-700/30'
                      }`}
                    >
                      <td className="px-3 py-2.5 text-slate-500">
                        {isExpanded
                          ? <ChevronUp size={13} />
                          : <ChevronDown size={13} />
                        }
                      </td>
                      <td className="px-4 py-2.5 text-slate-600 text-xs">{rowNum}</td>
                      <td className="px-4 py-2.5 font-medium text-slate-200">
                        <div className="flex items-center gap-1.5">
                          {isWeak && <span title="弱覆盖：单探针且无favicon"><AlertTriangle size={11} className="text-red-500 shrink-0" /></span>}
                          {item.name}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${catColor(item.category)}`}>
                          {item.category}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {(item.tags ?? []).slice(0, 5).map(t => (
                            <span
                              key={t}
                              onClick={e => handleTagClick(t, e)}
                              className="rounded bg-base-700 px-1.5 py-0.5 text-[10px] text-slate-400 cursor-pointer hover:bg-cyber/20 hover:text-cyber transition-colors"
                              title={`搜索标签: ${t}`}
                            >
                              {t}
                            </span>
                          ))}
                          {(item.tags ?? []).length > 5 && (
                            <span className="text-[10px] text-slate-600">+{item.tags.length - 5}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-right text-slate-400">{item.probeCount}</td>
                      <td className="px-4 py-2.5 text-right">
                        {item.favCount > 0
                          ? <span className="font-mono text-xs text-amber-400">{item.favCount}</span>
                          : <span className="text-slate-600">—</span>
                        }
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${p.cls}`}>
                          {p.label}
                        </span>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${item.name}-detail`} className="border-b border-base-700/50 bg-base-900/60">
                        <td colSpan={8} className="px-4 pt-2 pb-3">
                          {detailLoading === item.name && (
                            <span className="text-xs text-slate-500">加载详情…</span>
                          )}
                          {detailCache[item.name] && (
                            <ProbeDetail rule={detailCache[item.name]} />
                          )}
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* 分页 */}
        {data && totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-base-600 px-4 py-2.5">
            <span className="text-xs text-slate-500">
              共 {data.total} 条，第 {data.page}/{totalPages} 页
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="rounded p-1 text-slate-400 hover:bg-base-700 disabled:opacity-30"
              >
                <ChevronLeft size={16} />
              </button>
              {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                let p = page - 3 + i
                if (p < 1) p = i + 1
                if (p > totalPages) p = totalPages - (6 - i)
                if (p < 1 || p > totalPages) return null
                return (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`min-w-[28px] rounded px-1.5 py-0.5 text-xs ${
                      p === page
                        ? 'bg-cyber/20 text-cyber border border-cyber/40'
                        : 'text-slate-400 hover:bg-base-700'
                    }`}
                  >
                    {p}
                  </button>
                )
              })}
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="rounded p-1 text-slate-400 hover:bg-base-700 disabled:opacity-30"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
