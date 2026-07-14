import { useEffect, useState, useMemo } from 'react'
import {
  ShieldAlert, Search, ChevronDown, ChevronRight, ChevronLeft,
  Tag, Zap, Loader2, CheckCircle2, XCircle, Copy, TerminalSquare, X,
} from 'lucide-react'
import { engineGet, enginePost } from '@/lib/engine'

const CAP = 'xc-vuln'
const PAGE_SIZE = 50

interface XCTemplate {
  id: string
  name: string
  author: string
  severity: string
  description: string
  tags: string[]
  category: string
  subCategory: string
  file: string
}

interface StatsResp {
  total: number
  categories: Record<string, { total: number; subs: Record<string, number> }>
  severities: Record<string, number>
}

interface VerifyResult {
  found: boolean
  output: string
  request: string
  response: string
  curlCmd: string
  error?: string
}

const SEV: Record<string, { label: string; cls: string; dot: string }> = {
  critical: { label: 'CRITICAL', dot: 'bg-red-400',    cls: 'bg-red-500/20 text-red-300 border-red-500/40' },
  high:     { label: 'HIGH',     dot: 'bg-orange-400', cls: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
  medium:   { label: 'MEDIUM',   dot: 'bg-amber-400',  cls: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  low:      { label: 'LOW',      dot: 'bg-blue-400',   cls: 'bg-blue-500/20 text-blue-300 border-blue-500/40' },
  info:     { label: 'INFO',     dot: 'bg-slate-400',  cls: 'bg-slate-500/20 text-slate-300 border-slate-500/40' },
}
const SEV_ORDER = ['critical','high','medium','low','info']

const CAT_CLS: Record<string, string> = {
  '国产OA':      'text-violet-300 bg-violet-500/15 border-violet-500/30',
  '国产数据库':   'text-cyan-300   bg-cyan-500/15   border-cyan-500/30',
  '国产中间件':   'text-emerald-300 bg-emerald-500/15 border-emerald-500/30',
  '国产网络':    'text-amber-300  bg-amber-500/15  border-amber-500/30',
  '国产安全':    'text-red-300    bg-red-500/15    border-red-500/30',
  '国产操作系统': 'text-sky-300   bg-sky-500/15    border-sky-500/30',
  '国产监控':    'text-orange-300 bg-orange-500/15 border-orange-500/30',
}
const catCls = (cat: string) => CAT_CLS[cat] ?? 'text-slate-300 bg-slate-500/15 border-slate-500/30'

function SevBadge({ sev }: { sev: string }) {
  const s = SEV[sev] ?? SEV.info
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${s.cls}`}>
      {s.label}
    </span>
  )
}

function CopyBtn({ text }: { text: string }) {
  const [ok, setOk] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(()=>setOk(false),1500) })
  }
  return (
    <button onClick={copy} className="ml-1 text-slate-500 hover:text-slate-300 transition">
      {ok ? <CheckCircle2 size={12} className="text-green-400"/> : <Copy size={12}/>}
    </button>
  )
}

export default function XcVulnView() {
  const [stats, setStats]         = useState<StatsResp | null>(null)
  const [templates, setTemplates] = useState<XCTemplate[]>([])
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')

  // 搜索框即时值 + 防抖后的实际请求值
  const [search, setSearch]           = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const [selCat, setSelCat]       = useState('')
  const [selSub, setSelSub]       = useState('')
  const [selSev, setSelSev]       = useState('')
  const [openCats, setOpenCats]   = useState<Set<string>>(new Set())
  const [openRow, setOpenRow]     = useState<string | null>(null)
  const [page, setPage]           = useState(0)

  // modal 验证状态
  const [modal, setModal]               = useState<XCTemplate | null>(null)
  const [modalTarget, setModalTarget]   = useState('')
  const [modalLoading, setModalLoading] = useState(false)
  const [modalResult, setModalResult]   = useState<VerifyResult | null>(null)
  const [showReqResp, setShowReqResp]   = useState(false)

  // 加载全局统计（分类树 + 严重级别计数），只请求一次
  useEffect(() => {
    engineGet<StatsResp>(CAP, '/stats').then(r => setStats(r)).catch(() => {})
  }, [])

  // 搜索防抖 300ms
  useEffect(() => {
    const t = setTimeout(() => setSearchQuery(search), 300)
    return () => clearTimeout(t)
  }, [search])

  // 筛选条件变化时重置翻页
  useEffect(() => { setPage(0); setOpenRow(null) }, [searchQuery, selCat, selSub, selSev])

  // 分页加载：每次 page / 筛选条件变化时从服务端拉取当前页数据
  useEffect(() => {
    setLoading(true)
    engineGet<{ templates: XCTemplate[]; total: number }>(CAP, '/templates', {
      page,
      pageSize:    PAGE_SIZE,
      category:    selCat      || undefined,
      subCategory: selSub      || undefined,
      severity:    selSev      || undefined,
      search:      searchQuery || undefined,
    })
      .then(r => { setTemplates(r.templates ?? []); setTotal(r.total ?? 0); setLoading(false) })
      .catch(e => { setError(String(e)); setLoading(false) })
  }, [page, searchQuery, selCat, selSub, selSev])

  // 分类树和级别统计从 /stats 响应构建，不依赖当前页的 templates
  const catTree = useMemo(() => {
    if (!stats) return new Map<string, Map<string, number>>()
    return new Map(
      Object.entries(stats.categories).map(([cat, v]) => [
        cat,
        new Map(Object.entries(v.subs)),
      ])
    )
  }, [stats])

  const sevStats = stats?.severities ?? {}

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const openModal = (t: XCTemplate, e: React.MouseEvent) => {
    e.stopPropagation()
    setModal(t)
    setModalTarget('')
    setModalResult(null)
    setShowReqResp(false)
  }

  const closeModal = () => {
    setModal(null)
    setModalLoading(false)
    setModalResult(null)
  }

  const runVerify = async () => {
    if (!modal || !modalTarget.trim()) return
    setModalLoading(true)
    setModalResult(null)
    try {
      const res = await enginePost<VerifyResult>(CAP, '/verify', {
        target: modalTarget.trim(), templateFile: modal.file
      })
      setModalResult(res)
    } catch(e) {
      setModalResult({ found: false, output: '', request: '', response: '', curlCmd: '', error: String(e) })
    } finally {
      setModalLoading(false)
    }
  }

  const toggleCat = (cat: string) => setOpenCats(prev => {
    const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n
  })

  return (
    <div className="flex h-full overflow-hidden">

      {/* 左侧分类边栏 */}
      <aside className="w-48 shrink-0 flex flex-col border-r border-base-600 bg-base-800">
        <div className="px-3 py-2.5 border-b border-base-600/50">
          <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">分类筛选</span>
        </div>
        <nav className="flex-1 overflow-y-auto py-1 px-1 space-y-px">
          <button
            onClick={() => { setSelCat(''); setSelSub(''); setSelSev('') }}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition ${
              !selCat && !selSub && !selSev ? 'bg-cyber/15 text-cyber' : 'text-slate-300 hover:bg-base-700'
            }`}
          >
            <span className="flex items-center gap-1.5"><ShieldAlert size={12}/>全部</span>
            <span className="text-[10px] text-slate-500">{stats?.total ?? '…'}</span>
          </button>

          <div className="h-px bg-base-600/40 mx-1 my-1"/>

          {[...catTree.entries()].sort(([a],[b])=>a.localeCompare(b,'zh-Hans')).map(([cat, subs]) => {
            const catTotal = [...subs.values()].reduce((a,b)=>a+b,0)
            const isOpen = openCats.has(cat)
            return (
              <div key={cat}>
                <button
                  onClick={() => {
                    toggleCat(cat)
                    setSelCat(selCat===cat && !selSub ? '' : cat)
                    setSelSub('')
                    setSelSev('')
                  }}
                  className={`w-full flex items-center gap-1 px-2.5 py-1.5 rounded text-xs transition ${
                    selCat===cat && !selSub ? 'bg-cyber/10 text-cyber' : 'text-slate-300 hover:bg-base-700'
                  }`}
                >
                  {isOpen
                    ? <ChevronDown size={10} className="text-slate-500 shrink-0"/>
                    : <ChevronRight size={10} className="text-slate-500 shrink-0"/>}
                  <span className="flex-1 text-left truncate">{cat}</span>
                  <span className="text-[10px] text-slate-500">{catTotal}</span>
                </button>
                {isOpen && [...subs.entries()].sort(([a],[b])=>a.localeCompare(b,'zh-Hans')).map(([sub,cnt])=>(
                  <button key={sub}
                    onClick={() => {
                      setSelCat(cat)
                      setSelSub(selSub===sub ? '' : sub)
                      setSelSev('')
                    }}
                    className={`w-full flex items-center justify-between pl-7 pr-2.5 py-1 rounded text-[11px] transition ${
                      selSub===sub ? 'bg-cyber/10 text-cyber' : 'text-slate-400 hover:bg-base-700/60'
                    }`}
                  >
                    <span className="truncate">{sub}</span>
                    <span className="text-[10px] text-slate-600">{cnt}</span>
                  </button>
                ))}
              </div>
            )
          })}

          <div className="h-px bg-base-600/40 mx-1 my-1"/>

          <p className="px-2.5 pt-1 pb-0.5 text-[10px] text-slate-600 uppercase tracking-wider">严重级别</p>
          {SEV_ORDER.filter(s=>sevStats[s]).map(s=>{
            const cfg = SEV[s]
            return (
              <button key={s}
                onClick={()=>{ setSelSev(selSev===s?'':s); setSelCat(''); setSelSub('') }}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition ${
                  selSev===s ? 'bg-cyber/10 text-cyber' : 'text-slate-300 hover:bg-base-700'
                }`}
              >
                <span className="flex items-center gap-1.5">
                  <span className={`w-2 h-2 rounded-full ${cfg.dot}`}/>
                  {cfg.label}
                </span>
                <span className="text-[10px] text-slate-500">{sevStats[s]}</span>
              </button>
            )
          })}
        </nav>
      </aside>

      {/* 右侧主区 */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* 统计栏 + 搜索 */}
        <div className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-base-600 bg-base-800/80">
          {[
            { l:'漏洞总数', v:stats?.total ?? 0,         c:'text-cyber' },
            { l:'严重',    v:sevStats.critical ?? 0,     c:'text-red-400' },
            { l:'高危',    v:sevStats.high ?? 0,         c:'text-orange-400' },
            { l:'中危',    v:sevStats.medium ?? 0,       c:'text-amber-400' },
            { l:'分类',    v:catTree.size,               c:'text-violet-400' },
          ].map(s=>(
            <div key={s.l} className="flex items-baseline gap-1.5 rounded border border-base-600 bg-base-700/40 px-3 py-1.5">
              <span className={`text-xl font-bold tabular-nums ${s.c}`}>{s.v}</span>
              <span className="text-xs text-slate-500">{s.l}</span>
            </div>
          ))}

          <div className="relative flex-1 min-w-44">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"/>
            <input value={search} onChange={e=>setSearch(e.target.value)}
              placeholder="搜索名称、ID、标签…"
              className="w-full rounded-lg border border-base-600 bg-base-700 pl-8 pr-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyber/60"/>
          </div>
          {(selCat||selSub||selSev||search) && (
            <button onClick={()=>{setSelCat('');setSelSub('');setSelSev('');setSearch('');setSearchQuery('')}}
              className="text-xs text-slate-500 hover:text-slate-300 border border-base-600 rounded px-2 py-1.5">
              清除筛选
            </button>
          )}
        </div>

        {/* 当前筛选提示条 */}
        {(selCat||selSub||selSev) && (
          <div className="flex items-center gap-2 px-4 py-1.5 bg-cyber/5 border-b border-cyber/20 text-xs text-slate-400">
            <span className="text-cyber">筛选：</span>
            {selCat && <span className={`rounded border px-1.5 py-0.5 ${catCls(selCat)}`}>{selCat}</span>}
            {selSub && <span className="text-slate-300">/ {selSub}</span>}
            {selSev && <SevBadge sev={selSev}/>}
            <span className="ml-auto text-slate-600">{total} 条</span>
          </div>
        )}

        {/* 表格 */}
        <div className="flex-1 overflow-y-auto">
          {loading && <div className="py-24 text-center text-slate-500">加载中…</div>}
          {error   && <div className="py-24 text-center text-red-400">{error}</div>}
          {!loading && !error && (
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10">
                <tr className="border-b border-base-600 bg-base-800/95">
                  <th className="w-7 px-2 py-2.5"/>
                  <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">漏洞名称</th>
                  <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400">分类</th>
                  <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 hidden md:table-cell">标签</th>
                  <th className="px-3 py-2.5 text-center text-xs font-medium text-slate-400">级别</th>
                  <th className="px-3 py-2.5 text-center text-xs font-medium text-slate-400">操作</th>
                </tr>
              </thead>
              <tbody>
                {templates.length === 0 && (
                  <tr><td colSpan={6} className="py-20 text-center text-slate-500">无匹配结果</td></tr>
                )}
                {templates.map(t => {
                  const detailOpen = openRow === t.id
                  return [
                    /* 主行 */
                    <tr key={t.id} onClick={()=>setOpenRow(detailOpen?null:t.id)}
                      className={`border-b border-base-700/40 cursor-pointer transition-colors ${
                        detailOpen ? 'bg-base-700/30' : 'hover:bg-base-800/60'
                      }`}>
                      <td className="px-3 py-3 text-slate-600">
                        {detailOpen?<ChevronDown size={12}/>:<ChevronRight size={12}/>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-slate-200">{t.name}</div>
                        <div className="text-[10px] text-slate-600 font-mono mt-0.5">{t.id}</div>
                      </td>
                      <td className="px-3 py-3">
                        <div className="space-y-0.5">
                          <button
                            onClick={e=>{e.stopPropagation();setSelCat(t.category);setSelSub('');setSelSev('');setPage(0)}}
                            className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium cursor-pointer hover:opacity-80 transition ${catCls(t.category)}`}>
                            {t.category}
                          </button>
                          {t.subCategory && (
                            <button
                              onClick={e=>{e.stopPropagation();setSelCat(t.category);setSelSub(t.subCategory);setSelSev('');setPage(0);setOpenCats(p=>{const n=new Set(p);n.add(t.category);return n})}}
                              className="block text-[10px] text-slate-500 hover:text-cyber transition cursor-pointer">
                              {t.subCategory}
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3 hidden md:table-cell">
                        <div className="flex flex-wrap gap-1">
                          {t.tags.slice(0,3).map(tg=>(
                            <span key={tg} className="rounded bg-base-700 px-1.5 py-0.5 text-[10px] text-slate-400">{tg}</span>
                          ))}
                          {t.tags.length>3 && <span className="text-[10px] text-slate-600">+{t.tags.length-3}</span>}
                        </div>
                      </td>
                      <td className="px-3 py-3 text-center"><SevBadge sev={t.severity}/></td>
                      <td className="px-3 py-3 text-center" onClick={e=>e.stopPropagation()}>
                        <button
                          onClick={e=>openModal(t, e)}
                          className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-medium transition bg-base-700 text-slate-400 border-base-600 hover:bg-yellow-500/15 hover:text-yellow-300 hover:border-yellow-500/40"
                        >
                          <Zap size={11}/> 一键检测
                        </button>
                      </td>
                    </tr>,

                    /* 详情行 */
                    detailOpen ? (
                      <tr key={`${t.id}-detail`} className="border-b border-base-700/40 bg-base-900/50">
                        <td colSpan={6} className="px-8 py-3">
                          <div className="space-y-2">
                            {t.description && <p className="text-xs text-slate-300 leading-relaxed">{t.description}</p>}
                            <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-slate-500">
                              <span>ID: <span className="font-mono text-slate-400">{t.id}</span></span>
                              <span>文件: <span className="font-mono text-slate-400">{t.file}</span></span>
                              {t.author && <span>作者: <span className="text-slate-400">{t.author}</span></span>}
                            </div>
                            {t.tags.length>0 && (
                              <div className="flex items-center gap-1 flex-wrap">
                                <Tag size={10} className="text-slate-600"/>
                                {t.tags.map(tg=>(
                                  <span key={tg} className="rounded border border-base-600 bg-base-700 px-1.5 py-0.5 text-[10px] text-slate-400">{tg}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    ) : null,
                  ]
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* 分页栏 */}
        {!loading && !error && totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-base-600 bg-base-800/80 px-4 py-2">
            <span className="text-xs text-slate-500">
              共 {total} 条 · 第 {page+1}/{totalPages} 页（每页{PAGE_SIZE}条）
            </span>
            <div className="flex items-center gap-1">
              <button onClick={()=>setPage(0)} disabled={page===0}
                className="rounded px-2 py-1 text-xs text-slate-400 hover:bg-base-700 disabled:opacity-30 transition">«</button>
              <button onClick={()=>setPage(p=>Math.max(0,p-1))} disabled={page===0}
                className="rounded px-2 py-1 text-xs text-slate-400 hover:bg-base-700 disabled:opacity-30 transition">
                <ChevronLeft size={13}/>
              </button>
              {Array.from({length:totalPages},(_,i)=>i)
                .filter(i=>Math.abs(i-page)<=2||i===0||i===totalPages-1)
                .reduce<(number|string)[]>((acc,i,idx,arr)=>{
                  if(idx>0&&(i as number)-(arr[idx-1] as number)>1) acc.push('...')
                  acc.push(i); return acc
                },[])
                .map((item,i)=>item==='...'
                  ? <span key={`e${i}`} className="px-1 text-xs text-slate-600">…</span>
                  : <button key={item} onClick={()=>setPage(item as number)}
                      className={`rounded w-7 py-1 text-xs transition ${
                        item===page?'bg-cyber/20 text-cyber':'text-slate-400 hover:bg-base-700'
                      }`}>{(item as number)+1}</button>
                )}
              <button onClick={()=>setPage(p=>Math.min(totalPages-1,p+1))} disabled={page===totalPages-1}
                className="rounded px-2 py-1 text-xs text-slate-400 hover:bg-base-700 disabled:opacity-30 transition">
                <ChevronRight size={13}/>
              </button>
              <button onClick={()=>setPage(totalPages-1)} disabled={page===totalPages-1}
                className="rounded px-2 py-1 text-xs text-slate-400 hover:bg-base-700 disabled:opacity-30 transition">»</button>
            </div>
          </div>
        )}
      </div>

      {/* ====== 验证 Modal ====== */}
      {modal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={closeModal}>
          <div className="w-[480px] rounded-xl border border-base-500 bg-base-800 shadow-2xl"
            onClick={e=>e.stopPropagation()}>

            {/* 标题栏 */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-base-600">
              <span className="text-sm font-semibold text-slate-200">验证模板</span>
              <button onClick={closeModal} className="text-slate-500 hover:text-slate-200 transition">
                <X size={16}/>
              </button>
            </div>

            {/* 模板信息 */}
            <div className="px-5 py-4 space-y-2">
              <div className="flex items-center gap-2">
                <SevBadge sev={modal.severity}/>
                <span className="text-sm font-medium text-slate-100">{modal.name}</span>
              </div>
              <div className="text-[11px] text-slate-500 font-mono break-all">{modal.file}</div>
            </div>

            {/* 目标输入 */}
            <div className="px-5 pb-4 space-y-1.5">
              <label className="text-xs text-slate-400 font-medium">
                目标 URL / IP <span className="text-red-400">*</span>
              </label>
              <input
                autoFocus
                value={modalTarget}
                onChange={e=>setModalTarget(e.target.value)}
                onKeyDown={e=>{ if(e.key==='Enter') runVerify() }}
                placeholder="http://192.168.1.100:8080"
                className="w-full rounded-lg border border-base-500 bg-base-700 px-3 py-2 text-sm text-slate-200 placeholder-slate-600 outline-none focus:border-yellow-500/60 font-mono"
              />
            </div>

            {/* 结果区 */}
            {modalResult && (
              <div className={`mx-5 mb-4 rounded-lg border p-3 space-y-2 ${
                modalResult.error
                  ? 'border-red-500/30 bg-red-500/10'
                  : modalResult.found
                    ? 'border-green-500/30 bg-green-500/10'
                    : 'border-slate-600 bg-base-900/60'
              }`}>
                <div className="flex items-center gap-2 text-xs font-semibold">
                  {modalResult.error
                    ? <><XCircle size={14} className="text-red-400"/><span className="text-red-300">执行错误</span></>
                    : modalResult.found
                      ? <><CheckCircle2 size={14} className="text-green-400"/><span className="text-green-300">漏洞存在！</span></>
                      : <><XCircle size={14} className="text-slate-500"/><span className="text-slate-400">未发现漏洞</span></>
                  }
                </div>
                {modalResult.error && (
                  <p className="text-xs text-red-300 font-mono break-all">{modalResult.error}</p>
                )}
                {modalResult.output && (
                  <div className="flex items-start gap-1 rounded bg-black/40 px-2.5 py-1.5 font-mono text-[11px] text-green-300">
                    <TerminalSquare size={11} className="text-green-600 shrink-0 mt-0.5"/>
                    <span className="flex-1 break-all">{modalResult.output}</span>
                    <CopyBtn text={modalResult.output}/>
                  </div>
                )}
                {modalResult.curlCmd && (
                  <div className="rounded bg-black/40 px-2.5 py-1.5">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] text-slate-500">Curl 命令</span>
                      <CopyBtn text={modalResult.curlCmd}/>
                    </div>
                    <code className="block text-[10px] text-slate-300 font-mono break-all whitespace-pre-wrap">{modalResult.curlCmd}</code>
                  </div>
                )}
                {(modalResult.request||modalResult.response) && (
                  <button
                    onClick={()=>setShowReqResp(v=>!v)}
                    className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition">
                    {showReqResp?<ChevronDown size={10}/>:<ChevronRight size={10}/>}
                    {showReqResp?'收起':'展开'} 请求/响应详情
                  </button>
                )}
                {showReqResp && (
                  <div className="grid grid-cols-2 gap-2">
                    {modalResult.request && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] text-slate-500">Request</span>
                          <CopyBtn text={modalResult.request}/>
                        </div>
                        <pre className="rounded bg-black/60 p-2 text-[10px] text-slate-300 font-mono overflow-auto max-h-40 whitespace-pre-wrap break-all">{modalResult.request}</pre>
                      </div>
                    )}
                    {modalResult.response && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] text-slate-500">Response</span>
                          <CopyBtn text={modalResult.response}/>
                        </div>
                        <pre className="rounded bg-black/60 p-2 text-[10px] text-slate-300 font-mono overflow-auto max-h-40 whitespace-pre-wrap break-all">{modalResult.response}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* 底部按钮 */}
            <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-base-600">
              <button onClick={closeModal}
                className="rounded-lg border border-base-500 px-4 py-2 text-sm text-slate-400 hover:text-slate-200 hover:bg-base-700 transition">
                取消
              </button>
              <button
                onClick={runVerify}
                disabled={!modalTarget.trim() || modalLoading}
                className="inline-flex items-center gap-2 rounded-lg border border-yellow-500/40 bg-yellow-500/15 px-5 py-2 text-sm font-medium text-yellow-300 hover:bg-yellow-500/25 disabled:opacity-40 disabled:cursor-not-allowed transition"
              >
                {modalLoading
                  ? <><Loader2 size={14} className="animate-spin"/> 验证中…</>
                  : <><Zap size={14}/> 开始验证</>
                }
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
