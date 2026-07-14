import { useCallback, useEffect, useRef, useState } from 'react'
import {
  FolderSearch, FileSearch, FolderTree, Filter, Play, Square, RefreshCw, Download, ExternalLink,
} from 'lucide-react'
import { Panel, StatCard, Progress, SeverityTag } from '@/components/ui'
import type { Severity } from '@/types'
import { engineGet, enginePost, engineDownload } from '@/lib/engine'
import { ApiError } from '@/lib/api'
import { createTask, updateTask } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'scan-dir'

interface Hit {
  url: string
  path: string
  status: number
  length: number
  words: number
  lines: number
  redirect: string
  contentType: string
  depth: number
  isDir: boolean
  severity: Severity
  kind: string
}

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

interface ScanStatus {
  running: boolean
  phase: string
  total: number
  probed: number
  found: number
  filtered: number
  rate: number
  elapsedMs: number
  target: string
  startedAt: string
  endedAt: string
  err: string
  resumable: boolean
}

type Method = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS'
const METHODS: Method[] = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

interface DictEntry {
  id: string
  label: string
  source: string
  count: number
}

// 状态码配色：2xx 绿 / 3xx 青 / 4xx 橙 / 5xx 红。
function codeClass(code: number): string {
  if (code >= 200 && code < 300) return 'text-sev-low'
  if (code >= 300 && code < 400) return 'text-cyber'
  if (code >= 400 && code < 500) return 'text-sev-medium'
  if (code >= 500) return 'text-sev-high'
  return 'text-slate-400'
}

function fmtLen(n: number): string {
  if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + 'M'
  if (n >= 1024) return (n / 1024).toFixed(1) + 'K'
  return String(n)
}

export default function View() {
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [hits, setHits] = useState<Hit[]>([])
  const [dicts, setDicts] = useState<DictEntry[]>([])

  const [targets, setTargets] = useState('')
  const [wordlist, setWordlist] = useState<string>('common')
  const [customWords, setCustomWords] = useState('')
  const [wordlist2, setWordlist2] = useState<string>('none')
  const [customWords2, setCustomWords2] = useState('')
  const [fuzzMode, setFuzzMode] = useState<'clusterbomb' | 'pitchfork'>('clusterbomb')
  const [extensions, setExtensions] = useState('')
  const [concurrency, setConcurrency] = useState(20)
  const [rate, setRate] = useState(0)
  const [timeout, setTimeoutMs] = useState(8000)
  const [statusInclude, setStatusInclude] = useState('')
  const [statusExclude, setStatusExclude] = useState('404')
  const [filterLength, setFilterLength] = useState('')
  const [filterWords, setFilterWords] = useState('')
  const [filterLines, setFilterLines] = useState('')
  const [filterRegex, setFilterRegex] = useState('')
  const [matchRegex, setMatchRegex] = useState('')
  const [minLength, setMinLength] = useState(0)
  const [maxLength, setMaxLength] = useState(0)
  const [prefixes, setPrefixes] = useState('')
  const [suffixes, setSuffixes] = useState('')
  const [crawl, setCrawl] = useState(false)
  const [collectBackups, setCollectBackups] = useState(false)
  const [randomAgent, setRandomAgent] = useState(false)
  const [followRedirect, setFollowRedirect] = useState(false)
  const [recursion, setRecursion] = useState(0)
  const [method, setMethod] = useState<Method>('GET')
  const [requestBody, setRequestBody] = useState('')
  const [proxy, setProxy] = useState('')
  const [cookie, setCookie] = useState('')
  const [userAgent, setUserAgent] = useState('')
  const [customHeaders, setCustomHeaders] = useState('')

  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [taskReload, setTaskReload] = useState(0)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  const refresh = useCallback(async () => {
    const [st, h] = await Promise.all([
      engineGet<{ status: ScanStatus; id: string }>(CAP, '/scan/status'),
      engineGet<{ items: Hit[] }>(CAP, '/hits'),
    ])
    setStatus(st.status)
    setHits(h.items ?? [])
    return st.status
  }, [])

  // 仅在扫描运行时轮询实时进度/命中（界面展示）。任务台账的进度/结果固化由
  // 后端 reconcile-on-read 负责（读取任务时按 task_id 拉引擎落库结果），本端不镜像。
  const startPolling = useCallback(() => {
    if (timer.current) return
    timer.current = setInterval(async () => {
      try {
        const st = await refresh()
        if (!st.running && timer.current) {
          clearInterval(timer.current); timer.current = null
          setTaskReload((n) => n + 1)
        }
      } catch { /* 轮询瞬时错误忽略 */ }
    }, 1500)
  }, [refresh])

  useEffect(() => {
    refresh().then((st) => { if (st.running) startPolling() }).catch((e) => setErr(String(e?.message ?? e)))
    engineGet<{ lists: DictEntry[] }>(CAP, '/dict').then((d) => setDicts(d.lists ?? [])).catch(() => {})
    return () => { if (timer.current) clearInterval(timer.current) }
  }, [refresh, startPolling])

  async function call(fn: () => Promise<unknown>) {
    setBusy(true); setErr(null)
    try { await fn(); await refresh() }
    catch (e) { setErr(e instanceof ApiError ? e.message : String((e as Error)?.message ?? e)) }
    finally { setBusy(false) }
  }

  async function startScan() {
    const list = targets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (!list.length) { setErr('请填写至少一个目标（http(s) URL / 域名 / IP，每行一个）'); return }
    const words = customWords.split('\n').map((t) => t.trim()).filter(Boolean)
    if (wordlist === 'custom' && !words.length) { setErr('字典选择了「自定义」，请填写词条'); return }
    await call(async () => {
      const words2 = customWords2.split('\n').map((t) => t.trim()).filter(Boolean)
      // Merge cookie and custom headers into a single headers list (backend format: "Key: Value").
      const extraHeaders = customHeaders.split('\n').map((h) => h.trim()).filter(Boolean)
      if (cookie.trim()) extraHeaders.push(`Cookie: ${cookie.trim()}`)
      const params = {
        targets: list, wordlist, customWords: words, extensions,
        wordlist2: wordlist2 === 'none' ? '' : wordlist2, customWords2: words2, fuzzMode,
        concurrency, rate, timeout, statusInclude, statusExclude,
        filterLength, filterWords, filterLines, filterRegex, matchRegex,
        minLength, maxLength, prefixes, suffixes,
        crawl, collectBackups, randomAgent, followRedirect, recursion, method,
        requestBody, proxy, userAgent, headers: extraHeaders,
      }
      // 统一 task_id：先向系统申请 id 落台账，再透传给引擎 /invoke。
      const t = await createTask({ capabilityKey: CAP, action: 'scan', params })
      setTaskReload((n) => n + 1)
      try {
        await enginePost(CAP, '/invoke', { taskId: t.id, function: 'scan', params })
      } catch (e) {
        await updateTask(t.id, {
          status: 'failed', error: e instanceof Error ? e.message : String(e),
        }).catch(() => {})
        setTaskReload((n) => n + 1)
        throw e
      }
      startPolling()
    })
  }

  const running = status?.running ?? false
  const pct = status && status.total > 0 ? Math.min(100, Math.round((status.probed / status.total) * 100)) : 0
  const highValue = hits.filter((h) => h.severity === 'critical' || h.severity === 'high').length
  const selDict = dicts.find((d) => d.id === wordlist)
  // 展示用:按敏感度降序、同级保持发现顺序。
  const sortedHits = [...hits].sort((a, b) => (SEV_RANK[b.severity] ?? 1) - (SEV_RANK[a.severity] ?? 1))

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="命中路径" value={hits.length || '—'} icon={<FileSearch size={18} />} />
        <StatCard label="高危命中" value={highValue || '—'} icon={<FolderTree size={18} />} />
        <StatCard label="已过滤" value={status?.filtered ?? '—'} icon={<Filter size={18} />} />
        <StatCard label="字典词条" value={selDict ? selDict.count.toLocaleString() : (wordlist === 'custom' ? '自定义' : '—')} icon={<FolderSearch size={18} />} />
      </div>

      <Panel title="发起目录扫描" icon={<FolderSearch size={16} />}>
        <div className="space-y-3">
          <textarea
            className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-sm text-slate-200 outline-none focus:border-cyber"
            rows={3} placeholder="目标，每行一个：https://example.com 或 example.com/app 或 含 FUZZ 关键字（ffuf 风格）如 https://x.com/api/FUZZ?id=1"
            value={targets} onChange={(e) => setTargets(e.target.value)} disabled={running}
          />
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">字典
              <select value={wordlist} onChange={(e) => setWordlist(e.target.value)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                {dicts.map((d) => (
                  <option key={d.id} value={d.id}>{d.label}（{d.count.toLocaleString()}）</option>
                ))}
                <option value="custom">自定义词条</option>
              </select>
            </label>
            <label className="flex items-center gap-2" title="替换字典中的 %EXT% 占位符，并对目录型词条追加">扩展名
              <input value={extensions} onChange={(e) => setExtensions(e.target.value)} disabled={running}
                placeholder="php,bak,zip,txt（%EXT%）"
                className="w-44 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">方法
              <select value={method} onChange={(e) => setMethod(e.target.value as Method)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                {METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </label>
            <label className="flex items-center gap-2">递归
              <input type="number" min={0} max={3} value={recursion}
                onChange={(e) => setRecursion(+e.target.value)} disabled={running}
                className="w-16 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="ffuf -x / dirsearch --proxy">代理
              <input value={proxy} onChange={(e) => setProxy(e.target.value)} disabled={running}
                placeholder="http://127.0.0.1:8080"
                className="w-52 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="附加 Cookie：自动拼为 Cookie: <value> 请求头">Cookie
              <input value={cookie} onChange={(e) => setCookie(e.target.value)} disabled={running}
                placeholder="session=abc123; token=xyz"
                className="w-56 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="留空使用内置随机 UA 池">UA
              <input value={userAgent} onChange={(e) => setUserAgent(e.target.value)} disabled={running}
                placeholder="留空=默认"
                className="w-56 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
          </div>

          {/* 自定义请求头 */}
          <div className="space-y-1">
            <label className="flex items-center gap-1 text-xs text-slate-500" title="每行一个 Key: Value，可用 FUZZ 占位符做请求头 Fuzz">
              自定义请求头（每行一个 <code className="font-mono">Key: Value</code>，支持 FUZZ 占位符）
            </label>
            <textarea
              className="w-full rounded-lg border border-line bg-base-700/60 p-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
              rows={2}
              placeholder={"Authorization: Bearer eyJhbGci...\nX-Forwarded-For: 127.0.0.1\nX-Custom-Header: FUZZ"}
              value={customHeaders} onChange={(e) => setCustomHeaders(e.target.value)} disabled={running}
            />
          </div>

          {method !== 'GET' && method !== 'HEAD' && (
            <textarea
              className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
              rows={2} placeholder="请求体（ffuf -d）：非 GET/HEAD 时发送，可含 FUZZ，如 user=admin&pass=FUZZ"
              value={requestBody} onChange={(e) => setRequestBody(e.target.value)} disabled={running}
            />
          )}

          {wordlist === 'custom' && (
            <textarea
              className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
              rows={3} placeholder="自定义词条，每行一个路径名（如 admin、api/v1、backup.zip）"
              value={customWords} onChange={(e) => setCustomWords(e.target.value)} disabled={running}
            />
          )}

          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <span className="text-xs text-slate-500" title="ffuf 多关键字：目标/请求体/请求头里用 FUZ2Z 标记第二位置">多关键字（FUZ2Z）：</span>
            <label className="flex items-center gap-2">第二字典
              <select value={wordlist2} onChange={(e) => setWordlist2(e.target.value)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                <option value="none">不启用</option>
                {dicts.map((d) => <option key={d.id} value={d.id}>{d.label}（{d.count.toLocaleString()}）</option>)}
                <option value="custom">自定义词条</option>
              </select>
            </label>
            {wordlist2 !== 'none' && (
              <label className="flex items-center gap-2">模式
                <select value={fuzzMode} onChange={(e) => setFuzzMode(e.target.value as 'clusterbomb' | 'pitchfork')} disabled={running}
                  className="rounded border border-line bg-base-700/60 px-2 py-1">
                  <option value="clusterbomb">clusterbomb（N×M）</option>
                  <option value="pitchfork">pitchfork（并行）</option>
                </select>
              </label>
            )}
          </div>
          {wordlist2 === 'custom' && (
            <textarea
              className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
              rows={2} placeholder="第二字典词条（FUZ2Z），每行一个"
              value={customWords2} onChange={(e) => setCustomWords2(e.target.value)} disabled={running}
            />
          )}

          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">并发
              <input type="number" min={1} max={64} value={concurrency}
                onChange={(e) => setConcurrency(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">限速/s
              <input type="number" min={0} max={2000} value={rate}
                onChange={(e) => setRate(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">超时ms
              <input type="number" min={500} max={30000} value={timeout}
                onChange={(e) => setTimeoutMs(+e.target.value)} disabled={running}
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">仅保留码
              <input value={statusInclude} onChange={(e) => setStatusInclude(e.target.value)} disabled={running}
                placeholder="留空=全部"
                className="w-32 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">排除码
              <input value={statusExclude} onChange={(e) => setStatusExclude(e.target.value)} disabled={running}
                placeholder="404"
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={followRedirect} onChange={(e) => setFollowRedirect(e.target.checked)} disabled={running} />
              跟随跳转
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <span className="text-xs text-slate-500">ffuf 过滤（命中后剔除匹配项）：</span>
            <label className="flex items-center gap-2" title="ffuf -fs：过滤掉这些响应体字节数">大小
              <input value={filterLength} onChange={(e) => setFilterLength(e.target.value)} disabled={running}
                placeholder="0,1234"
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="ffuf -fw：过滤掉这些词数">词数
              <input value={filterWords} onChange={(e) => setFilterWords(e.target.value)} disabled={running}
                placeholder="10,42"
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="ffuf -fl：过滤掉这些行数">行数
              <input value={filterLines} onChange={(e) => setFilterLines(e.target.value)} disabled={running}
                placeholder="1,7"
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="dirsearch --minimal / --maximal：响应大小区间(0=不限)">大小区间
              <input type="number" min={0} value={minLength} onChange={(e) => setMinLength(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
              <span className="text-slate-500">~</span>
              <input type="number" min={0} value={maxLength} onChange={(e) => setMaxLength(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2" title="ffuf -fr / dirsearch --exclude-texts：正文匹配则剔除">正文过滤
              <input value={filterRegex} onChange={(e) => setFilterRegex(e.target.value)} disabled={running}
                placeholder="Access Denied|无权限"
                className="w-48 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="ffuf -mr：仅保留正文匹配者">正文匹配
              <input value={matchRegex} onChange={(e) => setMatchRegex(e.target.value)} disabled={running}
                placeholder="admin|console"
                className="w-40 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="dirsearch --prefixes：为每词条加前缀">前缀
              <input value={prefixes} onChange={(e) => setPrefixes(e.target.value)} disabled={running}
                placeholder=".,_"
                className="w-24 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="dirsearch --suffixes：为每词条加后缀">后缀
              <input value={suffixes} onChange={(e) => setSuffixes(e.target.value)} disabled={running}
                placeholder="~,.bak,/"
                className="w-28 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="feroxbuster --extract-links / dirsearch --crawl">
              <input type="checkbox" checked={crawl} onChange={(e) => setCrawl(e.target.checked)} disabled={running} />
              链接抽取
            </label>
            <label className="flex items-center gap-2" title="feroxbuster --collect-backups：命中文件时自动探 .bak/~/.old/.swp 等备份变体">
              <input type="checkbox" checked={collectBackups} onChange={(e) => setCollectBackups(e.target.checked)} disabled={running} />
              备份衍生
            </label>
            <label className="flex items-center gap-2" title="dirsearch random-agent">
              <input type="checkbox" checked={randomAgent} onChange={(e) => setRandomAgent(e.target.checked)} disabled={running} />
              随机 UA
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <button onClick={() => call(() => enginePost(CAP, '/scan/stop'))} disabled={busy}
                className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={14} /> 停止扫描
              </button>
            ) : (
              <>
                <button onClick={startScan} disabled={busy}
                  className="chip border border-cyber/40 bg-cyber/10 text-cyber">
                  <Play size={14} /> 发起扫描
                </button>
                {status?.resumable && (
                  <button onClick={() => call(async () => { await enginePost(CAP, '/scan/resume'); startPolling() })} disabled={busy}
                    className="chip border border-sev-medium/40 bg-sev-medium/10 text-sev-medium"
                    title="从上次中断处继续(保留已有命中,跳过已扫目录)">
                    <RefreshCw size={14} /> 续扫
                  </button>
                )}
              </>
            )}
            <button onClick={() => call(async () => { await refresh() })} disabled={busy}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <RefreshCw size={14} /> 刷新
            </button>
            <div className="ml-auto flex items-center gap-1">
              {(['json', 'csv', 'html'] as const).map((f) => (
                <button key={f} onClick={() => engineDownload(CAP, '/export', `dirscan-hits.${f}`, { format: f })}
                  disabled={hits.length === 0}
                  className="chip border border-line bg-base-600/60 text-slate-400">
                  <Download size={14} /> {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {running && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-slate-400">
                <span>{status?.phase || '扫描中…'}　{status?.target}</span>
                <span className="font-mono">{status?.probed}/{status?.total}（命中 {status?.found}）</span>
              </div>
              <Progress value={pct} />
            </div>
          )}
          {err && <div className="text-sm text-sev-high">{err}</div>}
        </div>
      </Panel>

      <Panel title={`命中路径（${hits.length}）`} icon={<FileSearch size={16} />} bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-slate-500">
                <th className="px-4 py-2 font-medium">敏感度</th>
                <th className="px-4 py-2 font-medium">状态</th>
                <th className="px-4 py-2 font-medium">路径</th>
                <th className="px-4 py-2 font-medium">长度</th>
                <th className="px-4 py-2 font-medium">词/行</th>
                <th className="px-4 py-2 font-medium">跳转 / 类型</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {hits.length === 0 && (
                <tr><td colSpan={7} className="p-6 text-center text-sm text-slate-500">暂无命中</td></tr>
              )}
              {sortedHits.map((h, i) => (
                <tr key={`${h.url}/${i}`} className="hover:bg-base-600/40">
                  <td className="px-4 py-2">
                    {h.severity && h.severity !== 'info'
                      ? <SeverityTag severity={h.severity} />
                      : <span className="text-xs text-slate-600">—</span>}
                  </td>
                  <td className={`px-4 py-2 font-mono font-semibold ${codeClass(h.status)}`}>{h.status}</td>
                  <td className="px-4 py-2 font-mono text-slate-300">
                    {h.isDir && <FolderTree size={12} className="mr-1 inline text-cyber" />}
                    {h.path}
                    {h.kind && <span className="ml-2 text-xs text-slate-500">{h.kind}</span>}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-400">{fmtLen(h.length)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">{h.words}/{h.lines}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">{h.redirect || h.contentType || '—'}</td>
                  <td className="px-4 py-2">
                    <a href={h.url} target="_blank" rel="noreferrer" className="text-slate-500 hover:text-cyber">
                      <ExternalLink size={14} />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="历史任务" icon={<FolderSearch size={16} />} bodyClass="p-3">
        <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload}
          emptyHint="暂无任务记录，发起一次扫描后将登记到此。" />
      </Panel>
    </div>
  )
}
