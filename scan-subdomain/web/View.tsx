import { useEffect, useRef, useState } from 'react'
import { Globe, Network, Shield, Wifi, Play, Square, RefreshCw, Download, ChevronRight, ChevronDown, ChevronUp, Save, CheckCircle2, KeyRound } from 'lucide-react'
import { Panel, StatCard, Progress } from '@/components/ui'
import { engineGet, enginePost } from '@/lib/engine'
import { ApiError } from '@/lib/api'
import { createTask, updateTask, pollTask, listTasks, type TaskRecord } from '@/lib/tasks'
import TaskList from '@/components/TaskList'

const CAP = 'scan-subdomain'

interface SubdomainRecord {
  subdomain: string
  ip: string[]
  cdn: string
  status: number
  title: string
  source: string
}

// /findings 端点返回的 ip 是逗号分隔字符串（archiveResults 存储格式）
interface FindingItem {
  subdomain: string
  ip: string
  cdn: string
  status: number
  title: string
  source: string
  foundAt: string
}

interface SavedKeys {
  hunterKey: string
  zoomeyeKey: string
  quakeKey: string
  zerozoneKey: string
  fofaEmail: string
  fofaKey: string
  shodanKey: string
  securitytrailsKey: string
  censysId: string
  censysSecret: string
  virusTotalKey: string
  chaosKey: string
  threatbookKey: string
}

function findingsToRecords(items: FindingItem[]): SubdomainRecord[] {
  return items.map((item) => ({
    subdomain: item.subdomain,
    ip: item.ip ? item.ip.split(',').filter(Boolean) : [],
    cdn: item.cdn,
    status: item.status,
    title: item.title,
    source: item.source,
  }))
}

async function applyFinished(
  finished: TaskRecord,
  stoppedRef: { current: boolean },
  setResults: (r: SubdomainRecord[]) => void,
  setErr: (e: string | null) => void,
) {
  if (finished.status === 'succeeded') {
    try {
      const r = await engineGet<{ items: FindingItem[] }>(CAP, '/findings', { taskId: finished.id })
      setResults(findingsToRecords(r.items ?? []))
      setErr(null)
    } catch {
      setErr('加载结果失败')
    }
  } else if (finished.status === 'failed' && !stoppedRef.current) {
    setErr(finished.error ?? '枚举失败')
  }
}

const statusColor = (code: number) => {
  if (!code) return 'text-slate-500'
  if (code < 300) return 'text-emerald-400'
  if (code < 400) return 'text-amber-400'
  if (code < 500) return 'text-sev-high'
  return 'text-sev-critical'
}

const sourceLabel: Record<string, string> = {
  dict:           '字典',
  ct:             'CT日志',
  brute:          'DNS暴破',
  perm:           '排列组合',
  hunter:         'Hunter',
  zoomeye:        'ZoomEye',
  quake:          '360 Quake',
  zerozone:       '零零信安',
  fofa:           'FOFA',
  shodan:         'Shodan',
  securitytrails: 'SecurityTrails',
  censys:         'Censys',
  virustotal:     'VirusTotal',
  chaos:          'Chaos',
  threatbook:     '微步',
}

const sourceChipClass: Record<string, string> = {
  dict:           'border-slate-600/40 bg-slate-800/40 text-slate-400',
  ct:             'border-cyber/30 bg-cyber/10 text-cyber',
  brute:          'border-slate-600/40 bg-slate-800/40 text-slate-500',
  perm:           'border-pink-500/40 bg-pink-500/10 text-pink-400',
  hunter:         'border-amber-500/40 bg-amber-500/10 text-amber-400',
  zoomeye:        'border-purple-500/40 bg-purple-500/10 text-purple-400',
  quake:          'border-orange-500/40 bg-orange-500/10 text-orange-400',
  zerozone:       'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
  fofa:           'border-blue-400/40 bg-blue-400/10 text-blue-400',
  shodan:         'border-red-400/40 bg-red-400/10 text-red-400',
  securitytrails: 'border-teal-400/40 bg-teal-400/10 text-teal-400',
  censys:         'border-indigo-400/40 bg-indigo-400/10 text-indigo-400',
  virustotal:     'border-sky-400/40 bg-sky-400/10 text-sky-400',
  chaos:          'border-yellow-400/40 bg-yellow-400/10 text-yellow-400',
  threatbook:     'border-rose-400/40 bg-rose-400/10 text-rose-400',
}

const EMPTY_KEYS: SavedKeys = {
  hunterKey: '', zoomeyeKey: '', quakeKey: '', zerozoneKey: '',
  fofaEmail: '', fofaKey: '', shodanKey: '',
  securitytrailsKey: '', censysId: '', censysSecret: '',
  virusTotalKey: '', chaosKey: '', threatbookKey: '',
}

export default function SubdomainView() {
  // 表单参数（单次扫描临时覆盖）
  const [domain, setDomain] = useState('')
  const [mode, setMode] = useState<'dict' | 'brute' | 'ct' | 'all'>('all')
  const [dictPreset, setDictPreset] = useState('medium')
  const [permutation, setPermutation] = useState(true)
  const [resolver, setResolver] = useState('8.8.8.8,1.1.1.1')
  const [threads, setThreads] = useState(100)
  const [timeout, setTimeout_] = useState(3000)
  const [showApiKeys, setShowApiKeys] = useState(false)

  // 情报源 Key（当次会话临时值，留空则引擎自动使用持久化存储的 Key）
  const [hunterKey, setHunterKey] = useState('')
  const [zoomeyeKey, setZoomeyeKey] = useState('')
  const [quakeKey, setQuakeKey] = useState('')
  const [zerozoneKey, setZerozoneKey] = useState('')
  const [fofaEmail, setFofaEmail] = useState('')
  const [fofaKey, setFofaKey] = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [securitytrailsKey, setSecuritytrailsKey] = useState('')
  const [censysId, setCensysId] = useState('')
  const [censysSecret, setCensysSecret] = useState('')
  const [virusTotalKey, setVirusTotalKey] = useState('')
  const [chaosKey, setChaosKey] = useState('')
  const [threatbookKey, setThreatbookKey] = useState('')

  // 已持久化的 Key（从引擎 SQLite 读取，仅用于 UI 展示是否已配置）
  const [savedKeys, setSavedKeys] = useState<SavedKeys>(EMPTY_KEYS)
  const [savingKeys, setSavingKeys] = useState(false)
  const [saveMsg, setSaveMsg] = useState<string | null>(null)

  // 扫描状态
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<SubdomainRecord[]>([])
  const [progress, setProgress] = useState<string | null>(null)
  const [progressPct, setProgressPct] = useState(0)
  const [err, setErr] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [taskReload, setTaskReload] = useState(0)

  const [keysOpen, setKeysOpen] = useState(false)

  const stoppedRef = useRef(false)
  const mountedRef = useRef(true)

  // 挂载：并行完成三件事——
  //   1. 从引擎读取已保存的 API Key 配置
  //   2. 检测引擎是否有扫描在跑（若有则重连轮询）
  //   3. 若无在跑扫描，从 SQLite 加载上次扫描结果（页面刷新不丢数据）
  useEffect(() => {
    mountedRef.current = true

    async function initCheck() {
      const [settingsResult, statusResult] = await Promise.allSettled([
        engineGet<SavedKeys>(CAP, '/settings'),
        engineGet<{ running: boolean }>(CAP, '/status'),
      ])

      if (!mountedRef.current) return

      // 1. 加载已保存的 API Key 配置
      if (settingsResult.status === 'fulfilled') {
        setSavedKeys(settingsResult.value)
      }

      // 2. 检测引擎运行状态
      if (statusResult.status === 'fulfilled' && statusResult.value.running) {
        // 引擎正在扫描，查找对应后端任务并恢复轮询
        const [runningTasks, pendingTasks] = await Promise.all([
          listTasks({ capabilityKey: CAP, status: 'running', limit: 1 }),
          listTasks({ capabilityKey: CAP, status: 'pending', limit: 1 }),
        ])
        const activeTask = runningTasks[0] ?? pendingTasks[0]
        if (activeTask && mountedRef.current) {
          setRunning(true)
          setProgress('重连扫描任务…')
          setTaskReload((n) => n + 1)
          pollTask(activeTask.id, {
            intervalMs: 2000,
            timeoutMs: 20 * 60 * 1000,
            onProgress: (t) => {
              if (mountedRef.current) {
                setProgress(t.message ?? '枚举中…')
                setProgressPct(t.progress)
              }
            },
          })
            .then(async (finished) => {
              if (!mountedRef.current) return
              await applyFinished(finished, stoppedRef, setResults, setErr)
              setRunning(false)
              setProgress(null)
              setProgressPct(0)
              setTaskReload((n) => n + 1)
              stoppedRef.current = false
            })
            .catch((e) => {
              if (!mountedRef.current || stoppedRef.current) return
              setErr(e instanceof Error ? e.message : String(e))
              setRunning(false)
              setProgress(null)
              setProgressPct(0)
              stoppedRef.current = false
            })
          return // 有运行中任务时跳过历史结果加载
        }
      }

      // 3. 无在跑扫描时，从 SQLite 加载最近一次成功任务的结果
      try {
        const tasks = await listTasks({ capabilityKey: CAP, status: 'succeeded', limit: 1 })
        if (tasks.length > 0 && mountedRef.current) {
          const res = await engineGet<{ items: FindingItem[] }>(CAP, '/findings', { taskId: tasks[0].id })
          if (mountedRef.current && res.items?.length > 0) {
            setResults(findingsToRecords(res.items))
          }
        }
      } catch { /* 历史结果加载失败不影响主流程 */ }
    }

    initCheck().catch(() => { /* 引擎未启动时静默忽略 */ })
    return () => { mountedRef.current = false }
  }, [])

  // 保存情报源 API Key 到引擎 SQLite（永久生效，所有后续扫描自动使用）
  async function saveApiKeys() {
    setSavingKeys(true)
    setSaveMsg(null)
    try {
      const body = {
        hunterKey, zoomeyeKey, quakeKey, zerozoneKey,
        fofaEmail, fofaKey, shodanKey,
        securitytrailsKey, censysId, censysSecret,
        virusTotalKey, chaosKey, threatbookKey,
      }
      await enginePost(CAP, '/settings', body)
      if (mountedRef.current) {
        setSavedKeys(body)
        setSaveMsg('已保存')
        // 3 秒后清除成功提示
        setTimeout(() => { if (mountedRef.current) setSaveMsg(null) }, 3000)
      }
    } catch (e) {
      if (mountedRef.current) {
        setSaveMsg('保存失败：' + (e instanceof ApiError ? e.message : (e instanceof Error ? e.message : String(e))))
      }
    } finally {
      if (mountedRef.current) setSavingKeys(false)
    }
  }

  async function stopScan() {
    stoppedRef.current = true
    try { await enginePost(CAP, '/stop', {}) } catch { /* 引擎已空闲时忽略 */ }
  }

  async function startScan() {
    if (!domain.trim()) { setErr('请输入目标主域名（如 example.com）'); return }
    setErr(null)
    setRunning(true)
    setResults([])
    setProgress('正在提交任务…')
    setProgressPct(0)
    stoppedRef.current = false

    // 前端传入当次临时 Key；引擎在 invokeEnumerate 中 fallback 读取持久化 Key
    const params = {
      domain: domain.trim(), mode, dictPreset, permutation, resolver, threads, timeoutMs: timeout,
      hunterKey: hunterKey.trim(), zoomeyeKey: zoomeyeKey.trim(),
      quakeKey: quakeKey.trim(), zerozoneKey: zerozoneKey.trim(),
      fofaEmail: fofaEmail.trim(), fofaKey: fofaKey.trim(),
      shodanKey: shodanKey.trim(),
      securitytrailsKey: securitytrailsKey.trim(),
      censysId: censysId.trim(), censysSecret: censysSecret.trim(),
      virusTotalKey: virusTotalKey.trim(),
      chaosKey: chaosKey.trim(),
      threatbookKey: threatbookKey.trim(),
    }
    let task: Awaited<ReturnType<typeof createTask>> | null = null
    let finished: TaskRecord | null = null
    try {
      task = await createTask({ capabilityKey: CAP, action: 'enumerate', params })
      setTaskReload((n) => n + 1)
      await enginePost(CAP, '/invoke', { taskId: task.id, function: 'enumerate', params })
      finished = await pollTask(task.id, {
        intervalMs: 2000,
        timeoutMs: 20 * 60 * 1000,
        onProgress: (t) => {
          if (mountedRef.current) {
            setProgress(t.message ?? '枚举中…')
            setProgressPct(t.progress)
          }
        },
      })
    } catch (e: unknown) {
      if (!stoppedRef.current && mountedRef.current) {
        const msg = e instanceof ApiError ? e.message : (e instanceof Error ? e.message : String(e))
        if (task) await updateTask(task.id, { status: 'failed', error: msg }).catch(() => {})
        setErr(msg)
      }
    } finally {
      if (mountedRef.current) {
        if (finished) await applyFinished(finished, stoppedRef, setResults, setErr)
        setRunning(false)
        setProgress(null)
        setProgressPct(0)
        setTaskReload((n) => n + 1)
        stoppedRef.current = false
      }
    }
  }

  function exportCSV() {
    const header = '子域名,IP,CDN,状态码,标题,来源'
    const rows = results.map((r) =>
      [r.subdomain, r.ip.join(';'), r.cdn, r.status || '', r.title, r.source]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(','),
    )
    const csv = [header, ...rows].join('\n')
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `subdomain-${domain || 'results'}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  // FOFA / Censys 需要两字段都存在才算"已配置"，在 UI 上计为 1 个情报源
  const fofaConfigured = Boolean(savedKeys.fofaEmail && savedKeys.fofaKey)
  const censysConfigured = Boolean(savedKeys.censysId && savedKeys.censysSecret)
  const hasSavedKey = (k: keyof SavedKeys): boolean => {
    if (k === 'fofaEmail' || k === 'fofaKey') return fofaConfigured
    if (k === 'censysId' || k === 'censysSecret') return censysConfigured
    return Boolean(savedKeys[k])
  }
  const configuredCount = [
    savedKeys.hunterKey,
    savedKeys.zoomeyeKey,
    savedKeys.quakeKey,
    savedKeys.zerozoneKey,
    fofaConfigured ? 'fofa' : '',
    savedKeys.shodanKey,
    savedKeys.securitytrailsKey,
    censysConfigured ? 'censys' : '',
    savedKeys.virusTotalKey,
    savedKeys.chaosKey,
    savedKeys.threatbookKey,
  ].filter(Boolean).length

  const subFl = filter.toLowerCase()
  const filtered = results.filter(
    (r) => !subFl ||
      r.subdomain.includes(subFl) ||
      r.ip.join(',').includes(subFl) ||
      r.cdn.toLowerCase().includes(subFl) ||
      r.title.toLowerCase().includes(subFl) ||
      (sourceLabel[r.source] ?? r.source).toLowerCase().includes(subFl),
  )
  const withCDN = results.filter((r) => r.cdn !== '—').length
  const alive = results.filter((r) => r.status > 0 && r.status < 400).length
  const uniqueIPs = results.length ? new Set(results.flatMap((r) => r.ip)).size : 0

  const keyConfigs: Array<{ key: keyof SavedKeys; label: string; value: string; set: (v: string) => void; placeholder: string; desc: string }> = [
    { key: 'hunterKey',        label: 'Hunter（奇安信鹰图）',   value: hunterKey,        set: setHunterKey,        placeholder: 'hunter.qianxin.com API Key',         desc: '查询鹰图资产测绘平台域名情报' },
    { key: 'zoomeyeKey',       label: 'ZoomEye（钟馗之眼）',    value: zoomeyeKey,       set: setZoomeyeKey,       placeholder: 'zoomeye.org API Key',                desc: '查询 ZoomEye 网络空间测绘数据' },
    { key: 'quakeKey',         label: '360 Quake',              value: quakeKey,         set: setQuakeKey,         placeholder: 'quake.360.net API Token',            desc: '查询 360 Quake 互联网测绘平台' },
    { key: 'zerozoneKey',      label: '零零信安（0.zone）',      value: zerozoneKey,      set: setZerozoneKey,      placeholder: '0.zone API Key',                     desc: '查询零零信安威胁情报平台' },
    { key: 'fofaEmail',        label: 'FOFA 账号邮箱',           value: fofaEmail,        set: setFofaEmail,        placeholder: 'you@example.com',                    desc: 'FOFA 认证需同时填写邮箱与 Key' },
    { key: 'fofaKey',          label: 'FOFA API Key',            value: fofaKey,          set: setFofaKey,          placeholder: 'fofa.info API Key',                  desc: '查询 FOFA 网络空间测绘数据' },
    { key: 'shodanKey',        label: 'Shodan',                  value: shodanKey,        set: setShodanKey,        placeholder: 'shodan.io API Key',                  desc: '查询 Shodan 全球互联网设备数据' },
    { key: 'securitytrailsKey', label: 'SecurityTrails',         value: securitytrailsKey, set: setSecuritytrailsKey, placeholder: 'securitytrails.com API Key',        desc: '查询 DNS 历史记录与子域名数据库' },
    { key: 'censysId',         label: 'Censys API ID',           value: censysId,         set: setCensysId,         placeholder: 'Censys API ID',                      desc: 'Censys 证书搜索需同时填写 ID 与 Secret' },
    { key: 'censysSecret',     label: 'Censys API Secret',       value: censysSecret,     set: setCensysSecret,     placeholder: 'Censys API Secret',                  desc: '查询 Censys 证书透明度与网络测绘数据' },
    { key: 'virusTotalKey',    label: 'VirusTotal',              value: virusTotalKey,    set: setVirusTotalKey,    placeholder: 'virustotal.com API Key',             desc: '查询 VirusTotal 子域名被动 DNS 数据' },
    { key: 'chaosKey',         label: 'Chaos (ProjectDiscovery)', value: chaosKey,        set: setChaosKey,         placeholder: 'chaos.projectdiscovery.io API Key',  desc: '查询 ProjectDiscovery 公开子域名数据集' },
    { key: 'threatbookKey',    label: '微步在线 ThreatBook',       value: threatbookKey,    set: setThreatbookKey,    placeholder: 'threatbook.cn API Key',              desc: '查询微步在线子域名威胁情报' },
  ]

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="发现子域" value={results.length || '—'} icon={<Globe size={18} />} />
        <StatCard label="有效响应" value={alive || '—'} icon={<Wifi size={18} />} />
        <StatCard label="CDN 保护" value={withCDN || '—'} icon={<Shield size={18} />} />
        <StatCard label="唯一 IP" value={uniqueIPs || '—'} icon={<Network size={18} />} />
      </div>

      {/* ── 情报源 API Key 全局配置（可折叠）────────────────────────── */}
      <section className="panel">
        <header
          className="panel-head cursor-pointer select-none"
          onClick={() => setKeysOpen((v) => !v)}
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <KeyRound size={16} />
            情报源配置
          </div>
          <div className="flex items-center gap-2">
            {configuredCount > 0 && (
              <span className="chip border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs">
                <CheckCircle2 size={12} /> 已配置 {configuredCount}/11 个情报源
              </span>
            )}
            {keysOpen
              ? <ChevronUp size={14} className="text-slate-400" />
              : <ChevronDown size={14} className="text-slate-400" />}
          </div>
        </header>
        {keysOpen && (
          <div className="p-4 space-y-3">
            <p className="text-xs text-slate-500">
              配置后所有扫描自动调用对应情报平台（子域名被动收集），结果与字典/DNS暴破合并去重。
              Key 存储在引擎本地 SQLite，不上传任何服务器。单次扫描填写的临时 Key 优先级更高。
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {keyConfigs.map(({ key, label, value, set, placeholder, desc }) => (
                <div key={key} className="space-y-1">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs text-slate-300">{label}</span>
                    {hasSavedKey(key) && (
                      <span className="chip border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs">
                        <CheckCircle2 size={10} /> 已配置
                      </span>
                    )}
                  </div>
                  <input
                    value={value}
                    onChange={(e) => set(e.target.value)}
                    placeholder={hasSavedKey(key) ? '留空沿用已保存的 Key（点击保存覆盖）' : placeholder}
                    className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-300 outline-none focus:border-cyber"
                  />
                  <p className="text-xs text-slate-600">{desc}</p>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={saveApiKeys}
                disabled={savingKeys || running}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber disabled:opacity-50"
              >
                <Save size={14} />
                {savingKeys ? '保存中…' : '保存配置'}
              </button>
              {saveMsg && (
                <span className={`text-xs ${saveMsg.startsWith('保存失败') ? 'text-sev-high' : 'text-emerald-400'}`}>
                  {saveMsg}
                </span>
              )}
              <span className="ml-auto text-xs text-slate-600">
                留空某项则该情报源不启用
              </span>
            </div>
          </div>
        )}
      </section>

      {/* ── 扫描发起 ──────────────────────────────────────────────── */}
      <Panel title="发起子域名枚举" icon={<Globe size={16} />}>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-3">
            <div className="flex-1 min-w-48">
              <label className="mb-1 block text-xs text-slate-400">目标主域名</label>
              <input
                value={domain} onChange={(e) => setDomain(e.target.value)} disabled={running}
                placeholder="example.com"
                className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-400">枚举模式</label>
              <select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)} disabled={running}
                className="rounded-lg border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200">
                <option value="all">全部模式</option>
                <option value="dict">字典爆破</option>
                <option value="brute">DNS 递归</option>
                <option value="ct">证书透明度</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-400">字典规模</label>
              <select value={dictPreset} onChange={(e) => setDictPreset(e.target.value)} disabled={running}
                className="rounded-lg border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200">
                <option value="small">小字典（~250 条）</option>
                <option value="medium">中字典（~1800 条）</option>
                <option value="large">大字典（~2300 条）</option>
                <option value="xlarge">超大字典（~61500 条）</option>
              </select>
            </div>
          </div>
          <div className="flex flex-wrap gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2" title="从已发现子域名前缀生成 prefix-dev / prod-prefix 等组合，二次解析">
              <input type="checkbox" checked={permutation} onChange={(e) => setPermutation(e.target.checked)} disabled={running} />
              排列组合增强
            </label>
            <label className="flex items-center gap-2">DNS 服务器
              <input value={resolver} onChange={(e) => setResolver(e.target.value)} disabled={running}
                className="w-44 rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs" />
            </label>
            <label className="flex items-center gap-2">并发线程
              <input type="number" min={10} max={500} value={threads}
                onChange={(e) => setThreads(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">超时 ms
              <input type="number" min={500} max={10000} value={timeout}
                onChange={(e) => setTimeout_(+e.target.value)} disabled={running}
                className="w-20 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
          </div>

          {/* 单次临时覆盖 Key（折叠） */}
          <div className="rounded-lg border border-line bg-base-700/30">
            <button
              type="button"
              onClick={() => setShowApiKeys((v) => !v)}
              className="flex w-full items-center justify-between px-3 py-2 text-xs text-slate-400 hover:text-slate-200"
            >
              <span>单次临时 Key 覆盖（留空则使用上方已保存的全局配置）</span>
              {showApiKeys ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
            {showApiKeys && (
              <div className="grid grid-cols-1 gap-2 px-3 pb-3 sm:grid-cols-2">
                {keyConfigs.map(({ key, label, value, set, placeholder }) => (
                  <label key={key} className="flex flex-col gap-1 text-xs text-slate-400">
                    {label}
                    <input value={value} onChange={(e) => set(e.target.value)} disabled={running}
                      placeholder={hasSavedKey(key) ? '留空沿用已保存的 Key' : placeholder}
                      className="rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-300 outline-none focus:border-cyber" />
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <button onClick={stopScan}
                className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={14} /> 停止
              </button>
            ) : (
              <button onClick={startScan}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber">
                <Play size={14} /> 开始枚举
              </button>
            )}
            <button onClick={() => { setResults([]); setErr(null) }} disabled={running}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <RefreshCw size={14} /> 清空
            </button>
            {results.length > 0 && !running && (
              <button onClick={exportCSV}
                className="chip border border-line bg-base-600/60 text-slate-400 ml-auto">
                <Download size={14} /> 导出 CSV
              </button>
            )}
          </div>

          {running && progress && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-2">
                  <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-cyber" />
                  {progress}
                </span>
                {progressPct > 0 && <span className="font-mono text-cyber">{progressPct}%</span>}
              </div>
              {progressPct > 0 && <Progress value={progressPct} />}
            </div>
          )}
          {err && <div className="text-sm text-sev-high">{err}</div>}
        </div>
      </Panel>

      {/* ── 结果表格 ──────────────────────────────────────────────── */}
      {results.length > 0 && (
        <Panel
          title={`发现子域名（${filtered.length}${filtered.length !== results.length ? `/${results.length}` : ''}）`}
          icon={<ChevronRight size={16} />}
          action={
            <input value={filter} onChange={(e) => setFilter(e.target.value)}
              placeholder="过滤子域/IP/CDN/来源…"
              className="rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-300 outline-none focus:border-cyber" />
          }
          bodyClass="p-0"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-slate-500">
                  <th className="px-4 py-2 font-medium">子域名</th>
                  <th className="px-4 py-2 font-medium">IP 地址</th>
                  <th className="px-4 py-2 font-medium">CDN/WAF</th>
                  <th className="px-4 py-2 font-medium">状态码</th>
                  <th className="px-4 py-2 font-medium">页面标题</th>
                  <th className="px-4 py-2 font-medium">来源</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filtered.map((r) => (
                  <tr key={r.subdomain} className="hover:bg-base-600/40">
                    <td className="px-4 py-2 font-mono text-cyber text-xs">{r.subdomain}</td>
                    <td className="px-4 py-2 font-mono text-xs text-slate-300">{r.ip.join(', ')}</td>
                    <td className="px-4 py-2 text-xs">
                      {r.cdn !== '—' ? (
                        <span className="chip border border-amber-400/30 bg-amber-400/10 text-amber-400">{r.cdn}</span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className={`px-4 py-2 font-mono text-xs ${statusColor(r.status)}`}>
                      {r.status || '—'}
                    </td>
                    <td className="px-4 py-2 text-slate-400 text-xs max-w-48 truncate" title={r.title}>{r.title || '—'}</td>
                    <td className="px-4 py-2 text-xs">
                      <span className={`chip border ${sourceChipClass[r.source] ?? 'border-line bg-base-600/60 text-slate-400'}`}>
                        {sourceLabel[r.source] ?? r.source}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* ── 历史任务 ──────────────────────────────────────────────── */}
      <Panel title="历史任务" icon={<ChevronRight size={16} />} bodyClass="p-3">
        <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload}
          emptyHint="暂无任务记录，发起一次枚举后将登记到此。" />
      </Panel>
    </div>
  )
}
