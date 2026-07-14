import { useCallback, useEffect, useRef, useState } from 'react'
import {
  DatabaseBackup, FileSearch, Globe, ShieldAlert, Play, Square,
  Trash2, Download, RefreshCw, ChevronRight,
} from 'lucide-react'
import { Panel, StatCard, Progress, SeverityTag } from '@/components/ui'
import { engineGet, enginePost, engineDownload } from '@/lib/engine'
import { ApiError } from '@/lib/api'
import { createTask, updateTask } from '@/lib/tasks'
import TaskList from '@/components/TaskList'
import type { Severity } from '@/types'

const CAP = 'scan-backup'

interface Stats {
  total: number; accessible: number; hosts: number
  high: number; med: number; low: number
  src: number; db: number; conf: number; other: number
  demo: boolean; module: string; version: string
}

interface ScanStatus {
  running: boolean; total: number; probed: number; found: number
  target: string; startedAt: string; endedAt: string; err: string
  demo: boolean; resumable: boolean
}

interface Evidence { request: string; response: string; note: string }
interface Hit {
  id: string; url: string; file: string; kind: string; size: string
  code: number; rule: string; host: string; severity: string; at: string
  note: string; detail: string; sample: string; evidence: Evidence
  remediation: string; refs: string[]; chain: string[]
}

const SEV_MAP: Record<string, Severity> = { 高危: 'high', 中危: 'medium', 低危: 'low' }
const sevOf = (s: string): Severity => SEV_MAP[s] ?? 'info'

export default function View() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [hits, setHits] = useState<Hit[]>([])
  const [targets, setTargets] = useState('')
  const [concurrency, setConcurrency] = useState(16)
  const [ratePerSec, setRatePerSec] = useState(20)
  const [maxDepth, setMaxDepth] = useState(1)
  const [crawl, setCrawl] = useState(false)
  const [cookie, setCookie] = useState('')
  const [authorization, setAuthorization] = useState('')
  const [extraWordlist, setExtraWordlist] = useState('')
  const [extraWordlistURL, setExtraWordlistURL] = useState('')
  const [customWordlistText, setCustomWordlistText] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [taskReload, setTaskReload] = useState(0)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  const refresh = useCallback(async () => {
    const [s, st, h] = await Promise.all([
      engineGet<Stats>(CAP, '/stats'),
      engineGet<ScanStatus>(CAP, '/scan/status'),
      engineGet<{ items: Hit[] }>(CAP, '/hits'),
    ])
    setStats(s); setStatus(st); setHits(h.items ?? [])
    return st
  }, [])

  // 轮询:仅在扫描运行时拉取实时进度/命中(界面展示)。进度与结果的台账固化由
  // 后端 reconcile-on-read 负责(读取任务时按 task_id 拉引擎落库结果),本端不再镜像。
  const startPolling = useCallback(() => {
    if (timer.current) return
    timer.current = setInterval(async () => {
      try {
        const st = await refresh()
        if (!st.running && timer.current) {
          clearInterval(timer.current); timer.current = null
          setTaskReload((n) => n + 1) // 扫描结束:刷新历史任务,触发后端固化终态
        }
      } catch { /* 轮询期间瞬时错误忽略 */ }
    }, 2000)
  }, [refresh])

  useEffect(() => {
    refresh().then((st) => { if (st.running) startPolling() }).catch((e) => setErr(String(e?.message ?? e)))
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
    if (!list.length) { setErr('请填写至少一个目标（http(s) URL 或域名，每行一个）'); return }
    await call(async () => {
      const customWordlistTextLines = customWordlistText.split('\n').map((l) => l.trim()).filter(Boolean)
      const params = {
        targets: list, concurrency, ratePerSec, maxDepth, crawl,
        cookie, authorization, extraWordlist, extraWordlistURL,
        customWordlistText: customWordlistTextLines,
      }
      // 统一 task_id:先向系统申请 id 落台账,再透传给引擎 /invoke。
      // 引擎按 id 持久化状态/结果,后端读取时固化,无须前端镜像。
      const t = await createTask({ capabilityKey: CAP, action: 'scan', params })
      setTaskReload((n) => n + 1)
      try {
        await enginePost(CAP, '/invoke', { taskId: t.id, function: 'scan', params })
      } catch (e) {
        // 引擎拒绝/不可达:把台账直接落失败终态,避免悬空 pending。
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

  return (
    <div className="space-y-4 animate-fade-in">
      {stats?.demo && (
        <div className="rounded-lg border border-sev-info/30 bg-sev-info/10 px-4 py-2 text-sm text-sev-info">
          当前展示为演示数据（尚未执行真实扫描）。填写目标并发起扫描后将替换为真实结果。
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="命中总数" value={stats?.total ?? '—'} icon={<FileSearch size={18} />} />
        <StatCard label="可访问" value={stats?.accessible ?? '—'} sub="状态码 <300" tone="high" icon={<DatabaseBackup size={18} />} />
        <StatCard label="涉及主机" value={stats?.hosts ?? '—'} icon={<Globe size={18} />} />
        <StatCard label="高危" value={stats?.high ?? '—'} tone="critical" icon={<ShieldAlert size={18} />} />
      </div>

      <Panel title="发起备份/敏感文件探测" icon={<FileSearch size={16} />}>
        <div className="space-y-3">
          <textarea
            className="w-full rounded-lg border border-line bg-base-700/60 p-3 font-mono text-sm text-slate-200 outline-none focus:border-cyber"
            rows={3} placeholder="目标，每行一个：https://example.com 或 example.com"
            value={targets} onChange={(e) => setTargets(e.target.value)} disabled={running}
          />
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">并发
              <input type="number" min={1} max={32} value={concurrency}
                onChange={(e) => setConcurrency(+e.target.value)} disabled={running}
                className="w-16 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">速率/秒
              <input type="number" min={1} max={100} value={ratePerSec}
                onChange={(e) => setRatePerSec(+e.target.value)} disabled={running}
                className="w-16 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">递归深度
              <input type="number" min={0} max={3} value={maxDepth}
                onChange={(e) => setMaxDepth(+e.target.value)} disabled={running}
                className="w-16 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={crawl} onChange={(e) => setCrawl(e.target.checked)} disabled={running} />
              抓取页面发现路径
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2" title="目标需要登录时填写；格式与浏览器相同">Cookie
              <input value={cookie} onChange={(e) => setCookie(e.target.value)} disabled={running}
                placeholder="PHPSESSID=abc123; token=xyz"
                className="w-64 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
            <label className="flex items-center gap-2" title="HTTP Authorization 头，支持 Bearer / Basic">Auth
              <input value={authorization} onChange={(e) => setAuthorization(e.target.value)} disabled={running}
                placeholder="Bearer eyJhbGci..."
                className="w-64 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">扩展字典
              <select value={extraWordlist} onChange={(e) => setExtraWordlist(e.target.value)} disabled={running}
                className="rounded border border-line bg-base-700/60 px-2 py-1">
                <option value="">不使用</option>
                <option value="raft-medium-files">raft-medium-files（内置）</option>
                <option value="raft-medium-dirs">raft-medium-dirs（内置）</option>
                <option value="raft-large-files">raft-large-files（下载）</option>
                <option value="raft-medium-directories">raft-medium-directories（下载）</option>
                <option value="dirsearch">dirsearch（下载）</option>
                <option value="custom">自定义 URL</option>
              </select>
            </label>
            {extraWordlist === 'custom' && (
              <label className="flex items-center gap-2">字典 URL
                <input value={extraWordlistURL} onChange={(e) => setExtraWordlistURL(e.target.value)} disabled={running}
                  placeholder="https://example.com/wordlist.txt"
                  className="w-80 rounded border border-line bg-base-700/60 px-2 py-1 font-mono" />
              </label>
            )}
          </div>
          <div className="space-y-1">
            <label className="text-xs text-slate-500">自定义字典（粘贴路径，每行一条，与内置字典叠加）</label>
            <textarea
              className="w-full rounded-lg border border-line bg-base-700/60 p-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
              rows={2} placeholder={"admin/config.php\n.env\n.git/config"}
              value={customWordlistText} onChange={(e) => setCustomWordlistText(e.target.value)} disabled={running}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <button onClick={() => call(() => enginePost(CAP, '/scan/stop'))} disabled={busy}
                className="chip border border-sev-high/40 bg-sev-high/10 text-sev-high">
                <Square size={14} /> 停止扫描
              </button>
            ) : (
              <button onClick={startScan} disabled={busy}
                className="chip border border-cyber/40 bg-cyber/10 text-cyber">
                <Play size={14} /> 发起扫描
              </button>
            )}
            {status?.resumable && !running && (
              <button onClick={() => call(async () => {
                // 续扫是对上次未完成任务的延续(引擎 /scan/resume 不另起 task_id),
                // 仅恢复实时视图;不新登记台账。
                await enginePost(CAP, '/scan/resume')
                startPolling()
              })} disabled={busy}
                className="chip border border-line bg-base-600/60 text-slate-300">
                <RefreshCw size={14} /> 续扫
              </button>
            )}
            <button onClick={() => call(() => enginePost(CAP, '/hits/clear'))} disabled={busy || running}
              className="chip border border-line bg-base-600/60 text-slate-300">
              <Trash2 size={14} /> 清空
            </button>
            <div className="ml-auto flex items-center gap-1">
              {(['json', 'csv', 'html'] as const).map((f) => (
                <button key={f} onClick={() => engineDownload(CAP, '/export', `backup-hits.${f}`, { format: f })}
                  className="chip border border-line bg-base-600/60 text-slate-400">
                  <Download size={14} /> {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {running && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-slate-400">
                <span>{status?.target || '扫描中…'}</span>
                <span className="font-mono">{status?.probed}/{status?.total}（命中 {status?.found}）</span>
              </div>
              <Progress value={pct} />
            </div>
          )}
          {err && <div className="text-sm text-sev-high">{err}</div>}
        </div>
      </Panel>

      <Panel title={`命中清单（${hits.length}）`} icon={<ShieldAlert size={16} />} bodyClass="p-0">
        <div className="divide-y divide-line">
          {hits.length === 0 && <div className="p-6 text-center text-sm text-slate-500">暂无命中</div>}
          {hits.map((h) => (
            <div key={h.id}>
              <button onClick={() => setExpanded(expanded === h.id ? null : h.id)}
                className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-base-600/40">
                <ChevronRight size={14} className={`shrink-0 text-slate-500 transition-transform ${expanded === h.id ? 'rotate-90' : ''}`} />
                <SeverityTag severity={sevOf(h.severity)} />
                <span className="font-mono text-sm text-slate-200">{h.file}</span>
                <span className="text-xs text-slate-500">{h.host}</span>
                <span className="ml-auto font-mono text-xs text-slate-400">HTTP {h.code}</span>
                <span className="chip border border-line bg-base-600/60 text-xs text-slate-400">{h.kind}</span>
              </button>
              {expanded === h.id && (
                <div className="space-y-2 bg-base-800/60 px-11 py-3 text-sm">
                  <div className="text-slate-300">{h.note}</div>
                  <div className="text-xs text-slate-400">{h.detail}</div>
                  <div className="grid gap-2 lg:grid-cols-2">
                    <pre className="overflow-x-auto rounded border border-line bg-base-900/60 p-2 font-mono text-xs text-slate-400">{h.evidence?.request}</pre>
                    <pre className="overflow-x-auto rounded border border-line bg-base-900/60 p-2 font-mono text-xs text-slate-400">{h.evidence?.response}</pre>
                  </div>
                  <div className="text-xs"><span className="text-cyber">处置建议：</span><span className="text-slate-400">{h.remediation}</span></div>
                  <div className="flex flex-wrap gap-1">
                    {h.refs?.map((r) => <span key={r} className="chip border border-line bg-base-600/60 text-xs text-slate-500">{r}</span>)}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="历史任务" icon={<FileSearch size={16} />} bodyClass="p-3">
        <TaskList params={{ capabilityKey: CAP }} showCapability={false} reloadToken={taskReload}
          emptyHint="暂无任务记录，发起一次扫描后将登记到此。" />
      </Panel>
    </div>
  )
}
