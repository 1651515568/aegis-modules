import { useState } from 'react'
import {
  Wifi, WifiOff, Moon, Server, Crown, Network, ShieldHalf,
  Radio, CircleDot, ChevronRight,
} from 'lucide-react'
import { Panel } from '@/components/ui'
import { sessions } from '@/data/mock'
import type { SessionStatus, Integrity } from '@/types'

const statusMeta: Record<SessionStatus, { label: string; cls: string; icon: typeof Wifi }> = {
  active: { label: '在线', cls: 'text-emerald-400', icon: Wifi },
  idle: { label: '空闲', cls: 'text-cyber', icon: CircleDot },
  sleeping: { label: '休眠', cls: 'text-amber-400', icon: Moon },
  lost: { label: '失联', cls: 'text-slate-500', icon: WifiOff },
}

const integrityMeta: Record<Integrity, { label: string; cls: string }> = {
  system: { label: 'SYSTEM', cls: 'text-sev-critical bg-sev-critical/10 border-sev-critical/30' },
  admin: { label: 'Admin', cls: 'text-sev-high bg-sev-high/10 border-sev-high/30' },
  high: { label: 'root/High', cls: 'text-sev-high bg-sev-high/10 border-sev-high/30' },
  medium: { label: 'Medium', cls: 'text-cyber bg-cyber/10 border-cyber/30' },
  low: { label: 'Low', cls: 'text-slate-400 bg-slate-400/10 border-slate-400/30' },
}

const quickCmds = ['sysinfo', 'getuid', 'ps', 'ipconfig', 'screenshot', 'hashdump', 'portscan', 'pivot']

function Stat({ icon, label, value, tone, sub }: { icon: React.ReactNode; label: string; value: number; tone: string; sub: string }) {
  const tones: Record<string, string> = { emerald: 'text-emerald-400', critical: 'text-sev-critical', cyber: 'text-cyber', accent: 'text-accent' }
  return (
    <div className="panel flex items-center gap-3 p-4">
      <div className={`rounded-lg border border-line bg-base-600/60 p-2.5 ${tones[tone]}`}>{icon}</div>
      <div>
        <div className={`font-mono text-2xl font-semibold ${tones[tone]}`}>{value}</div>
        <div className="text-xs text-slate-300">{label}</div>
        <div className="text-[10px] text-slate-500">{sub}</div>
      </div>
    </div>
  )
}

export default function C2DemoView() {
  const [selId, setSelId] = useState(sessions[0].id)
  const [cmd, setCmd] = useState('')
  const sel = sessions.find((s) => s.id === selId)!

  const active = sessions.filter((s) => s.status === 'active').length
  const priv = sessions.filter((s) => ['system', 'high', 'admin'].includes(s.integrity)).length

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat icon={<Radio size={18} />} label="活跃会话" value={active} tone="emerald" sub={`共 ${sessions.length} 个 Beacon`} />
        <Stat icon={<Crown size={18} />} label="高权限会话" value={priv} tone="critical" sub="SYSTEM / root / Admin" />
        <Stat icon={<Network size={18} />} label="跳板链路" value={sessions.filter((s) => s.pivot).length} tone="cyber" sub="经内网中继" />
        <Stat icon={<ShieldHalf size={18} />} label="监听器" value={4} tone="accent" sub="HTTPS / DNS / SMB / TCP" />
      </div>

      <div className="grid grid-cols-12 gap-5">
        {/* session list */}
        <div className="col-span-12 lg:col-span-5 xl:col-span-4">
          <Panel title="C2 会话列表" icon={<Server size={16} className="text-cyber" />} bodyClass="p-2 space-y-1.5">
            {sessions.map((s) => {
              const sm = statusMeta[s.status]
              const SIcon = sm.icon
              const im = integrityMeta[s.integrity]
              const activeRow = s.id === selId
              return (
                <button
                  key={s.id}
                  onClick={() => setSelId(s.id)}
                  className={`w-full rounded-lg border p-3 text-left transition ${
                    activeRow ? 'border-cyber/50 bg-cyber/5 shadow-glow' : 'border-line bg-base-700/40 hover:bg-base-600/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 font-mono text-sm text-slate-200">
                      <SIcon size={13} className={`${sm.cls} ${s.status === 'active' ? 'animate-pulse' : ''}`} />
                      {s.id}
                    </span>
                    <span className={`chip border ${im.cls} text-[10px]`}>{im.label}</span>
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-xs">
                    <span className="text-slate-300">{s.user}@{s.host}</span>
                    <span className="font-mono text-slate-500">{s.internalIp}</span>
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-500">
                    <span>{s.os} · {s.listener}</span>
                    <span className={sm.cls}>{sm.label} · {s.lastSeen}</span>
                  </div>
                  {s.pivot && (
                    <div className="mt-1.5 flex items-center gap-1 text-[10px] text-amber-400/80">
                      <Network size={10} /> 经 {s.pivot} 跳板
                    </div>
                  )}
                </button>
              )
            })}
          </Panel>
        </div>

        {/* interactive console */}
        <div className="col-span-12 lg:col-span-7 xl:col-span-8 space-y-5">
          <Panel bodyClass="p-0">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-lg text-slate-100">{sel.user}@{sel.host}</span>
                  <span className={`chip border ${integrityMeta[sel.integrity].cls}`}>{integrityMeta[sel.integrity].label}</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-0.5 font-mono text-[11px] text-slate-500">
                  <span>{sel.id}</span>
                  <span>{sel.ip}</span>
                  <span>PID {sel.pid} · {sel.process}</span>
                  <span>{sel.arch}</span>
                  <span>sleep {sel.sleep}</span>
                </div>
              </div>
              <div className="flex gap-2">
                <button className="rounded-md border border-line bg-base-600 px-2.5 py-1.5 text-xs text-slate-300 hover:text-cyber">进程列表</button>
                <button className="rounded-md border border-line bg-base-600 px-2.5 py-1.5 text-xs text-slate-300 hover:text-cyber">文件浏览</button>
                <button className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-2.5 py-1.5 text-xs text-sev-critical hover:bg-sev-critical/20">终止</button>
              </div>
            </div>

            {/* terminal */}
            <div className="relative h-80 overflow-y-auto bg-base-900/80 p-4 font-mono text-[12.5px] leading-relaxed">
              <div className="text-slate-500"># Beacon {sel.beacon} · 监听器 {sel.listener} · 建立于 {sel.openedAt}</div>
              {sel.history.map((h, i) => (
                <div key={i} className="mt-2">
                  <div className="flex items-center gap-2 text-cyber">
                    <span className="text-emerald-400">{sel.user}@{sel.host}</span>
                    <span className="text-slate-600">:~$</span>
                    <span className="text-slate-200">{h.cmd}</span>
                    <span className="ml-auto text-[10px] text-slate-700">{h.time}</span>
                  </div>
                  <pre className="mt-0.5 whitespace-pre-wrap text-emerald-300/90">{h.output}</pre>
                </div>
              ))}
              <div className="mt-2 flex items-center gap-2 text-cyber">
                <span className="text-emerald-400">{sel.user}@{sel.host}</span>
                <span className="text-slate-600">:~$</span>
                <span className="h-3.5 w-2 animate-pulse bg-cyber" />
              </div>
            </div>

            {/* prompt input */}
            <div className="flex items-center gap-2 border-t border-line p-3">
              <span className="font-mono text-sm text-emerald-400">›</span>
              <input
                value={cmd}
                onChange={(e) => setCmd(e.target.value)}
                placeholder="输入指令并回车，例如 shell whoami / pivot 10.20.4.0/24"
                className="flex-1 bg-transparent font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none"
              />
              <button className="rounded-md border border-cyber/40 bg-cyber/10 px-3 py-1.5 text-xs text-cyber hover:bg-cyber/20">执行</button>
            </div>
          </Panel>

          <Panel title="快捷指令" icon={<ChevronRight size={16} className="text-cyber" />}>
            <div className="flex flex-wrap gap-2">
              {quickCmds.map((c) => (
                <button
                  key={c}
                  onClick={() => setCmd(c)}
                  className="rounded-md border border-line bg-base-600/50 px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-cyber/40 hover:text-cyber"
                >
                  {c}
                </button>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
