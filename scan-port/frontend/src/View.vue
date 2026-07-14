<template>
  <div class="rx-page rx-fade-in">
    <header class="rx-head">
      <div>
        <div class="rx-eyebrow">扫描探测 · PORTS</div>
        <h1>端口扫描</h1>
        <p class="rx-sub"><code>scan-port</code> 模块 · TCP/UDP/SYN 三模式端口扫描，服务识别，Banner 抓取，主动协议探针</p>
      </div>
    </header>

    <div class="rx-card" style="margin-bottom:18px">
      <div class="rx-card-head">
        <h3>发起端口扫描</h3>
      </div>
      <div class="rx-card-pad">
        <textarea v-model="targets" class="rx-input pt-targets" rows="3" :disabled="running"
          placeholder="目标，每行一个：192.168.1.0/24 或 example.com 或 10.0.0.5"></textarea>

        <div class="pt-opts">
          <label class="pt-opt">端口
            <select v-model="portSpec" :disabled="running" class="rx-input">
              <option value="top100">top100（高频端口）</option>
              <option value="top500">top500（约 370 个）</option>
              <option value="top1000">top1000（推荐）</option>
              <option value="all">全端口（慎用）</option>
              <option value="custom">自定义</option>
            </select>
          </label>
          <label v-if="portSpec === 'custom'" class="pt-opt">自定义端口
            <input v-model="portsCustom" :disabled="running" placeholder="22,80,443,8000-8100" class="rx-input" style="width:180px" />
          </label>
          <label class="pt-opt">引擎
            <select v-model="mode" :disabled="running" class="rx-input">
              <option value="masscan">masscan（高速·需管理员）</option>
              <option value="connect">connect（免提权）</option>
              <option value="syn">SYN（需 npcap）</option>
            </select>
          </label>
          <label class="pt-opt">协议
            <select v-model="proto" :disabled="running" class="rx-input">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">TCP+UDP</option>
            </select>
          </label>
          <label class="pt-opt">速率
            <input v-model.number="rate" type="number" min="0" max="100000" :disabled="running" class="rx-input pt-num" />
          </label>
          <label class="pt-opt">并发
            <input v-model.number="concurrency" type="number" min="1" max="1024" :disabled="running" class="rx-input pt-num" />
          </label>
          <label class="pt-opt">超时ms
            <input v-model.number="timeout" type="number" min="100" max="10000" :disabled="running" class="rx-input pt-num" />
          </label>
          <label class="pt-opt pt-check">
            <input v-model="discovery" type="checkbox" :disabled="running" /> 存活探测
          </label>
          <label class="pt-opt pt-check">
            <input v-model="svc" type="checkbox" :disabled="running" /> 服务识别
          </label>
          <label class="pt-opt pt-check">
            <input v-model="banner" type="checkbox" :disabled="running" /> 抓取 Banner
          </label>
          <span class="rx-spacer"></span>
          <button v-if="!running" class="rx-btn rx-btn-primary" :disabled="!targetList.length" @click="start">▸ 发起扫描</button>
          <button v-else class="rx-btn rx-btn-danger" @click="stop">■ 停止扫描</button>
          <button class="rx-btn rx-btn-ghost" :disabled="!ports.length" @click="exportAs('json')">⭳ JSON</button>
          <button class="rx-btn rx-btn-ghost" :disabled="!ports.length" @click="exportAs('csv')">⭳ CSV</button>
          <button class="rx-btn rx-btn-ghost" :disabled="!ports.length" @click="exportAs('html')">⭳ 报告</button>
        </div>

        <div v-if="running || scan.probed > 0" class="pt-progress">
          <div class="pt-bar"><span :style="{ width: pct + '%' }"></span></div>
          <div class="pt-prog-meta rx-mono">
            <span>{{ running ? '扫描中' : '已完成' }} · {{ scan.phase || '—' }} {{ scan.target ? '· ' + scan.target : '' }}</span>
            <span>{{ scan.probed }} / {{ scan.total || '?' }} · 开放 <b style="color:var(--rx-cyan)">{{ scan.found }}</b> · {{ pct }}%</span>
          </div>
          <div v-if="scan.err" class="rx-error" style="margin-top:8px">{{ scan.err }}</div>
        </div>
      </div>
    </div>

    <section class="rx-grid rx-cols-4" style="margin-bottom:18px">
      <div class="rx-stat">
        <div class="rx-stat-label">开放端口</div>
        <div class="rx-stat-val">{{ ports.length || '—' }}</div>
      </div>
      <div class="rx-stat">
        <div class="rx-stat-label">涉及主机</div>
        <div class="rx-stat-val">{{ hostCount || '—' }}</div>
      </div>
      <div class="rx-stat">
        <div class="rx-stat-label">TCP / UDP</div>
        <div class="rx-stat-val rx-mono" style="font-size:18px">{{ tcpCount }} / {{ udpCount }}</div>
      </div>
      <div class="rx-stat">
        <div class="rx-stat-label">本次引擎</div>
        <div class="rx-stat-val" style="font-size:14px">{{ scan.engine || '—' }}</div>
      </div>
    </section>

    <div class="rx-card">
      <div class="rx-card-head">
        <h3>开放端口（{{ filtered.length }}）</h3>
        <span class="rx-right">
          <input v-model="q" class="rx-input" placeholder="过滤主机/端口/服务…" style="width:200px" />
        </span>
      </div>
      <table class="rx-table">
        <thead>
          <tr><th>主机</th><th>端口</th><th>协议</th><th>服务</th><th>OS</th><th>Banner</th></tr>
        </thead>
        <tbody>
          <tr v-for="p in filtered" :key="p.host+'/'+p.proto+'/'+p.port">
            <td class="mono">{{ p.host }}</td>
            <td class="mono" style="color:var(--rx-cyan)">{{ p.port }}</td>
            <td><span class="rx-badge rx-info">{{ p.proto }}</span></td>
            <td>{{ p.service || '—' }}</td>
            <td class="rx-dim" style="font-size:12px">{{ p.osGuess || '—' }}</td>
            <td class="mono rx-dim" style="font-size:11px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ p.banner || '—' }}</td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="6" class="rx-empty">{{ running ? '扫描中，正在发现开放端口…' : '暂无开放端口（填写目标后点「发起扫描」）' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
declare const RedOps: any
const MID = 'scan-port'

const targets = ref('')
const portSpec = ref('top1000')
const portsCustom = ref('22,80,443')
const mode = ref('masscan')
const proto = ref('tcp')
const rate = ref(1000)
const concurrency = ref(256)
const timeout = ref(1500)
const discovery = ref(false)
const svc = ref(true)
const banner = ref(true)
const q = ref('')

interface Port { host: string; port: number; proto: string; service: string; banner: string; osGuess: string }
interface ScanStatus {
  running: boolean; phase: string; total: number; probed: number; found: number
  rate: number; engine: string; target: string; err: string; elapsedMs: number
}

const ports = ref<Port[]>([])
const scan = ref<ScanStatus>({ running: false, phase: '', total: 0, probed: 0, found: 0, rate: 0, engine: '', target: '', err: '', elapsedMs: 0 })
let timer: any = null

const running = computed(() => scan.value.running)
const targetList = computed(() => targets.value.split('\n').map(s => s.trim()).filter(Boolean))
const hostCount = computed(() => new Set(ports.value.map(p => p.host)).size)
const tcpCount = computed(() => ports.value.filter(p => p.proto === 'tcp').length)
const udpCount = computed(() => ports.value.filter(p => p.proto === 'udp').length)
const pct = computed(() => scan.value.total > 0 ? Math.min(100, Math.round(scan.value.probed / scan.value.total * 100)) : (scan.value.running ? 0 : 100))
const filtered = computed(() => {
  const kw = q.value.trim().toLowerCase()
  if (!kw) return ports.value
  return ports.value.filter(p => [p.host, String(p.port), p.service || '', p.banner || ''].join(' ').toLowerCase().includes(kw))
})

async function refresh() {
  try {
    const [st, pr] = await Promise.all([
      RedOps.api(MID, '/scan/status').then((r: Response) => r.json()),
      RedOps.api(MID, '/ports').then((r: Response) => r.json()),
    ])
    scan.value = st.status ?? scan.value
    ports.value = pr.items ?? []
  } catch { /* ignore polling errors */ }
}

function poll() {
  if (timer) clearTimeout(timer)
  const tick = async () => {
    await refresh()
    if (scan.value.running) { timer = setTimeout(tick, 1500) } else { timer = null }
  }
  timer = setTimeout(tick, 800)
}

async function start() {
  if (!targetList.value.length) { RedOps?.toast?.('请先填写扫描目标', 'warn'); return }
  try {
    const res = await RedOps.api(MID, '/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets: targetList.value, ports: portSpec.value, portsCustom: portsCustom.value,
        mode: mode.value, proto: proto.value, rate: rate.value,
        concurrency: concurrency.value, timeout: timeout.value,
        discovery: discovery.value, svc: svc.value, banner: banner.value,
      }),
    })
    if (res.status === 409) { RedOps?.toast?.('已有扫描在运行，请先停止', 'warn'); return }
    if (!res.ok) { const j = await res.json().catch(() => ({})); RedOps?.toast?.(j.error || '发起失败', 'err'); return }
    const j = await res.json()
    scan.value = j.status ?? scan.value
    ports.value = []
    RedOps?.toast?.(`已对 ${targetList.value.length} 个目标发起扫描`, 'ok')
    poll()
  } catch (e: any) { RedOps?.toast?.('发起失败: ' + (e?.message ?? e), 'err') }
}

async function stop() {
  try { await RedOps.api(MID, '/scan/stop', { method: 'POST' }); RedOps?.toast?.('已请求停止', 'warn') } catch { /* ignore */ }
}

async function exportAs(fmt: string) {
  try {
    const res = await RedOps.api(MID, `/export?format=${fmt}`)
    if (!res.ok) { RedOps?.toast?.('导出失败', 'err'); return }
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `portscan.${fmt}`
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url)
    RedOps?.toast?.(`已导出 ${fmt.toUpperCase()}`, 'ok')
  } catch (e: any) { RedOps?.toast?.('导出失败: ' + (e?.message ?? e), 'err') }
}

onMounted(async () => { await refresh(); if (scan.value.running) poll() })
onUnmounted(() => { if (timer) clearTimeout(timer) })
</script>

<style scoped>
.pt-targets { width: 100%; resize: vertical; font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 12.5px; line-height: 1.6; }
.pt-opts { display: flex; align-items: center; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
.pt-opt { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--rx-mid, #94a3b8); }
.pt-num { width: 84px; }
.pt-check { cursor: pointer; }
.pt-check input { accent-color: var(--rx-cyan, #22d3ee); }
.rx-btn-danger { background: rgba(244, 63, 94, .14); border-color: rgba(244, 63, 94, .4); color: #fda4af; }
.rx-btn-ghost { background: rgba(34, 211, 238, .08); border-color: rgba(34, 211, 238, .28); color: #7dd3fc; font-size: 12px; padding: 5px 10px; }
.rx-btn-ghost:disabled { opacity: .4; cursor: not-allowed; }
.pt-progress { margin-top: 14px; }
.pt-bar { height: 8px; border-radius: 5px; background: rgba(7, 10, 16, .6); overflow: hidden; border: 1px solid var(--rx-line, #1d2533); }
.pt-bar span { display: block; height: 100%; background: linear-gradient(90deg, #22d3ee, #6366f1); transition: width .4s ease; }
.pt-prog-meta { display: flex; justify-content: space-between; font-size: 11.5px; color: var(--rx-dim, #6b7689); margin-top: 6px; }
</style>
