<template>
  <div class="rx-page rx-fade-in">
    <header class="rx-head">
      <div>
        <div class="rx-eyebrow">扫描探测 · PROBE</div>
        <h1>Web 指纹识别</h1>
        <p class="rx-sub"><code>scan-probe</code> 模块 · 9000+ 条指纹库，CMS / WAF / 框架 / 中间件 / favicon hash 识别，多路径主动探针</p>
      </div>
    </header>

    <div class="rx-card" style="margin-bottom:18px">
      <div class="rx-card-head"><h3>发起指纹探测</h3></div>
      <div class="rx-card-pad">
        <textarea v-model="targets" class="rx-input pb-targets" rows="3" :disabled="running"
          placeholder="http://192.168.1.100&#10;https://target.com&#10;192.168.1.101:8080"></textarea>

        <div class="pb-opts">
          <label class="pb-opt">并发
            <input v-model.number="threads" type="number" min="1" max="200" :disabled="running" class="rx-input pb-num" />
          </label>
          <label class="pb-opt">超时ms
            <input v-model.number="timeoutMs" type="number" min="500" max="30000" :disabled="running" class="rx-input pb-num" style="width:90px" />
          </label>
          <label class="pb-opt pb-check">
            <input v-model="detectWaf" type="checkbox" :disabled="running" /> WAF 识别
          </label>
          <label class="pb-opt pb-check">
            <input v-model="detectCms" type="checkbox" :disabled="running" /> CMS 指纹
          </label>
          <span class="rx-spacer"></span>
          <button v-if="!running" class="rx-btn rx-btn-primary" :disabled="!targetList.length" @click="start">▸ 开始探测</button>
          <button v-else class="rx-btn rx-btn-danger" @click="stop">■ 停止</button>
          <button class="rx-btn rx-btn-ghost" :disabled="running" @click="() => { results.value = [] }">↺ 清空</button>
          <button class="rx-btn rx-btn-ghost" :disabled="!results.length" @click="exportCSV">⭳ CSV</button>
        </div>

        <div v-if="running || progress" class="pb-prog-wrap">
          <div class="pt-bar"><span :style="{ width: pct + '%' }"></span></div>
          <div class="pt-prog-meta rx-mono">
            <span><span style="color:var(--rx-cyan);animation: pulse 1s infinite">●</span> {{ progress || '探测中…' }}</span>
            <span>{{ pct }}%</span>
          </div>
        </div>
        <div v-if="errMsg" class="rx-error" style="margin-top:8px">{{ errMsg }}</div>
      </div>
    </div>

    <section class="rx-grid rx-cols-4" style="margin-bottom:18px">
      <div class="rx-stat">
        <div class="rx-stat-label">探测目标</div>
        <div class="rx-stat-val">{{ results.length || '—' }}</div>
      </div>
      <div class="rx-stat rx-amber">
        <div class="rx-stat-label">CMS 识别</div>
        <div class="rx-stat-val">{{ cmsCount || '—' }}</div>
      </div>
      <div class="rx-stat rx-red">
        <div class="rx-stat-label">WAF 保护</div>
        <div class="rx-stat-val">{{ wafCount || '—' }}</div>
      </div>
      <div class="rx-stat rx-purple">
        <div class="rx-stat-label">框架/中间件</div>
        <div class="rx-stat-val">{{ fwCount || '—' }}</div>
      </div>
    </section>

    <div class="rx-card">
      <div class="rx-card-head">
        <h3>指纹结果（{{ filtered.length }}）</h3>
        <span class="rx-right">
          <input v-model="q" class="rx-input" placeholder="过滤主机/CMS/框架/WAF…" style="width:200px" />
        </span>
      </div>
      <table class="rx-table">
        <thead>
          <tr><th>主机</th><th>状态</th><th>CMS · 框架 · Favicon</th><th>WAF</th><th>Server</th><th>OS</th><th>标题</th></tr>
        </thead>
        <tbody>
          <tr v-for="(r, i) in filtered" :key="i">
            <td class="mono" style="color:var(--rx-cyan);font-size:12px">{{ r.protocol }}://{{ r.host }}:{{ r.port }}</td>
            <td class="mono" :class="statusClass(r.statusCode)" style="font-weight:600">{{ r.statusCode || '—' }}</td>
            <td style="max-width:200px">
              <div class="pb-chips">
                <template v-if="r.components && r.components.length">
                  <span v-for="(c, ci) in r.components" :key="ci" class="rx-badge" :class="ci === 0 ? 'rx-run' : 'pb-chip-fw'">{{ c }}</span>
                </template>
                <template v-else>
                  <span v-if="r.cms !== '—'" class="rx-badge rx-run">{{ r.cms }}</span>
                  <span v-if="r.framework !== '—'" class="rx-badge pb-chip-fw">{{ r.framework }}</span>
                  <span v-if="r.cms === '—' && r.framework === '—'" class="rx-dim">—</span>
                </template>
                <span v-if="r.faviconHash" class="rx-badge rx-info rx-mono" style="font-size:10px" :title="'Favicon Hash: ' + r.faviconHash">#{{ r.faviconHash }}</span>
              </div>
            </td>
            <td>
              <span v-if="r.waf !== '无'" class="rx-badge rx-med">{{ r.waf }}</span>
              <span v-else class="rx-dim">—</span>
            </td>
            <td class="rx-dim" style="font-size:12px;max-width:120px;overflow:hidden;text-overflow:ellipsis">{{ r.server }}</td>
            <td class="rx-dim" style="font-size:12px">{{ r.os !== '—' ? r.os : '—' }}</td>
            <td class="rx-dim" style="font-size:12px;max-width:140px;overflow:hidden;text-overflow:ellipsis">{{ r.title || '—' }}</td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="7" class="rx-empty">{{ running ? '探测中，正在识别目标指纹…' : '暂无结果（填写目标后点「开始探测」）' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
declare const RedOps: any
const MID = 'scan-probe'

const targets = ref('')
const threads = ref(20)
const timeoutMs = ref(5000)
const detectWaf = ref(true)
const detectCms = ref(true)
const q = ref('')
const running = ref(false)
const progress = ref('')
const errMsg = ref('')
const pct = ref(0)

interface ProbeResult {
  host: string; port: number; protocol: string; cms: string; framework: string
  waf: string; server: string; title: string; statusCode: number; os: string
  faviconHash?: number; components?: string[]
}

const results = ref<ProbeResult[]>([])
let taskId = ''
let timer: any = null

const targetList = computed(() => targets.value.split('\n').map(s => s.trim()).filter(Boolean))
const cmsCount = computed(() => results.value.filter(r => r.cms !== '—').length)
const wafCount = computed(() => results.value.filter(r => r.waf !== '无').length)
const fwCount = computed(() => new Set(results.value.filter(r => r.framework !== '—').map(r => r.framework)).size)
const filtered = computed(() => {
  const kw = q.value.trim().toLowerCase()
  if (!kw) return results.value
  return results.value.filter(r =>
    [r.host, r.cms, r.framework, r.waf, r.server, r.title, ...(r.components ?? [])].join(' ').toLowerCase().includes(kw)
  )
})

function statusClass(code: number): string {
  if (!code) return 'rx-dim'
  if (code < 300) return 'pb-code-ok'
  if (code < 400) return 'pb-code-redirect'
  return 'pb-code-err'
}

function pollTask() {
  if (timer) clearTimeout(timer)
  const tick = async () => {
    try {
      const t = await RedOps.api(MID, `/tasks/${taskId}`).then((r: Response) => r.json())
      pct.value = t.progress ?? 0
      progress.value = t.message ?? '探测中…'
      if (t.status === 'succeeded') {
        running.value = false; timer = null
        progress.value = ''
        const r = t.result as { results?: ProbeResult[] } | null
        if (r?.results?.length) { results.value = r.results }
        else { await loadResults() }
        RedOps?.toast?.('探测完成', 'ok')
        return
      }
      if (t.status === 'failed') {
        running.value = false; timer = null; progress.value = ''
        errMsg.value = t.error ?? '探测失败'
        return
      }
      timer = setTimeout(tick, 1500)
    } catch { timer = setTimeout(tick, 2000) }
  }
  timer = setTimeout(tick, 800)
}

async function loadResults() {
  try { const d = await RedOps.api(MID, '/results').then((r: Response) => r.json()); results.value = d.items ?? [] } catch { /* ignore */ }
}

async function start() {
  if (!targetList.value.length) { RedOps?.toast?.('请先填写至少一个目标', 'warn'); return }
  errMsg.value = ''; running.value = true; pct.value = 0; progress.value = '提交任务…'
  results.value = []
  try {
    const res = await RedOps.api(MID, '/invoke', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        function: 'probe',
        params: { targets: targetList.value, threads: threads.value, timeoutMs: timeoutMs.value, detectWaf: detectWaf.value, detectCms: detectCms.value },
      }),
    })
    if (res.status === 409) { running.value = false; progress.value = ''; RedOps?.toast?.('已有探测任务在运行', 'warn'); return }
    if (!res.ok) { running.value = false; progress.value = ''; const j = await res.json().catch(() => ({})); RedOps?.toast?.(j.error || '发起失败', 'err'); return }
    const j = await res.json()
    taskId = j.taskId ?? ''
    progress.value = '探测中…'
    if (taskId) { pollTask() } else { running.value = false; progress.value = ''; RedOps?.toast?.('发起失败：未返回 taskId', 'err') }
  } catch (e: any) { running.value = false; progress.value = ''; errMsg.value = e?.message ?? String(e) }
}

async function stop() {
  try { await RedOps.api(MID, '/stop', { method: 'POST' }); running.value = false; progress.value = ''; if (timer) clearTimeout(timer); RedOps?.toast?.('已请求停止', 'warn') } catch { /* ignore */ }
}

function exportCSV() {
  const header = '主机,端口,协议,状态码,CMS,框架,组件,WAF,Server,标题,OS,FaviconHash'
  const rows = results.value.map(r => [
    r.host, r.port, r.protocol, r.statusCode, r.cms, r.framework,
    (r.components ?? []).join('|'), r.waf, r.server, r.title, r.os, r.faviconHash ?? '',
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
  const csv = [header, ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'probe-results.csv'
  document.body.appendChild(a); a.click(); a.remove()
  RedOps?.toast?.('已导出 CSV', 'ok')
}

onMounted(loadResults)
onUnmounted(() => { if (timer) clearTimeout(timer) })
</script>

<style scoped>
.pb-targets { width: 100%; resize: vertical; font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 12.5px; line-height: 1.6; }
.pb-opts { display: flex; align-items: center; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
.pb-opt { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--rx-mid, #94a3b8); }
.pb-num { width: 80px; }
.pb-check { cursor: pointer; }
.pb-check input { accent-color: var(--rx-cyan, #22d3ee); }
.rx-btn-danger { background: rgba(244, 63, 94, .14); border-color: rgba(244, 63, 94, .4); color: #fda4af; }
.rx-btn-ghost { background: rgba(34, 211, 238, .08); border-color: rgba(34, 211, 238, .28); color: #7dd3fc; font-size: 12px; padding: 5px 10px; }
.rx-btn-ghost:disabled { opacity: .4; cursor: not-allowed; }
.pb-prog-wrap { margin-top: 14px; }
.pt-bar { height: 8px; border-radius: 5px; background: rgba(7, 10, 16, .6); overflow: hidden; border: 1px solid var(--rx-line, #1d2533); }
.pt-bar span { display: block; height: 100%; background: linear-gradient(90deg, #22d3ee, #6366f1); transition: width .4s ease; }
.pt-prog-meta { display: flex; justify-content: space-between; font-size: 11.5px; color: var(--rx-dim, #6b7689); margin-top: 6px; }
.pb-chips { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
.pb-chip-fw { background: rgba(168, 85, 247, .12); border: 1px solid rgba(168, 85, 247, .3); color: #c084fc; }
.pb-code-ok { color: #4ade80; }
.pb-code-redirect { color: var(--rx-cyan, #22d3ee); }
.pb-code-err { color: #f87171; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .3; } }
</style>
