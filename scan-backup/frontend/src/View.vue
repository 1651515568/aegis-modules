<template>
  <div class="rx-page rx-fade-in">
    <header class="rx-head">
      <div>
        <div class="rx-eyebrow">扫描探测 · BACKUP</div>
        <h1>备份文件</h1>
        <p class="rx-sub"><code>backup</code> 模块 · 对真实目标探测备份 / 敏感文件泄露(.zip / .bak / .sql / .git / .env…),仅探存在性不取内容</p>
      </div>
      <div class="rx-actions">
        <span class="rx-demo-flag" :class="{ live: !isDemo }">
          {{ isDemo ? '演示种子数据 · 未跑真实扫描' : '实测数据 · HEAD/Range(≤16B,soft-404 校准≤512B),不下载文件体' }}
        </span>
      </div>
    </header>

    <!-- 真实扫描控制台 -->
    <div class="rx-card bk-scan" style="margin-bottom:18px">
      <div class="rx-card-head">
        <h3>真实存在性探测</h3>
        <span class="rx-right rx-mono" style="font-size:12px">
          字典 {{ dict.baseEntries || '—' }} 条 + 主机名派生 · SecLists + OWASP
        </span>
      </div>
      <div class="rx-card-pad">
        <textarea v-model="targets" class="rx-input bk-targets" rows="2"
          placeholder="目标 URL / 域名,每行或逗号分隔，如：&#10;https://www.example.com&#10;oa.example.com, 203.0.113.18"></textarea>
        <div class="bk-opts">
          <label class="bk-opt">每主机候选上限
            <input v-model.number="maxPerHost" type="number" min="50" max="12000" class="rx-input bk-num" />
          </label>
          <label class="bk-opt">并发
            <input v-model.number="concurrency" type="number" min="1" max="32" class="rx-input bk-num" />
          </label>
          <label class="bk-opt">限速 req/s
            <input v-model.number="ratePerSec" type="number" min="1" max="100" class="rx-input bk-num" title="全局每秒请求数上限,命中 429/503 自动退避降速" />
          </label>
          <label class="bk-opt">递归深度
            <input v-model.number="maxDepth" type="number" min="0" max="3" class="rx-input bk-num" title="发现存在的目录后向下递归探测的层数;0=关闭,仅在干净 404 站点生效" />
          </label>
          <label class="bk-opt">时长上限(分)
            <input v-model.number="maxDurationMin" type="number" min="0" max="1440" class="rx-input bk-num" title="扫描总时长上限(分钟),到点优雅停止并保存已命中;0=不限" />
          </label>
          <label class="bk-opt bk-check">
            <input v-model="includeEditor" type="checkbox" /> 文件名套编辑器遗留后缀(~ .bak .old…)
          </label>
          <label class="bk-opt bk-check">
            <input v-model="crawl" type="checkbox" /> 智能爬取(提取真实文件名/目录派生候选)
          </label>
          <span class="rx-spacer"></span>
          <button v-if="!scan.running && scan.resumable" class="rx-btn rx-btn-ghost" @click="resume" title="继续上次未完成的扫描(跳过已完成目标)">⟳ 续扫</button>
          <button v-if="!scan.running" class="rx-btn rx-btn-primary" :disabled="!targetList.length" @click="start">
            ▸ 开始真实探测
          </button>
          <button v-else class="rx-btn rx-btn-danger" @click="stop">■ 停止</button>
        </div>

        <!-- 进度 -->
        <div v-if="scan.running || scan.probed > 0" class="bk-progress">
          <div class="bk-bar"><span :style="{ width: pct + '%' }"></span></div>
          <div class="bk-prog-meta rx-mono">
            <span>{{ scan.running ? '探测中' : '已完成' }} · {{ scan.target || '—' }}</span>
            <span>{{ scan.probed }} / {{ scan.total || '?' }} 候选 · 命中 <b style="color:var(--rx-cyan)">{{ scan.found }}</b> · {{ pct }}%</span>
          </div>
          <div v-if="scan.err" class="rx-error" style="margin-top:8px">{{ scan.err }}</div>
        </div>
        <p class="bk-disclaimer">
          ⚲ 探测疑似备份/敏感文件:默认仅 HEAD + Range ≤16B(soft-404 站点另读 ≤512B 做相似度校准),绝不下载其文件体。智能爬取仅获取目标普通页面(HTML/robots/sitemap,单页 ≤256KB)以提取真实文件名与目录。遇 401/403 仅标记不做绕过。请仅对已授权目标使用。
        </p>
      </div>
    </div>

    <!-- 统计磁贴 -->
    <section class="rx-grid rx-cols-4" style="margin-bottom:18px">
      <div class="rx-stat rx-red">
        <div class="rx-stat-label">高危命中</div>
        <div class="rx-stat-val">{{ tile('high', count('高危')) }}</div>
        <div class="rx-stat-sub">可访问</div>
      </div>
      <div class="rx-stat rx-amber">
        <div class="rx-stat-label">中危命中</div>
        <div class="rx-stat-val">{{ tile('med', count('中危')) }}</div>
      </div>
      <div class="rx-stat">
        <div class="rx-stat-label">命中文件</div>
        <div class="rx-stat-val">{{ tile('total', hits.length) }}<small> / 可访问 {{ tile('accessible', accessibleLocal) }}</small></div>
      </div>
      <div class="rx-stat rx-purple">
        <div class="rx-stat-label">命中主机数</div>
        <div class="rx-stat-val">{{ tile('hosts', hostLocal) }}</div>
        <div class="rx-stat-sub">across {{ hits.length }} 命中</div>
      </div>
    </section>

    <div class="rx-card" style="margin-bottom:18px">
      <div class="rx-card-head"><h3>泄露类型占比</h3><span class="rx-right">{{ hits.length }} 命中</span></div>
      <div class="rx-card-pad">
        <div class="rx-segbar">
          <span v-for="k in kindDist" :key="k.k" :style="{ width: k.pct + '%', background: k.color }" :title="k.k + ' ' + k.n"></span>
        </div>
        <div class="rx-legend">
          <span v-for="k in kindDist" :key="k.k" class="li"><span class="sw" :style="{ background: k.color }"></span>{{ k.k }} {{ k.n }}</span>
        </div>
      </div>
    </div>

    <div class="rx-toolbar">
      <input v-model="q" class="rx-input" placeholder="过滤 URL / 文件 / 规则 / 研判…" />
      <div class="bk-export">
        <button class="rx-btn rx-btn-ghost" :disabled="!hits.length" @click="exportAs('json')" title="导出 JSON">⭳ JSON</button>
        <button class="rx-btn rx-btn-ghost" :disabled="!hits.length" @click="exportAs('csv')" title="导出 CSV(Excel)">⭳ CSV</button>
        <button class="rx-btn rx-btn-ghost" :disabled="!hits.length" @click="exportAs('html')" title="导出 HTML 报告">⭳ 报告</button>
        <button class="rx-btn rx-btn-danger" :disabled="!hits.length || scan.running" @click="clearAll" title="清空全部命中并删除已保存结果">🗑 清空</button>
      </div>
      <div class="rx-tabs">
        <button v-for="k in kinds" :key="k" class="rx-tab" :class="{ active: kind === k }" @click="kind = k">
          {{ k }} <span class="rx-dim">{{ k === '全部' ? hits.length : countKind(k) }}</span>
        </button>
      </div>
      <span class="rx-spacer rx-dim rx-mono" style="font-size:12px">{{ filtered.length }} 条</span>
    </div>

    <div v-if="loading" class="rx-card rx-loading">正在拉取 /api/m/backup/hits …</div>
    <div v-else-if="error" class="rx-card rx-error">{{ error }}</div>
    <div v-else class="rx-card">
      <table class="rx-table">
        <thead>
          <tr><th>命中 URL</th><th>文件</th><th>类型</th><th>等级</th><th>大小</th><th>状态码</th><th>研判</th></tr>
        </thead>
        <tbody>
          <template v-for="h in filtered" :key="rowKey(h)">
            <tr class="rx-clickable" @click="toggle(h)">
              <td class="mono strong">
                <span class="rx-dim" style="font-size:11px">{{ open === rowKey(h) ? '▾' : '▸' }}</span>
                {{ h.url }}
              </td>
              <td class="mono" style="color:var(--rx-cyan)">{{ h.file }}</td>
              <td><span class="rx-badge" :class="kindBadge(h.kind)">{{ h.kind }}</span></td>
              <td><span class="rx-badge" :class="sevBadge(h.severity)">{{ h.severity || '—' }}</span></td>
              <td class="mono rx-dim">{{ h.size }}</td>
              <td><span class="rx-badge" :class="h.code < 300 ? 'rx-ok' : 'rx-warn'">{{ h.code }}</span></td>
              <td class="rx-dim">{{ h.note }}</td>
            </tr>
            <tr v-if="open === rowKey(h)" class="rx-row-detail">
              <td colspan="7">
                <div class="rx-detail-inner rx-grid rx-cols-3">
                  <!-- 概述 + 元信息 -->
                  <div class="rx-card rx-card-pad">
                    <div class="rx-eyebrow" style="margin-bottom:10px">风险概述</div>
                    <p style="margin:0;font-size:13px;line-height:1.7;color:var(--rx-mid)">{{ h.detail || '—' }}</p>
                    <hr class="rx-hr" />
                    <div class="rx-kv"><span class="k">来源主机</span><span class="v mono">{{ h.host || '—' }}</span></div>
                    <div class="rx-kv"><span class="k">文件 / 类型</span><span class="v">{{ h.file }} · {{ h.kind }}</span></div>
                    <div class="rx-kv"><span class="k">大小 / 状态码</span><span class="v mono">{{ h.size }} · {{ h.code }}</span></div>
                    <div class="rx-kv"><span class="k">命中规则</span><span class="v mono">{{ h.rule || '—' }}</span></div>
                    <div class="rx-kv"><span class="k">等级 / 时间</span><span class="v">{{ h.severity || '—' }} · {{ h.at || '—' }}</span></div>
                  </div>

                  <!-- 脱敏命中说明 + 证据 -->
                  <div class="rx-card rx-card-pad">
                    <div class="rx-eyebrow" style="margin-bottom:12px">脱敏命中说明 <span class="rx-dim" style="font-size:11px">· 仅探存在性</span></div>
                    <p style="margin:0 0 12px;font-size:12.5px;line-height:1.7;color:var(--rx-mid)">{{ h.sample || '—' }}</p>
                    <div class="bk-ev-label">探测请求</div>
                    <pre class="bk-ev">{{ h.evidence?.request || '—' }}</pre>
                    <div class="bk-ev-label">响应 / 判定</div>
                    <pre class="bk-ev resp">{{ h.evidence?.response || '—' }}</pre>
                    <div v-if="h.evidence?.note" class="bk-note">⚲ {{ h.evidence.note }}</div>
                  </div>

                  <!-- 处置建议 + 来源链路 -->
                  <div class="rx-card rx-card-pad">
                    <div class="rx-eyebrow" style="margin-bottom:10px">处置建议</div>
                    <p style="margin:0 0 12px;font-size:13px;line-height:1.7;color:var(--rx-mid)">{{ h.remediation || '—' }}</p>
                    <template v-if="h.refs && h.refs.length">
                      <div class="rx-eyebrow" style="margin-bottom:8px">参考</div>
                      <div class="rx-chiprow" style="margin-bottom:12px">
                        <span v-for="ref in h.refs" :key="ref" class="rx-tag">{{ ref }}</span>
                      </div>
                    </template>
                    <template v-if="h.chain && h.chain.length">
                      <div class="rx-eyebrow" style="margin-bottom:8px">来源链路</div>
                      <ol class="bk-chain">
                        <li v-for="(c, i) in h.chain" :key="i">{{ c }}</li>
                      </ol>
                    </template>
                    <div style="margin-top:14px;text-align:right">
                      <button class="rx-btn rx-btn-danger" @click.stop="removeHit(h)" title="删除此条命中">🗑 删除此条</button>
                    </div>
                  </div>
                </div>
              </td>
            </tr>
          </template>
          <tr v-if="!filtered.length"><td colspan="7" class="rx-empty">{{ scan.running ? '探测中…' : '无匹配命中(输入目标后点「开始真实探测」)' }}</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
declare const RedOps: any
const MID = 'scan-backup'

// 扫描输入
const targets = ref('')
const maxPerHost = ref(800)
const concurrency = ref(12)
const ratePerSec = ref(10)
const maxDepth = ref(1)
const maxDurationMin = ref(30)
const crawl = ref(true)
const includeEditor = ref(true)

const kinds = ['全部', '源码', '数据库', '配置', '其它']
const kind = ref('全部')
const q = ref('')
const open = ref<string | null>(null)

interface Evidence { request: string; response: string; note: string }
interface Hit {
  id: string; url: string; file: string; kind: string; size: string; code: number
  rule: string; host: string; severity: string; at: string; note: string
  detail: string; sample: string; evidence: Evidence; remediation: string; refs: string[]; chain: string[]
}
interface ScanStatus {
  running: boolean; total: number; probed: number; found: number
  target: string; startedAt: string; endedAt: string; err: string; demo: boolean; resumable: boolean
}
const hits = ref<Hit[]>([])
const stats = ref<Record<string, any>>({})
const dict = ref<Record<string, any>>({})
const scan = ref<ScanStatus>({ running: false, total: 0, probed: 0, found: 0, target: '', startedAt: '', endedAt: '', err: '', demo: true, resumable: false })
const loading = ref(true); const error = ref<string | null>(null)
let timer: any = null

const KIND_COLOR: Record<string, string> = { '源码': '#22d3ee', '数据库': '#f43f5e', '配置': '#f59e0b', '其它': '#a78bfa' }
const kindBadge = (k: string) => ({ '源码': 'rx-run', '数据库': 'rx-crit', '配置': 'rx-med', '其它': 'rx-info' } as any)[k] ?? 'rx-info'
const sevBadge = (s: string) => ({ '高危': 'rx-crit', '中危': 'rx-med', '低危': 'rx-low' } as any)[s] ?? 'rx-info'

const rowKey = (h: Hit) => h.id || h.url
function toggle(h: Hit) { const k = rowKey(h); open.value = open.value === k ? null : k }

const isDemo = computed(() => scan.value.demo && hits.value.length > 0)
const pct = computed(() => scan.value.total > 0 ? Math.min(100, Math.round((scan.value.probed / scan.value.total) * 100)) : (scan.value.running ? 0 : 100))
const targetList = computed(() => targets.value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean))

function tile(key: string, local: number) {
  const v = stats.value?.[key]
  return (v === undefined || v === null) ? local : v
}
function countKind(k: string) { return hits.value.filter(h => h.kind === k).length }
function count(sev: string) { return hits.value.filter(h => h.severity === sev && h.code < 300).length }
const accessibleLocal = computed(() => hits.value.filter(h => h.code < 300).length)
const hostLocal = computed(() => new Set(hits.value.map(h => h.host).filter(Boolean)).size)

const kindDist = computed(() => {
  const total = hits.value.length || 1
  return kinds.slice(1).map(k => ({ k, n: countKind(k), color: KIND_COLOR[k] }))
    .filter(x => x.n > 0).map(x => ({ ...x, pct: Math.round((x.n / total) * 100) }))
})
const filtered = computed(() => {
  let r = kind.value === '全部' ? hits.value : hits.value.filter(h => h.kind === kind.value)
  const kw = q.value.trim().toLowerCase()
  if (kw) r = r.filter(h => [h.url, h.file, h.rule, h.note].join(' ').toLowerCase().includes(kw))
  return r
})

async function loadHits() {
  try {
    const [hitRes, statRes] = await Promise.all([
      RedOps.api(MID, '/hits').then((r: Response) => r.json()),
      RedOps.api(MID, '/stats').then((r: Response) => r.json()).catch(() => ({})),
    ])
    hits.value = hitRes.items ?? []
    stats.value = statRes ?? {}
  } catch (e: any) { error.value = '请求失败: ' + (e?.message ?? String(e)) }
}

async function refreshStatus() {
  try { scan.value = await RedOps.api(MID, '/scan/status').then((r: Response) => r.json()) } catch { /* ignore */ }
}

async function start() {
  if (!targetList.value.length) { RedOps?.toast?.('请先填写目标 URL / 域名', 'warn'); return }
  error.value = null
  try {
    const res = await RedOps.api(MID, '/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets: targetList.value,
        maxPerHost: maxPerHost.value, concurrency: concurrency.value,
        ratePerSec: ratePerSec.value, maxDepth: maxDepth.value,
        maxDurationSec: Math.round((maxDurationMin.value || 0) * 60),
        crawl: crawl.value, includeEditor: includeEditor.value,
      }),
    })
    if (res.status === 409) { RedOps?.toast?.('已有扫描在运行', 'warn'); return }
    if (!res.ok) { const j = await res.json().catch(() => ({})); RedOps?.toast?.(j.error || '发起失败', 'err'); return }
    scan.value = await res.json()
    hits.value = []
    RedOps?.toast?.(`已对 ${targetList.value.length} 个目标发起真实探测`, 'ok')
    poll()
  } catch (e: any) { RedOps?.toast?.('发起失败: ' + (e?.message ?? e), 'err') }
}

async function stop() {
  try { await RedOps.api(MID, '/scan/stop', { method: 'POST' }); RedOps?.toast?.('已请求停止', 'warn') } catch { /* ignore */ }
}

// 续扫上次未完成的任务(跳过已完成目标,在原结果上追加)。
async function resume() {
  try {
    const res = await RedOps.api(MID, '/scan/resume', { method: 'POST' })
    if (res.status === 409) { RedOps?.toast?.('已有扫描在运行', 'warn'); return }
    if (!res.ok) { const j = await res.json().catch(() => ({})); RedOps?.toast?.(j.error || '续扫失败', 'err'); return }
    scan.value = await res.json()
    RedOps?.toast?.('已继续上次未完成的扫描', 'ok')
    poll()
  } catch (e: any) { RedOps?.toast?.('续扫失败: ' + (e?.message ?? e), 'err') }
}

// 导出命中结果为 JSON / CSV / HTML 报告(浏览器下载)。
async function exportAs(fmt: 'json' | 'csv' | 'html') {
  try {
    const res = await RedOps.api(MID, `/export?format=${fmt}`)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fmt === 'csv' ? 'backup-hits.csv' : fmt === 'html' ? 'backup-report.html' : 'backup-hits.json'
    document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
    RedOps?.toast?.(`已导出 ${fmt.toUpperCase()}`, 'ok')
  } catch (e: any) { RedOps?.toast?.('导出失败: ' + (e?.message ?? e), 'err') }
}

// 清空全部命中(并删除后端已保存的结果文件)。
async function clearAll() {
  if (!confirm('确认清空全部命中结果?此操作会同时删除后端已保存的结果文件。')) return
  try {
    const res = await RedOps.api(MID, '/hits/clear', { method: 'POST' })
    if (res.status === 409) { RedOps?.toast?.('扫描运行中,无法清空', 'warn'); return }
    hits.value = []; await loadHits(); await refreshStatus()
    RedOps?.toast?.('已清空命中结果', 'ok')
  } catch (e: any) { RedOps?.toast?.('清空失败: ' + (e?.message ?? e), 'err') }
}

// 删除单条命中。
async function removeHit(h: Hit) {
  try {
    await RedOps.api(MID, '/hits/delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: h.id }),
    })
    hits.value = hits.value.filter(x => x.id !== h.id)
    if (open.value === rowKey(h)) open.value = null
    await loadHits()
    RedOps?.toast?.('已删除', 'ok')
  } catch (e: any) { RedOps?.toast?.('删除失败: ' + (e?.message ?? e), 'err') }
}

// 轮询进度 —— 运行期间每秒刷新 status + hits;结束后再拉一次最终结果。
function poll() {
  if (timer) clearTimeout(timer)
  const tick = async () => {
    await refreshStatus()
    await loadHits()
    if (scan.value.running) { timer = setTimeout(tick, 1000) }
    else { timer = null; await loadHits() }
  }
  timer = setTimeout(tick, 800)
}

async function init() {
  loading.value = true; error.value = null
  try {
    dict.value = await RedOps.api(MID, '/dict').then((r: Response) => r.json()).catch(() => ({}))
    await refreshStatus()
    await loadHits()
    if (scan.value.running) poll()
  } finally { loading.value = false }
}
onMounted(init)
onUnmounted(() => { if (timer) clearTimeout(timer) })
</script>

<style scoped>
.bk-scan .rx-card-pad { padding-top: 14px; }
.bk-targets { width: 100%; resize: vertical; font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 12.5px; line-height: 1.6; }
.bk-opts { display: flex; align-items: center; gap: 16px; margin-top: 12px; flex-wrap: wrap; }
.bk-opt { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--rx-mid, #94a3b8); }
.bk-num { width: 84px; }
.bk-check { cursor: pointer; }
.bk-check input { accent-color: var(--rx-cyan, #22d3ee); }
.rx-btn-danger { background: rgba(244, 63, 94, .14); border-color: rgba(244, 63, 94, .4); color: #fda4af; }
.bk-export { display: flex; gap: 6px; align-items: center; margin-right: 8px; }
.rx-btn-ghost { background: rgba(34, 211, 238, .08); border-color: rgba(34, 211, 238, .28); color: #7dd3fc; font-size: 12px; padding: 5px 10px; }
.rx-btn-ghost:disabled, .rx-btn-danger:disabled { opacity: .4; cursor: not-allowed; }
.bk-progress { margin-top: 14px; }
.bk-bar { height: 8px; border-radius: 5px; background: rgba(7, 10, 16, .6); overflow: hidden; border: 1px solid var(--rx-line, #1d2533); }
.bk-bar span { display: block; height: 100%; background: linear-gradient(90deg, #22d3ee, #6366f1); transition: width .4s ease; }
.bk-prog-meta { display: flex; justify-content: space-between; font-size: 11.5px; color: var(--rx-dim, #6b7689); margin-top: 6px; }
.bk-disclaimer { margin: 12px 0 0; font-size: 11.5px; line-height: 1.6; color: var(--rx-amber, #f59e0b); }
.rx-demo-flag.live { color: #6ee7b7; border-color: rgba(52, 211, 153, .35); }
.bk-ev-label { font-size: 11px; color: var(--rx-dim, #6b7689); margin: 4px 0 4px; letter-spacing: .04em; }
.bk-ev {
  margin: 0 0 10px; padding: 9px 11px; border-radius: 6px;
  background: rgba(7, 10, 16, .6); border: 1px solid var(--rx-line, #1d2533);
  font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 11.5px; line-height: 1.55;
  color: #b7c2d2; white-space: pre-wrap; word-break: break-word; overflow-x: auto;
}
.bk-ev.resp { color: #9fb4c6; border-color: rgba(52, 211, 153, .25); }
.bk-note { font-size: 11.5px; color: var(--rx-amber, #f59e0b); line-height: 1.5; margin-top: 4px; }
.bk-chain { margin: 0; padding-left: 18px; }
.bk-chain li { font-size: 12.5px; line-height: 1.75; color: var(--rx-mid, #94a3b8); }
</style>
