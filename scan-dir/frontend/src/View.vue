<template>
  <div class="rx-page rx-fade-in">
    <header class="rx-head">
      <div>
        <div class="rx-eyebrow">扫描探测 · DIRSCAN</div>
        <h1>目录扫描</h1>
        <p class="rx-sub"><code>scan-dir</code> 模块 · ffuf 风格多字典、FUZZ 多关键字、软404过滤、递归扫描、备份衍生</p>
      </div>
    </header>

    <div class="rx-card" style="margin-bottom:18px">
      <div class="rx-card-head">
        <h3>发起目录扫描</h3>
        <span class="rx-right rx-mono" style="font-size:12px">
          {{ selDict ? selDict.label + '（' + selDict.count.toLocaleString() + ' 条）' : '加载字典…' }}
        </span>
      </div>
      <div class="rx-card-pad">
        <textarea v-model="targets" class="rx-input ds-targets" rows="3" :disabled="running"
          placeholder="目标，每行一个：https://example.com 或 example.com/app&#10;支持 FUZZ 关键字：https://x.com/api/FUZZ?id=1"></textarea>

        <div class="ds-opts">
          <label class="ds-opt">字典
            <select v-model="wordlist" :disabled="running" class="rx-input">
              <option v-for="d in dicts" :key="d.id" :value="d.id">{{ d.label }}（{{ d.count.toLocaleString() }}）</option>
              <option value="custom">自定义词条</option>
            </select>
          </label>
          <label class="ds-opt" title="替换字典中的 %EXT% 占位符，并对目录型词条追加">扩展名
            <input v-model="extensions" :disabled="running" placeholder="php,bak,zip,txt" class="rx-input" style="width:160px" />
          </label>
          <label class="ds-opt">方法
            <select v-model="method" :disabled="running" class="rx-input">
              <option v-for="m in METHODS" :key="m" :value="m">{{ m }}</option>
            </select>
          </label>
          <label class="ds-opt">递归深度
            <input v-model.number="recursion" type="number" min="0" max="3" :disabled="running" class="rx-input ds-num" />
          </label>
          <label class="ds-opt" title="ffuf -x">代理
            <input v-model="proxy" :disabled="running" placeholder="http://127.0.0.1:8080" class="rx-input" style="width:200px" />
          </label>
          <label class="ds-opt" title="自动拼为 Cookie: <value>">Cookie
            <input v-model="cookie" :disabled="running" placeholder="session=abc123; token=xyz" class="rx-input" style="width:200px" />
          </label>
          <label class="ds-opt" title="留空使用内置随机 UA 池">UA
            <input v-model="userAgent" :disabled="running" placeholder="留空=默认" class="rx-input" style="width:180px" />
          </label>
        </div>

        <div class="ds-subhead">自定义请求头（每行一个 <code>Key: Value</code>，支持 FUZZ 占位符）</div>
        <textarea v-model="customHeaders" class="rx-input ds-headers" rows="2" :disabled="running"
          placeholder="Authorization: Bearer eyJhbGci...&#10;X-Forwarded-For: 127.0.0.1&#10;X-Custom-Header: FUZZ"></textarea>

        <textarea v-if="method !== 'GET' && method !== 'HEAD'" v-model="requestBody"
          class="rx-input ds-headers" rows="2" :disabled="running"
          placeholder="请求体（非 GET/HEAD 时发送，可含 FUZZ，如 user=admin&pass=FUZZ）"></textarea>

        <textarea v-if="wordlist === 'custom'" v-model="customWords"
          class="rx-input ds-headers" rows="3" :disabled="running"
          placeholder="自定义词条，每行一个路径名（如 admin、api/v1、backup.zip）"></textarea>

        <!-- 多关键字 FUZ2Z -->
        <div class="ds-opts" style="margin-top:8px">
          <span class="ds-subhead" style="margin:0" title="目标/请求体/请求头里用 FUZ2Z 标记第二位置">多关键字（FUZ2Z）：</span>
          <label class="ds-opt">第二字典
            <select v-model="wordlist2" :disabled="running" class="rx-input">
              <option value="none">不启用</option>
              <option v-for="d in dicts" :key="d.id" :value="d.id">{{ d.label }}</option>
              <option value="custom">自定义</option>
            </select>
          </label>
          <label v-if="wordlist2 !== 'none'" class="ds-opt">模式
            <select v-model="fuzzMode" :disabled="running" class="rx-input">
              <option value="clusterbomb">clusterbomb（N×M）</option>
              <option value="pitchfork">pitchfork（并行）</option>
            </select>
          </label>
        </div>
        <textarea v-if="wordlist2 === 'custom'" v-model="customWords2"
          class="rx-input ds-headers" rows="2" :disabled="running"
          placeholder="第二字典词条（FUZ2Z），每行一个"></textarea>

        <!-- 并发/速率/超时/状态码 -->
        <div class="ds-opts" style="margin-top:8px">
          <label class="ds-opt">并发
            <input v-model.number="concurrency" type="number" min="1" max="64" :disabled="running" class="rx-input ds-num" />
          </label>
          <label class="ds-opt">限速/s
            <input v-model.number="rateLimit" type="number" min="0" max="2000" :disabled="running" class="rx-input ds-num" />
          </label>
          <label class="ds-opt">超时ms
            <input v-model.number="timeout" type="number" min="500" max="30000" :disabled="running" class="rx-input ds-num" style="width:90px" />
          </label>
          <label class="ds-opt">仅保留码
            <input v-model="statusInclude" :disabled="running" placeholder="留空=全部" class="rx-input ds-num" style="width:96px" />
          </label>
          <label class="ds-opt">排除码
            <input v-model="statusExclude" :disabled="running" placeholder="404" class="rx-input ds-num" style="width:80px" />
          </label>
          <label class="ds-opt ds-check">
            <input v-model="followRedirect" type="checkbox" :disabled="running" /> 跟随跳转
          </label>
        </div>

        <!-- ffuf 过滤 -->
        <div class="ds-opts" style="margin-top:8px">
          <span class="ds-subhead" style="margin:0">ffuf 过滤（命中后剔除）：</span>
          <label class="ds-opt" title="ffuf -fs">大小
            <input v-model="filterLength" :disabled="running" placeholder="0,1234" class="rx-input ds-num" style="width:88px" />
          </label>
          <label class="ds-opt" title="ffuf -fw">词数
            <input v-model="filterWords" :disabled="running" placeholder="10,42" class="rx-input ds-num" style="width:72px" />
          </label>
          <label class="ds-opt" title="ffuf -fl">行数
            <input v-model="filterLines" :disabled="running" placeholder="1,7" class="rx-input ds-num" style="width:72px" />
          </label>
          <label class="ds-opt" title="ffuf -fr 正文过滤正则">正文过滤
            <input v-model="filterRegex" :disabled="running" placeholder="Access Denied|无权限" class="rx-input" style="width:160px" />
          </label>
          <label class="ds-opt" title="ffuf -mr 仅保留正文匹配者">正文匹配
            <input v-model="matchRegex" :disabled="running" placeholder="admin|console" class="rx-input" style="width:140px" />
          </label>
          <label class="ds-opt ds-check">
            <input v-model="crawl" type="checkbox" :disabled="running" /> 链接抽取
          </label>
          <label class="ds-opt ds-check">
            <input v-model="collectBackups" type="checkbox" :disabled="running" /> 备份衍生
          </label>
          <label class="ds-opt ds-check">
            <input v-model="randomAgent" type="checkbox" :disabled="running" /> 随机 UA
          </label>
        </div>

        <!-- 操作按钮 -->
        <div class="ds-opts" style="margin-top:12px">
          <button v-if="!running" class="rx-btn rx-btn-primary" :disabled="!targetList.length" @click="start">▸ 发起扫描</button>
          <button v-else class="rx-btn rx-btn-danger" @click="stop">■ 停止扫描</button>
          <button v-if="!running && scan.resumable" class="rx-btn rx-btn-ghost" @click="resume" title="从上次中断处继续">⟳ 续扫</button>
          <span class="rx-spacer"></span>
          <button class="rx-btn rx-btn-ghost" :disabled="!hits.length" @click="exportAs('json')">⭳ JSON</button>
          <button class="rx-btn rx-btn-ghost" :disabled="!hits.length" @click="exportAs('csv')">⭳ CSV</button>
          <button class="rx-btn rx-btn-ghost" :disabled="!hits.length" @click="exportAs('html')">⭳ 报告</button>
        </div>

        <div v-if="running || scan.probed > 0" class="pt-progress">
          <div class="pt-bar"><span :style="{ width: pct + '%' }"></span></div>
          <div class="pt-prog-meta rx-mono">
            <span>{{ running ? '扫描中' : '已完成' }} · {{ scan.phase || '' }} {{ scan.target ? '· ' + scan.target : '' }}</span>
            <span>{{ scan.probed }} / {{ scan.total || '?' }} · 命中 <b style="color:var(--rx-cyan)">{{ scan.found }}</b> · {{ pct }}%</span>
          </div>
          <div v-if="scan.err" class="rx-error" style="margin-top:8px">{{ scan.err }}</div>
        </div>
      </div>
    </div>

    <section class="rx-grid rx-cols-4" style="margin-bottom:18px">
      <div class="rx-stat">
        <div class="rx-stat-label">命中路径</div>
        <div class="rx-stat-val">{{ hits.length || '—' }}</div>
      </div>
      <div class="rx-stat rx-red">
        <div class="rx-stat-label">高危命中</div>
        <div class="rx-stat-val">{{ highCount || '—' }}</div>
      </div>
      <div class="rx-stat">
        <div class="rx-stat-label">已过滤</div>
        <div class="rx-stat-val">{{ scan.filtered ?? '—' }}</div>
      </div>
      <div class="rx-stat rx-purple">
        <div class="rx-stat-label">字典词条</div>
        <div class="rx-stat-val" style="font-size:14px">{{ selDict ? selDict.count.toLocaleString() : (wordlist === 'custom' ? '自定义' : '—') }}</div>
      </div>
    </section>

    <div class="rx-card">
      <div class="rx-card-head">
        <h3>命中路径（{{ sortedHits.length }}）</h3>
        <span class="rx-right">
          <input v-model="q" class="rx-input" placeholder="过滤路径/类型/状态码…" style="width:200px" />
        </span>
      </div>
      <table class="rx-table">
        <thead>
          <tr><th>敏感度</th><th>状态</th><th>路径</th><th>长度</th><th>词/行</th><th>跳转 / 类型</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="(h, i) in filtered" :key="h.url+'/'+i">
            <td>
              <span v-if="h.severity && h.severity !== 'info'" class="rx-badge" :class="sevClass(h.severity)">{{ h.severity }}</span>
              <span v-else class="rx-dim">—</span>
            </td>
            <td class="mono" :class="codeClass(h.status)" style="font-weight:600">{{ h.status }}</td>
            <td class="mono" style="color:var(--rx-mid)">
              {{ h.isDir ? '📁 ' : '' }}{{ h.path }}
              <span v-if="h.kind" class="rx-dim" style="font-size:11px;margin-left:6px">{{ h.kind }}</span>
            </td>
            <td class="mono rx-dim" style="font-size:12px">{{ fmtLen(h.length) }}</td>
            <td class="mono rx-dim" style="font-size:12px">{{ h.words }}/{{ h.lines }}</td>
            <td class="mono rx-dim" style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ h.redirect || h.contentType || '—' }}</td>
            <td>
              <a :href="h.url" target="_blank" rel="noreferrer" class="rx-dim" style="font-size:13px" title="在浏览器中打开">↗</a>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="7" class="rx-empty">{{ running ? '扫描中，正在发现命中路径…' : '暂无命中（填写目标后点「发起扫描」）' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
declare const RedOps: any
const MID = 'scan-dir'

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

const targets = ref('')
const wordlist = ref('common')
const customWords = ref('')
const wordlist2 = ref('none')
const customWords2 = ref('')
const fuzzMode = ref<'clusterbomb' | 'pitchfork'>('clusterbomb')
const extensions = ref('')
const concurrency = ref(20)
const rateLimit = ref(0)
const timeout = ref(8000)
const statusInclude = ref('')
const statusExclude = ref('404')
const filterLength = ref('')
const filterWords = ref('')
const filterLines = ref('')
const filterRegex = ref('')
const matchRegex = ref('')
const prefixes = ref('')
const suffixes = ref('')
const crawl = ref(false)
const collectBackups = ref(false)
const randomAgent = ref(false)
const followRedirect = ref(false)
const recursion = ref(0)
const method = ref('GET')
const requestBody = ref('')
const proxy = ref('')
const cookie = ref('')
const userAgent = ref('')
const customHeaders = ref('')
const q = ref('')

interface Hit {
  url: string; path: string; status: number; length: number
  words: number; lines: number; redirect: string; contentType: string
  depth: number; isDir: boolean; severity: string; kind: string
}
interface DictEntry { id: string; label: string; source: string; count: number }
interface ScanStatus {
  running: boolean; phase: string; total: number; probed: number; found: number
  filtered: number; rate: number; target: string; err: string; resumable: boolean; elapsedMs: number
}

const hits = ref<Hit[]>([])
const dicts = ref<DictEntry[]>([])
const scan = ref<ScanStatus>({ running: false, phase: '', total: 0, probed: 0, found: 0, filtered: 0, rate: 0, target: '', err: '', resumable: false, elapsedMs: 0 })
let timer: any = null

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const running = computed(() => scan.value.running)
const targetList = computed(() => targets.value.split('\n').map(s => s.trim()).filter(Boolean))
const highCount = computed(() => hits.value.filter(h => h.severity === 'critical' || h.severity === 'high').length)
const selDict = computed(() => dicts.value.find(d => d.id === wordlist.value))
const pct = computed(() => scan.value.total > 0 ? Math.min(100, Math.round(scan.value.probed / scan.value.total * 100)) : (scan.value.running ? 0 : 100))
const sortedHits = computed(() => [...hits.value].sort((a, b) => (SEV_RANK[b.severity] ?? 1) - (SEV_RANK[a.severity] ?? 1)))
const filtered = computed(() => {
  const kw = q.value.trim().toLowerCase()
  if (!kw) return sortedHits.value
  return sortedHits.value.filter(h => [h.path, h.url, String(h.status), h.kind || '', h.contentType || ''].join(' ').toLowerCase().includes(kw))
})

function codeClass(code: number): string {
  if (code >= 200 && code < 300) return 'ds-code-ok'
  if (code >= 300 && code < 400) return 'ds-code-redirect'
  if (code >= 400 && code < 500) return 'ds-code-warn'
  if (code >= 500) return 'ds-code-err'
  return 'rx-dim'
}
function sevClass(sev: string): string {
  return ({ critical: 'rx-crit', high: 'rx-crit', medium: 'rx-med', low: 'rx-low', info: 'rx-info' } as any)[sev] ?? 'rx-info'
}
function fmtLen(n: number): string {
  if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + 'M'
  if (n >= 1024) return (n / 1024).toFixed(1) + 'K'
  return String(n)
}

async function refresh() {
  try {
    const [st, h] = await Promise.all([
      RedOps.api(MID, '/scan/status').then((r: Response) => r.json()),
      RedOps.api(MID, '/hits').then((r: Response) => r.json()),
    ])
    scan.value = st.status ?? scan.value
    hits.value = h.items ?? []
  } catch { /* ignore */ }
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
  const words = customWords.value.split('\n').map(s => s.trim()).filter(Boolean)
  if (wordlist.value === 'custom' && !words.length) { RedOps?.toast?.('字典选择了「自定义」，请填写词条', 'warn'); return }
  try {
    const words2 = customWords2.value.split('\n').map(s => s.trim()).filter(Boolean)
    const extraHeaders = customHeaders.value.split('\n').map(s => s.trim()).filter(Boolean)
    if (cookie.value.trim()) extraHeaders.push(`Cookie: ${cookie.value.trim()}`)
    const res = await RedOps.api(MID, '/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets: targetList.value, wordlist: wordlist.value, customWords: words, extensions: extensions.value,
        wordlist2: wordlist2.value === 'none' ? '' : wordlist2.value, customWords2: words2, fuzzMode: fuzzMode.value,
        concurrency: concurrency.value, rate: rateLimit.value, timeout: timeout.value,
        statusInclude: statusInclude.value, statusExclude: statusExclude.value,
        filterLength: filterLength.value, filterWords: filterWords.value, filterLines: filterLines.value,
        filterRegex: filterRegex.value, matchRegex: matchRegex.value,
        prefixes: prefixes.value, suffixes: suffixes.value,
        crawl: crawl.value, collectBackups: collectBackups.value, randomAgent: randomAgent.value,
        followRedirect: followRedirect.value, recursion: recursion.value, method: method.value,
        requestBody: requestBody.value, proxy: proxy.value, userAgent: userAgent.value, headers: extraHeaders,
      }),
    })
    if (res.status === 409) { RedOps?.toast?.('已有扫描在运行', 'warn'); return }
    if (!res.ok) { const j = await res.json().catch(() => ({})); RedOps?.toast?.(j.error || '发起失败', 'err'); return }
    const j = await res.json()
    scan.value = j.status ?? scan.value
    hits.value = []
    RedOps?.toast?.(`已对 ${targetList.value.length} 个目标发起扫描`, 'ok')
    poll()
  } catch (e: any) { RedOps?.toast?.('发起失败: ' + (e?.message ?? e), 'err') }
}

async function stop() {
  try { await RedOps.api(MID, '/scan/stop', { method: 'POST' }); RedOps?.toast?.('已请求停止', 'warn') } catch { /* ignore */ }
}

async function resume() {
  try {
    const res = await RedOps.api(MID, '/scan/resume', { method: 'POST' })
    if (res.status === 409) { RedOps?.toast?.('已有扫描在运行', 'warn'); return }
    if (!res.ok) { const j = await res.json().catch(() => ({})); RedOps?.toast?.(j.error || '续扫失败', 'err'); return }
    const j = await res.json()
    scan.value = j.status ?? scan.value
    RedOps?.toast?.('已继续上次未完成的扫描', 'ok')
    poll()
  } catch (e: any) { RedOps?.toast?.('续扫失败: ' + (e?.message ?? e), 'err') }
}

async function exportAs(fmt: string) {
  try {
    const res = await RedOps.api(MID, `/export?format=${fmt}`)
    if (!res.ok) { RedOps?.toast?.('导出失败', 'err'); return }
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `dirscan.${fmt}`
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url)
    RedOps?.toast?.(`已导出 ${fmt.toUpperCase()}`, 'ok')
  } catch (e: any) { RedOps?.toast?.('导出失败: ' + (e?.message ?? e), 'err') }
}

onMounted(async () => {
  try { const d = await RedOps.api(MID, '/dict').then((r: Response) => r.json()); dicts.value = d.lists ?? [] } catch { /* ignore */ }
  await refresh()
  if (scan.value.running) poll()
})
onUnmounted(() => { if (timer) clearTimeout(timer) })
</script>

<style scoped>
.ds-targets, .ds-headers { width: 100%; resize: vertical; font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 12.5px; line-height: 1.6; }
.ds-headers { margin-top: 8px; }
.ds-opts { display: flex; align-items: center; gap: 12px; margin-top: 10px; flex-wrap: wrap; }
.ds-opt { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--rx-mid, #94a3b8); }
.ds-num { width: 80px; }
.ds-check { cursor: pointer; }
.ds-check input { accent-color: var(--rx-cyan, #22d3ee); }
.ds-subhead { font-size: 11.5px; color: var(--rx-dim, #6b7689); margin-top: 10px; margin-bottom: 4px; }
.rx-btn-danger { background: rgba(244, 63, 94, .14); border-color: rgba(244, 63, 94, .4); color: #fda4af; }
.rx-btn-ghost { background: rgba(34, 211, 238, .08); border-color: rgba(34, 211, 238, .28); color: #7dd3fc; font-size: 12px; padding: 5px 10px; }
.rx-btn-ghost:disabled { opacity: .4; cursor: not-allowed; }
.pt-progress { margin-top: 14px; }
.pt-bar { height: 8px; border-radius: 5px; background: rgba(7, 10, 16, .6); overflow: hidden; border: 1px solid var(--rx-line, #1d2533); }
.pt-bar span { display: block; height: 100%; background: linear-gradient(90deg, #22d3ee, #6366f1); transition: width .4s ease; }
.pt-prog-meta { display: flex; justify-content: space-between; font-size: 11.5px; color: var(--rx-dim, #6b7689); margin-top: 6px; }
.ds-code-ok { color: #4ade80; }
.ds-code-redirect { color: var(--rx-cyan, #22d3ee); }
.ds-code-warn { color: #fb923c; }
.ds-code-err { color: #f87171; }
</style>
