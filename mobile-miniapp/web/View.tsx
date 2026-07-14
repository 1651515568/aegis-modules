import { useState } from 'react'
import { Layers, Code2, Globe, ShieldAlert, Search, Upload, Play, ChevronRight } from 'lucide-react'
import { Panel, StatCard, SeverityTag, Progress } from '@/components/ui'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type MiniPlatform = 'wechat' | 'alipay' | 'douyin' | 'baidu'

interface MiniFinding {
  id: string
  file: string
  line?: number
  category: string
  title: string
  severity: Severity
  code?: string
  detail: string
  fix: string
}

const MOCK_FINDINGS: MiniFinding[] = [
  { id: 'f1', file: 'app.js', line: 12, category: '隐私合规', title: '未声明 getUserInfo 权限即调用', severity: 'high', code: "wx.getUserInfo({ success: res => { ... } })", detail: '应用在未弹出授权弹窗的情况下直接调用敏感 API，违反微信平台隐私规范。', fix: '在 app.json 的 requiredPrivateInfos 中声明后再调用，并处理用户拒绝场景。' },
  { id: 'f2', file: 'utils/request.js', line: 37, category: '网络安全', title: 'HTTP 明文接口调用', severity: 'high', code: 'wx.request({ url: "http://api.target.com/user/login" })', detail: '存在 HTTP 明文请求，微信小程序网络请求应强制使用 HTTPS。', fix: '将所有接口地址改为 HTTPS，并在微信公众平台配置合法域名白名单。' },
  { id: 'f3', file: 'pages/login/login.js', line: 55, category: '数据存储', title: 'wx.setStorage 明文存储 token', severity: 'medium', code: "wx.setStorageSync('token', res.data.token)", detail: 'token 以明文形式存入 Storage，攻击者在 root 设备或 PC 调试环境可读取。', fix: '对敏感字段加密后再存储，或仅存储在内存（全局 globalData）中。' },
  { id: 'f4', file: 'pages/pay/pay.js', line: 88, category: '业务逻辑', title: '支付金额在客户端可篡改', severity: 'critical', code: 'wx.requestPayment({ total_fee: this.data.price })', detail: '支付价格从 data 中读取，前端可直接篡改，后端未做二次校验。', fix: '支付订单应由服务端生成并锁定金额，客户端只传 orderId，价格不经过客户端。' },
  { id: 'f5', file: 'app.json', category: '配置安全', title: 'navigateToMiniProgram 未限制 appid 白名单', severity: 'medium', detail: '允许跳转到任意小程序，可能被用于钓鱼或诱导跳转。', fix: '在 referrerInfo 中校验来源 appid，或限制仅跳转已知可信小程序。' },
  { id: 'f6', file: 'pages/profile/profile.js', line: 122, category: 'XSS', title: 'rich-text 组件渲染未过滤 HTML', severity: 'medium', code: '<rich-text nodes="{{htmlContent}}" />', detail: '直接渲染服务端返回的 HTML，若存在 XSS payload 可执行脚本。', fix: '对 htmlContent 过滤危险标签，或改用白名单解析器。' },
  { id: 'f7', file: 'utils/crypto.js', line: 8, category: '密码学', title: 'AES 使用固定 IV（ECB 模式）', severity: 'medium', code: 'CryptoJS.AES.encrypt(data, key)', detail: '使用 ECB 模式加密，相同明文产生相同密文，易被模式分析攻击。', fix: '使用 CBC/GCM 模式并生成随机 IV，随密文一并传输。' },
]

const PLATFORMS: { key: MiniPlatform; label: string }[] = [
  { key: 'wechat', label: '微信' },
  { key: 'alipay', label: '支付宝' },
  { key: 'douyin', label: '抖音' },
  { key: 'baidu', label: '百度' },
]

const CATEGORIES = ['全部', '隐私合规', '网络安全', '数据存储', '业务逻辑', '配置安全', 'XSS', '密码学']

export default function MobileMiniappView() {
  const [platform, setPlatform] = useState<MiniPlatform>('wechat')
  const [inputMode, setInputMode] = useState<'appid' | 'upload'>('appid')
  const [appId, setAppId] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('')
  const [findings, setFindings] = useState<MiniFinding[]>([])
  const [filterCat, setFilterCat] = useState('全部')
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all')
  const [expanded, setExpanded] = useState<string | null>(null)

  const PHASES = ['解包小程序包…', '提取 JS/WXML/JSON…', '污点流分析…', '合规策略检查…', '汇总报告…']

  function canStart() {
    return inputMode === 'appid' ? appId.trim().length > 0 : !!fileName
  }

  function simulate() {
    if (!canStart()) return
    setRunning(true); setProgress(0); setFindings([]); setPhase(PHASES[0])
    let step = 0
    const iv = setInterval(() => {
      step++
      setProgress(Math.min(step * 20, 95))
      setPhase(PHASES[Math.min(step, PHASES.length - 1)])
      if (step >= 5) { clearInterval(iv); setProgress(100); setFindings(MOCK_FINDINGS); setRunning(false); setPhase('') }
    }, 700)
  }

  const filtered = findings.filter((f) => {
    if (filterCat !== '全部' && f.category !== filterCat) return false
    if (filterSev !== 'all' && f.severity !== filterSev) return false
    return true
  })

  const sevCount = (s: Severity) => findings.filter((f) => f.severity === s).length

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatCard label="发现问题" value={findings.length || '—'} icon={<ShieldAlert size={18} />} />
        <StatCard label="严重" value={sevCount('critical') || '—'} icon={<ShieldAlert size={18} />} />
        <StatCard label="高危" value={sevCount('high') || '—'} icon={<Code2 size={18} />} />
        <StatCard label="中危" value={sevCount('medium') || '—'} icon={<Globe size={18} />} />
        <StatCard label="低危" value={sevCount('low') || '—'} icon={<Layers size={18} />} />
      </div>

      <Panel title="小程序安全评估" icon={<Layers size={16} />}>
        <div className="space-y-4">
          <div>
            <label className="mb-1.5 block text-xs text-slate-400">平台</label>
            <div className="flex gap-2">
              {PLATFORMS.map((p) => (
                <button key={p.key} onClick={() => setPlatform(p.key)}
                  className={`chip border transition ${platform === p.key ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs text-slate-400">输入方式</label>
            <div className="flex gap-2 mb-3">
              <button onClick={() => setInputMode('appid')}
                className={`chip border transition ${inputMode === 'appid' ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                <Search size={12} /> AppID 搜索
              </button>
              <button onClick={() => setInputMode('upload')}
                className={`chip border transition ${inputMode === 'upload' ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                <Upload size={12} /> 上传包文件
              </button>
            </div>

            {inputMode === 'appid' ? (
              <input value={appId} onChange={(e) => setAppId(e.target.value)}
                placeholder={`${platform === 'wechat' ? 'wx' : platform === 'alipay' ? '2021' : ''}xxxxxxxxxxxxxxxx`}
                className="w-full rounded-lg border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber" />
            ) : (
              <label className={`flex h-20 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition
                ${fileName ? 'border-cyber/40 bg-cyber/5' : 'border-line bg-base-700/40 hover:border-cyber/30'}`}>
                <Upload size={20} className="mb-1 text-slate-500" />
                <span className="text-xs text-slate-400">
                  {fileName ? <span className="text-cyber font-mono">{fileName}</span> : '上传 .wxapkg / .zip 文件'}
                </span>
                <input type="file" className="hidden" accept=".wxapkg,.zip,.xapk"
                  onChange={(e) => setFileName(e.target.files?.[0]?.name ?? null)} />
              </label>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button onClick={simulate} disabled={running || !canStart()}
              className="chip border border-cyber/40 bg-cyber/10 text-cyber disabled:opacity-40">
              <Play size={14} /> {running ? '分析中…' : '开始分析'}
            </button>
            {running && <span className="text-xs text-slate-500 animate-pulse">{phase}</span>}
          </div>
          {(running || progress > 0) && <Progress value={progress} />}
        </div>
      </Panel>

      {findings.length > 0 && (
        <Panel title={`发现问题（${filtered.length}）`} icon={<ShieldAlert size={16} />}
          action={
            <div className="flex gap-1">
              {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => (
                <button key={s} onClick={() => setFilterSev(s)}
                  className={`chip border text-xs ${filterSev === s ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                  {s === 'all' ? '全部' : s}
                </button>
              ))}
            </div>
          }
        >
          <div className="mb-3 flex flex-wrap gap-1">
            {CATEGORIES.map((c) => (
              <button key={c} onClick={() => setFilterCat(c)}
                className={`chip border text-xs transition ${filterCat === c ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                {c}
              </button>
            ))}
          </div>
          <div className="space-y-2">
            {filtered.map((f) => (
              <div key={f.id} className="rounded-lg border border-line bg-base-700/30">
                <button className="flex w-full items-center justify-between p-3"
                  onClick={() => setExpanded((prev) => prev === f.id ? null : f.id)}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityTag severity={f.severity} />
                    <span className="chip border border-line bg-base-600/60 text-[10px] text-slate-400">{f.category}</span>
                    <span className="text-sm text-slate-200">{f.title}</span>
                    <span className="font-mono text-[10px] text-slate-500">{f.file}{f.line ? `:${f.line}` : ''}</span>
                  </div>
                  <ChevronRight size={14} className={`shrink-0 text-slate-500 transition ${expanded === f.id ? 'rotate-90' : ''}`} />
                </button>
                {expanded === f.id && (
                  <div className="border-t border-line px-4 pb-4 pt-3 space-y-3 text-xs">
                    <div>
                      <div className="mb-1 text-slate-500">描述</div>
                      <div className="text-slate-300">{f.detail}</div>
                    </div>
                    {f.code && (
                      <div>
                        <div className="mb-1 text-slate-500">问题代码</div>
                        <pre className="rounded bg-black/50 px-3 py-2 font-mono text-[10px] text-amber-300 overflow-x-auto">{f.code}</pre>
                      </div>
                    )}
                    <div>
                      <div className="mb-1 text-slate-500">修复建议</div>
                      <div className="text-emerald-400">{f.fix}</div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  )
}
