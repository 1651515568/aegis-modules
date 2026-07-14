import { useState } from 'react'
import { Smartphone, Upload, ShieldAlert, Lock, Globe, FileText, Play, ChevronRight } from 'lucide-react'
import { Panel, StatCard, SeverityTag, Progress } from '@/components/ui'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type Platform = 'android' | 'ios'

interface AppFinding {
  id: string
  category: string
  title: string
  severity: Severity
  detail: string
  evidence: string
  fix: string
}

const MOCK_FINDINGS: AppFinding[] = [
  { id: 'f1', category: '数据存储', title: 'SharedPreferences 明文存储敏感信息', severity: 'high', detail: 'access_token 以明文形式存储在 shared_prefs/user.xml，任何 root 设备可直接读取。', evidence: "shared_prefs/user.xml: <string name=\"access_token\">eyJhbGci…</string>", fix: '使用 EncryptedSharedPreferences 或 Android Keystore 存储敏感字段。' },
  { id: 'f2', category: '网络通信', title: 'HTTP 明文传输（非 HTTPS）', severity: 'high', detail: '应用存在明文 HTTP 请求，攻击者可在同网络内抓包获取请求内容。', evidence: 'MainActivity.java:142: new URL("http://api.target.com/v1/login")', fix: '强制使用 HTTPS，并在 network_security_config.xml 禁用 cleartext traffic。' },
  { id: 'f3', category: '密码学', title: '使用弱加密算法 (MD5/DES)', severity: 'medium', detail: 'PasswordHelper.java 使用 MD5 对用户密码进行哈希，易受彩虹表攻击。', evidence: 'PasswordHelper.java:58: MessageDigest.getInstance("MD5")', fix: '改用 bcrypt / PBKDF2 / Argon2id 等自适应哈希算法，加入随机盐。' },
  { id: 'f4', category: '反编译保护', title: '代码未混淆（无 ProGuard/R8）', severity: 'medium', detail: '应用未启用代码混淆，通过 jadx 可直接还原业务逻辑和 API 密钥。', evidence: 'classes.dex: 类名未混淆，发现硬编码 ALIYUN_ACCESS_KEY = "LTAI5t…"', fix: '在 build.gradle 启用 minifyEnabled=true，配置合理的 ProGuard 规则。' },
  { id: 'f5', category: '日志泄露', title: 'Log.d/Log.e 输出敏感信息', severity: 'low', detail: '调试日志输出包含用户凭证和接口响应体，Release 版本未关闭日志。', evidence: 'LoginActivity.java:89: Log.d("login", "password=" + pwd)', fix: '通过 BuildConfig.DEBUG 控制日志输出，或使用 Timber 统一管理日志。' },
  { id: 'f6', category: '组件安全', title: 'Activity 组件 exported 未保护', severity: 'medium', detail: 'com.target.app.DebugActivity exported=true 且无权限保护，可被第三方 App 拉起。', evidence: 'AndroidManifest.xml: <activity android:name=".DebugActivity" android:exported="true"/>', fix: '对非必须 exported 的组件设置 android:exported="false" 或添加自定义权限。' },
  { id: 'f7', category: '网络通信', title: 'SSL/TLS 证书校验被绕过', severity: 'critical', detail: 'TrustManager 实现为空实现，任意证书均被接受，存在中间人攻击风险。', evidence: 'SSLHelper.java:23: checkServerTrusted() {} // 空实现', fix: '使用系统默认 TrustManager 或实现证书 Pinning（OkHttp CertificatePinner）。' },
]

const CATEGORIES = ['全部', '数据存储', '网络通信', '密码学', '反编译保护', '日志泄露', '组件安全']

export default function MobileAppView() {
  const [platform, setPlatform] = useState<Platform>('android')
  const [fileName, setFileName] = useState<string | null>(null)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [findings, setFindings] = useState<AppFinding[]>([])
  const [filterCat, setFilterCat] = useState('全部')
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [phase, setPhase] = useState('')

  const PHASES = ['反编译 APK/IPA…', '提取 Manifest/Info.plist…', '静态代码扫描…', '污点分析…', '生成报告…']

  function simulate() {
    if (!fileName) return
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
        <StatCard label="严重" value={sevCount('critical') || '—'} icon={<Lock size={18} />} />
        <StatCard label="高危" value={sevCount('high') || '—'} icon={<ShieldAlert size={18} />} />
        <StatCard label="中危" value={sevCount('medium') || '—'} icon={<Globe size={18} />} />
        <StatCard label="低危" value={sevCount('low') || '—'} icon={<FileText size={18} />} />
      </div>

      <Panel title="应用安全评估" icon={<Smartphone size={16} />}>
        <div className="space-y-4">
          <div className="flex gap-2">
            {(['android', 'ios'] as Platform[]).map((p) => (
              <button key={p} onClick={() => setPlatform(p)}
                className={`chip border transition ${platform === p ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line bg-base-700/40 text-slate-400'}`}>
                {p === 'android' ? 'Android' : 'iOS'}
              </button>
            ))}
          </div>

          <label className={`flex h-24 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition
            ${fileName ? 'border-cyber/40 bg-cyber/5' : 'border-line bg-base-700/40 hover:border-cyber/30'}`}>
            <Upload size={24} className="mb-2 text-slate-500" />
            <span className="text-sm text-slate-400">
              {fileName
                ? <span className="text-cyber font-mono">{fileName}</span>
                : <span>拖放 {platform === 'android' ? 'APK / AAB' : 'IPA'} 文件至此或点击上传</span>
              }
            </span>
            <input type="file" className="hidden"
              accept={platform === 'android' ? '.apk,.aab' : '.ipa'}
              onChange={(e) => setFileName(e.target.files?.[0]?.name ?? null)} />
          </label>

          <div className="flex items-center gap-3">
            <button onClick={simulate} disabled={running || !fileName}
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
                  </div>
                  <ChevronRight size={14} className={`shrink-0 text-slate-500 transition ${expanded === f.id ? 'rotate-90' : ''}`} />
                </button>
                {expanded === f.id && (
                  <div className="border-t border-line px-4 pb-4 pt-3 space-y-3 text-xs">
                    <div>
                      <div className="mb-1 text-slate-500">描述</div>
                      <div className="text-slate-300">{f.detail}</div>
                    </div>
                    <div>
                      <div className="mb-1 text-slate-500">证据</div>
                      <pre className="rounded bg-black/50 px-3 py-2 font-mono text-[10px] text-amber-300 overflow-x-auto">{f.evidence}</pre>
                    </div>
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
