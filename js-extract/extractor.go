package jsextract

// extractor.go — JS 静态分析引擎（对标 truffleHog + SecretFinder + LinkFinder）
//
// 核心设计：
//   1. 服务专属规则（50+）：每条规则独立命名，与 truffleHog 规则库对齐
//   2. Shannon 熵过滤：对通用 key=value 型规则校验值的随机度，剔除 placeholder/示例字符串
//   3. 黑名单过滤：去除常见 false-positive（example/placeholder/test 等）
//   4. 注释挖掘：提取 // 与 /* */ 注释内的敏感信息
//   5. 结果去重（category|value 级）+ 单文件上限（maxFindingsPerFile）+ 截断（500 字符）

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ── 单文件 finding 上限（防止超大混淆 bundle 导致内存暴涨）───────────────
const maxFindingsPerFile = 2000

// ── 类别 & 严重级别常量 ──────────────────────────────────────────────
const (
	CatEndpoint  = "endpoint"
	CatSecret    = "secret"
	CatIP        = "ip"
	CatCloud     = "cloud"
	CatSourceMap = "sourcemap"
	CatJWT       = "jwt"
	CatEmail     = "email"
	CatURL       = "url"
)

const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
	SevInfo   = "info"
)

// Finding 是单条提取结果。
type Finding struct {
	ID        string  `json:"id"`
	TaskID    string  `json:"taskId"`
	JSURL     string  `json:"jsUrl"`
	PageURL   string  `json:"pageUrl"`
	Category  string  `json:"category"`
	Severity  string  `json:"severity"`
	Label     string  `json:"label"`     // 含服务名
	Value     string  `json:"value"`
	Context   string  `json:"ctx"`
	Entropy   float64 `json:"entropy"`   // Shannon 熵，0=未计算
	Confident bool    `json:"confident"` // 高精度匹配（服务专属格式）
	FoundAt   string  `json:"foundAt"`
}

func newFindingID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// 熵源不可用时退回时间戳，避免全零 ID 引发 DB 冲突
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ── Shannon 熵 ────────────────────────────────────────────────────────
// 高随机度字符串（entropy≥3.5）更可能是真实密钥，低于阈值则过滤掉
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return math.Round(h*100) / 100
}

// ── 提取规则类型 ──────────────────────────────────────────────────────
type rule struct {
	label     string
	cat       string
	sev       string
	re        *regexp.Regexp
	grp       int     // capture group index（0=整体匹配作为值，1+=捕获组）
	minEnt    float64 // 对 grp>0 的值做熵检验（0=跳过）
	confident bool    // 服务专属高精度格式
}

// ── 密钥规则（50+ 条）────────────────────────────────────────────────
var secretRules = []rule{
	// ── AWS ──────────────────────────────────────────────────────────
	{"AWS Access Key ID", CatSecret, SevHigh,
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), 0, 0, true},
	{"AWS MFA Device ARN", CatSecret, SevMedium,
		regexp.MustCompile(`\bARN:aws:[a-z0-9-]+::[0-9]{12}:[^\s"'<>]{5,100}\b`), 0, 0, true},
	{"AWS Secret Access Key", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)aws[_-]?(?:secret|access[_-]?key)[_-]?(?:id)?\s*[:=]\s*["']([a-zA-Z0-9+/]{40})["']`), 1, 4.0, true},
	{"AWS Session Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)aws[_-]?session[_-]?token\s*[:=]\s*["']([a-zA-Z0-9+/=]{100,})["']`), 1, 4.0, false},

	// ── 阿里云 ────────────────────────────────────────────────────────
	{"阿里云 AccessKey ID", CatSecret, SevHigh,
		regexp.MustCompile(`\b(?:LTAI|AKID)[a-zA-Z0-9]{16,40}\b`), 0, 0, true},
	{"阿里云 Secret", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:aliyun|alibabacloud)[_-]?(?:secret|sk|access_key_secret)\s*[:=]\s*["']([a-zA-Z0-9]{30,64})["']`), 1, 3.5, true},

	// ── 腾讯云 ────────────────────────────────────────────────────────
	{"腾讯云 SecretId", CatSecret, SevHigh,
		regexp.MustCompile(`\bAKID[a-zA-Z0-9]{32}\b`), 0, 0, true},
	{"腾讯云 SecretKey", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:tencent|qcloud)[_-]?(?:secret[_-]?key|sk)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']`), 1, 3.5, true},

	// ── 华为云 ────────────────────────────────────────────────────────
	{"华为云 AK/SK", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:huawei|obs)[_-]?(?:access[_-]?key|ak)\s*[:=]\s*["']([A-Z0-9]{20})["']`), 1, 3.5, true},

	// ── Google ────────────────────────────────────────────────────────
	{"Google API Key", CatSecret, SevHigh,
		regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), 0, 0, true},
	{"Google OAuth Client ID", CatSecret, SevMedium,
		regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`), 0, 0, true},
	{"Google Service Account", CatSecret, SevHigh,
		regexp.MustCompile(`"type"\s*:\s*"service_account"`), 0, 0, true},
	{"Firebase API Key", CatSecret, SevMedium,
		regexp.MustCompile(`(?i)firebase[_-]?(?:api[_-]?key|key)\s*[:=]\s*["']([a-zA-Z0-9_-]{35,40})["']`), 1, 3.0, true},

	// ── GitHub ────────────────────────────────────────────────────────
	{"GitHub PAT (Fine-grained)", CatSecret, SevHigh,
		regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{82}\b`), 0, 0, true},
	{"GitHub PAT (Classic)", CatSecret, SevHigh,
		regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`), 0, 0, true},
	{"GitHub OAuth Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36}\b`), 0, 0, true},
	{"GitHub Actions Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bghs_[a-zA-Z0-9]{36}\b`), 0, 0, true},
	{"GitHub Refresh Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bghr_[a-zA-Z0-9]{36}\b`), 0, 0, true},

	// ── GitLab ────────────────────────────────────────────────────────
	{"GitLab PAT", CatSecret, SevHigh,
		regexp.MustCompile(`\bglpat-[a-zA-Z0-9_-]{20}\b`), 0, 0, true},
	{"GitLab Runner Registration Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bglrt-[a-zA-Z0-9_-]{20}\b`), 0, 0, true},
	{"GitLab CI Job Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bglcbt-[a-zA-Z0-9_-]{20}\b`), 0, 0, true},

	// ── Slack ─────────────────────────────────────────────────────────
	{"Slack Bot Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bxoxb-[0-9a-zA-Z-]{10,48}\b`), 0, 0, true},
	{"Slack User Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bxoxp-[0-9a-zA-Z-]{10,48}\b`), 0, 0, true},
	{"Slack App Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bxapp-[0-9a-zA-Z-]{10,48}\b`), 0, 0, true},
	{"Slack Legacy Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bxoxa-[0-9a-zA-Z-]{10,48}\b`), 0, 0, true},
	{"Slack Webhook URL", CatSecret, SevHigh,
		regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`), 0, 0, true},

	// ── Stripe ────────────────────────────────────────────────────────
	{"Stripe Live Secret Key", CatSecret, SevHigh,
		regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`), 0, 0, true},
	{"Stripe Live Publishable Key", CatSecret, SevMedium,
		regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,}\b`), 0, 0, true},
	{"Stripe Test Secret Key", CatSecret, SevLow,
		regexp.MustCompile(`\bsk_test_[0-9a-zA-Z]{24,}\b`), 0, 0, true},
	{"Stripe Webhook Secret", CatSecret, SevHigh,
		regexp.MustCompile(`\bwhsec_[a-zA-Z0-9]{32,}\b`), 0, 0, true},

	// ── Discord ───────────────────────────────────────────────────────
	{"Discord Webhook URL", CatSecret, SevHigh,
		regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+`), 0, 0, true},
	{"Discord Bot Token", CatSecret, SevHigh,
		regexp.MustCompile(`\b[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}\b`), 0, 0, true},

	// ── SendGrid ──────────────────────────────────────────────────────
	{"SendGrid API Key", CatSecret, SevHigh,
		regexp.MustCompile(`\bSG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}\b`), 0, 0, true},

	// ── Twilio ────────────────────────────────────────────────────────
	{"Twilio Account SID", CatSecret, SevMedium,
		regexp.MustCompile(`\bAC[a-f0-9]{32}\b`), 0, 0, true},
	{"Twilio API Key SID", CatSecret, SevHigh,
		regexp.MustCompile(`\bSK[a-f0-9]{32}\b`), 0, 0, true},
	{"Twilio Auth Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)twilio[_-]?(?:auth[_-]?token|token)\s*[:=]\s*["']([a-f0-9]{32})["']`), 1, 3.5, true},

	// ── Square ────────────────────────────────────────────────────────
	{"Square Access Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bsq0atp-[0-9A-Za-z\-_]{22}\b`), 0, 0, true},
	{"Square OAuth Secret", CatSecret, SevHigh,
		regexp.MustCompile(`\bsq0csp-[0-9A-Za-z\-_]{43}\b`), 0, 0, true},

	// ── Telegram ──────────────────────────────────────────────────────
	{"Telegram Bot Token", CatSecret, SevHigh,
		regexp.MustCompile(`\b[0-9]{8,10}:AA[a-zA-Z0-9_-]{33}\b`), 0, 0, true},

	// ── WeChat / 微信 ─────────────────────────────────────────────────
	{"微信 AppID", CatSecret, SevMedium,
		regexp.MustCompile(`\bwx[a-f0-9]{16}\b`), 0, 0, true},
	{"微信 AppSecret", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:wechat|wx|weixin)[_-]?(?:app[_-]?secret|secret)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']`), 1, 3.5, true},

	// ── Mailgun ───────────────────────────────────────────────────────
	{"Mailgun API Key", CatSecret, SevHigh,
		regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`), 0, 0, true},

	// ── PEM 私钥 ──────────────────────────────────────────────────────
	{"PEM 私钥 (BEGIN PRIVATE KEY)", CatSecret, SevHigh,
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), 0, 0, true},

	// ── Azure ─────────────────────────────────────────────────────────
	{"Azure Storage Connection String", CatSecret, SevHigh,
		regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+`), 0, 0, true},
	{"Azure SAS Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)SharedAccessSignature=[^\s"'<>&]{20,500}`), 0, 0, false},

	// ── NPM ───────────────────────────────────────────────────────────
	{"NPM Access Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`), 0, 0, true},

	// ── OpenAI ────────────────────────────────────────────────────────
	{"OpenAI API Key", CatSecret, SevHigh,
		regexp.MustCompile(`\bsk-(?:proj-[a-zA-Z0-9_-]{56,}|[a-zA-Z0-9]{48})\b`), 0, 0, true},

	// ── Anthropic ─────────────────────────────────────────────────────
	{"Anthropic API Key", CatSecret, SevHigh,
		regexp.MustCompile(`\bsk-ant-(?:api\d{2}-)?[a-zA-Z0-9_-]{90,}\b`), 0, 0, true},

	// ── HuggingFace ───────────────────────────────────────────────────
	{"HuggingFace Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bhf_[a-zA-Z0-9]{34}\b`), 0, 0, true},

	// ── Databricks ────────────────────────────────────────────────────
	{"Databricks Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bdapi[a-zA-Z0-9]{32}\b`), 0, 0, true},

	// ── Shopify ───────────────────────────────────────────────────────
	{"Shopify Private App Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bshppa_[a-zA-Z0-9]{32}\b`), 0, 0, true},
	{"Shopify Access Token", CatSecret, SevHigh,
		regexp.MustCompile(`\bshpat_[a-zA-Z0-9]{32}\b`), 0, 0, true},
	{"Shopify Shared Secret", CatSecret, SevHigh,
		regexp.MustCompile(`\bshpss_[a-zA-Z0-9]{32}\b`), 0, 0, true},

	// ── Heroku ────────────────────────────────────────────────────────
	{"Heroku API Key", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)heroku[_-]?(?:api[_-]?key|token)\s*[:=]\s*["']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']`), 1, 3.5, true},

	// ── Vercel ────────────────────────────────────────────────────────
	{"Vercel Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)vercel[_-]?(?:api[_-]?)?token\s*[:=]\s*["']([a-zA-Z0-9]{24,})["']`), 1, 3.5, false},

	// ── Netlify ───────────────────────────────────────────────────────
	{"Netlify Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)netlify[_-]?(?:api[_-]?)?token\s*[:=]\s*["']([a-zA-Z0-9_-]{24,})["']`), 1, 3.5, false},

	// ── Cloudflare ────────────────────────────────────────────────────
	{"Cloudflare API Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)cloudflare[_-]?(?:api[_-]?)?token\s*[:=]\s*["']([a-zA-Z0-9_-]{40})["']`), 1, 3.5, true},

	// ── Linear ────────────────────────────────────────────────────────
	{"Linear API Key", CatSecret, SevHigh,
		regexp.MustCompile(`\blin_api_[a-zA-Z0-9]{40}\b`), 0, 0, true},

	// ── Sentry DSN（包含 auth key，泄露即可接收/写入你的 Sentry 项目数据）──
	{"Sentry DSN", CatSecret, SevMedium,
		regexp.MustCompile(`https://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest(?:\.us|\.eu)?\.sentry\.io/[0-9]+`), 0, 0, true},

	// ── process.env 降级值（生产环境 fallback 硬编码）──────────────────
	// 形如: process.env.REACT_APP_KEY || "sk-prod-..."
	// 开发者误以为环境变量会覆盖，但部分 SSG/bundler 会把 fallback 打包进 bundle。
	// 排除 https?:// 开头的值（那些是 URL，由 endpointRules 的 process.env URL 规则处理）。
	{"process.env 降级密钥", CatSecret, SevHigh,
		regexp.MustCompile(`process\.env\.[A-Z][A-Z0-9_]{2,49}\s*\|\|\s*["']([^"']{8,256})["']`), 1, 3.0, false},

	// ── Generic（熵过滤保护，minEnt≥3.5）────────────────────────────
	{"API Key", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:api[_-]?key|apiKey|app[_-]?key|appKey)\s*[:=]\s*["']([^"'\s]{16,128})["']`), 1, 3.5, false},
	{"Client Secret", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:client[_-]?secret|app[_-]?secret|consumer[_-]?secret)\s*[:=]\s*["']([^"'\s]{16,128})["']`), 1, 3.5, false},
	{"密码 (Password)", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{6,128})["']`), 1, 2.8, false},
	{"Access Token", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token)\s*[:=]\s*["']([^"'\s]{16,256})["']`), 1, 3.5, false},
	{"Private Key", CatSecret, SevHigh,
		regexp.MustCompile(`(?i)(?:private[_-]?key|rsa[_-]?key|ssh[_-]?key)\s*[:=]\s*["']([^"']{16,512})["']`), 1, 3.0, false},
}

// ── 端点规则 ─────────────────────────────────────────────────────────
var endpointRules = []rule{
	{"API 调用(fetch/axios)", CatEndpoint, SevMedium,
		regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|patch|delete|request)|\.open)\s*\(\s*["'](/[a-zA-Z0-9_/%.+:@!=-]{2,200})["']`), 1, 0, false},
	{"baseURL 配置", CatEndpoint, SevMedium,
		regexp.MustCompile(`(?i)base[_-]?[Uu][Rr][Ll]\s*[:=]\s*["'](https?://[^"']{4,200})["']`), 1, 0, false},
	{"API 路径 (/api/)", CatEndpoint, SevMedium,
		regexp.MustCompile(`["'](/(?:api|v[0-9]+|rest|graphql|rpc|gw|gateway|service|internal|backend|admin)[a-zA-Z0-9_./?=&%+#:-]{0,150})["']`), 1, 0, false},
	{"表单 action URL", CatEndpoint, SevLow,
		regexp.MustCompile(`(?i)action\s*[:=]\s*["'](/[a-zA-Z0-9_/%.+:@!=-]{2,150})["']`), 1, 0, false},
	{"GraphQL Endpoint", CatEndpoint, SevMedium,
		regexp.MustCompile(`["']((?:https?://[^"']*)?/graphql(?:[^"'<>]*)?)["']`), 1, 0, false},
	{"WebSocket URL", CatEndpoint, SevMedium,
		regexp.MustCompile(`["'](wss?://[^\s"'<>]{5,200})["']`), 1, 0, false},
	// 模板字面量中的静态路径段（反引号字符串，\x60 = `）
	// 捕获 `${var}/api/endpoint` 中 ${} 后面的静态路径部分
	{"模板字面量路径", CatEndpoint, SevLow,
		regexp.MustCompile(`\x60\$\{[^}]{1,60}\}(/(?:api|v[0-9]+|rest|graphql|admin|internal)[a-zA-Z0-9_/.-]{0,100})\x60`), 1, 0, false},
	// process.env 环境变量 URL（常用于 baseURL 配置）
	{"process.env URL", CatEndpoint, SevMedium,
		regexp.MustCompile(`process\.env\.[A-Z][A-Z0-9_]{2,49}\s*(?:\|\|\s*)?["'](https?://[^\s"'<>]{5,200})["']`), 1, 0, false},
}

// ── 云存储规则 ───────────────────────────────────────────────────────
var cloudRules = []rule{
	{"AWS S3 Bucket", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.s3(?:[-.][\w-]+)?\.amazonaws\.com(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"阿里云 OSS", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.oss-[\w-]+\.aliyuncs\.com(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"腾讯云 COS", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.cos\.[\w-]+\.myqcloud\.com(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"Google Cloud Storage", CatCloud, SevMedium,
		regexp.MustCompile(`(storage\.googleapis\.com/[\w.-]+(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"华为云 OBS", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.obs\.[\w-]+\.myhuaweicloud\.com(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"Azure Blob Storage", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.blob\.core\.windows\.net(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"Azure Files Storage", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.file\.core\.windows\.net(?:/[^\s"'<>]*)?)`), 0, 0, true},
	{"Firebase Storage", CatCloud, SevMedium,
		regexp.MustCompile(`([\w.-]+\.firebasestorage\.app(?:/[^\s"'<>]*)?)`), 0, 0, true},
}

// ── 单条规则 ─────────────────────────────────────────────────────────
var (
	reRFC1918 = regexp.MustCompile(
		`(?:^|[^0-9.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?(?:[^0-9.]|$)`)
	reLocalhost = regexp.MustCompile(`["']((?:localhost|127\.0\.0\.1)(?::\d{2,5})?)["']`)

	reSourceMap = regexp.MustCompile(`//[#@] sourceMappingURL=(\S+)`)
	reJWT       = regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{10,}`)
	reEmail     = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b`)
	reExtURL    = regexp.MustCompile(`["'](https?://[^\s"'<>]{10,200})["']`)

	reSingleComment = regexp.MustCompile(`//[^\n]{4,500}`)
	reBlockComment  = regexp.MustCompile(`/\*[\s\S]{4,999}?\*/`)

	reCommentSecret = regexp.MustCompile(`(?i)(?:password|token|secret|key|credential|apikey)\s*[:=]\s*(\S{6,128})`)
)

// ── 噪音过滤词 ───────────────────────────────────────────────────────
var noiseWords = []string{
	// 英文占位符
	"example.com", "example.org", "your-", "YOUR_", "<your", "${", "placeholder",
	"xxx", "***", "TODO", "undefined", "null",
	"test.com", "foo.com", "bar.com", "test_", "fake_",
	"changeme", "insert_", "replace_", "your_api", "your_key",
	"xxxxxxxx", "00000000", "11111111", "aaaaaa",
	"dummy", "sample", "demo", "mock", "stub",
	"not-set", "notset", "none", "empty", "invalid",
	"your-token", "yourtoken", "mytoken", "mykey", "mysecret",
	// 中文占位符
	"示例", "填写", "你的", "请输入", "待填写",
	// 技术性噪声
	"@2x", "@3x", "data:image", "data:text",
}

var reSemVer = regexp.MustCompile(`^\d+\.\d+\.\d+`)

func isNoise(v string) bool {
	if len(v) < 3 {
		return true
	}
	// 版本号（semver）不是密钥
	if reSemVer.MatchString(v) {
		return true
	}
	vl := strings.ToLower(v)
	for _, w := range noiseWords {
		if strings.Contains(vl, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// isCodeFragment 判断字符串是否是 JS 代码片段而非凭据值。
// 主要用于过滤注释挖掘（scanComment）中常见的误报：
//   key = names[i++])  →  含括号 → 代码
//   step.value;\n      →  以分号结尾 → 代码
func isCodeFragment(v string) bool {
	// 含括号/花括号 → 函数调用或对象表达式
	if strings.ContainsAny(v, "(){}[]") {
		return true
	}
	// 去除尾部空白后以分号或逗号结尾 → JS 语句/参数列表
	trimmed := strings.TrimRight(v, " \t\r\n\\")
	if strings.HasSuffix(trimmed, ";") || strings.HasSuffix(trimmed, ",") {
		return true
	}
	// JS 关键字作为"值"
	switch strings.ToLower(trimmed) {
	case "true", "false", "null", "undefined", "function", "return", "this", "void":
		return true
	}
	return false
}

var commonCDNs = []string{
	"cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
	"unpkg.com", "fonts.googleapis.com", "fonts.gstatic.com",
	"cdn.bootcdn.net", "lib.baomitu.com", "static.cloudflareinsights.com",
	"gtm.google.com", "googletagmanager.com", "analytics.google.com",
}

func isCommonCDN(u string) bool {
	for _, cdn := range commonCDNs {
		if strings.Contains(u, cdn) {
			return true
		}
	}
	return false
}

var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".ico", ".woff", ".woff2", ".ttf", ".map",
}

func hasStaticExt(path string) bool {
	base := strings.Split(strings.ToLower(path), "?")[0]
	for _, ext := range staticExtensions {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// ── 主提取函数 ──────────────────────────────────────────────────────
// Extract 对单个 JS 文件内容运行全部规则，返回去重后的 Finding 列表。
// 单文件上限 maxFindingsPerFile 条，防止超大混淆 bundle 撑爆内存。
func Extract(jf JSFile, taskID string) []Finding {
	content := jf.Content
	now := time.Now().Format("2006-01-02 15:04:05")
	seen := make(map[string]bool)
	var out []Finding

	add := func(cat, sev, label, val, ctx string, ent float64, confident bool) {
		if len(out) >= maxFindingsPerFile {
			return
		}
		key := cat + "|" + val
		if len(val) < 3 || seen[key] || isNoise(val) {
			return
		}
		seen[key] = true
		if runes := []rune(val); len(runes) > 500 {
			val = string(runes[:500]) + "…"
		}
		out = append(out, Finding{
			ID: newFindingID(), TaskID: taskID,
			JSURL: jf.URL, PageURL: jf.PageURL,
			Category: cat, Severity: sev, Label: label,
			Value: val, Context: ctx,
			Entropy: ent, Confident: confident,
			FoundAt: now,
		})
	}

	// 取匹配位置周围的代码上下文（单行化，±120 字节）
	// 对齐到 UTF-8 字符边界，避免多字节字符被截断产生无效序列。
	surround := func(start, end int) string {
		from := start - 120
		if from < 0 {
			from = 0
		} else {
			// 向前步进到 rune 起始字节（跳过 UTF-8 后继字节 0x80-0xBF）
			for from < len(content) && !utf8.RuneStart(content[from]) {
				from++
			}
		}
		to := end + 120
		if to >= len(content) {
			to = len(content)
		} else {
			// 向后步进到 rune 起始字节
			for to > 0 && !utf8.RuneStart(content[to]) {
				to--
			}
		}
		s := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' {
				return ' '
			}
			return r
		}, content[from:to])
		return strings.TrimSpace(s)
	}

	// ── 密钥规则 ────────────────────────────────────────────────────
	for _, r := range secretRules {
		if len(out) >= maxFindingsPerFile {
			break
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(content, -1) {
			var val string
			var vs, ve int
			if r.grp == 0 {
				vs, ve = m[0], m[1]
			} else if len(m) > r.grp*2+1 && m[r.grp*2] >= 0 {
				vs, ve = m[r.grp*2], m[r.grp*2+1]
			} else {
				continue
			}
			val = content[vs:ve]
			// grp>0 的捕获组规则：值部分若为 URL 则属于端点，不归密钥。
			// grp=0 的完整匹配规则（如 Slack webhook、Discord webhook、Sentry DSN）
			// 本身就是 URL 型密钥，不过滤。
			if r.grp > 0 && (strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://")) {
				continue
			}
			ent := 0.0
			if r.minEnt > 0 {
				ent = shannonEntropy(val)
				if ent < r.minEnt {
					continue
				}
			}
			add(r.cat, r.sev, r.label, val, surround(m[0], m[1]), ent, r.confident)
		}
	}

	// ── 端点规则 ────────────────────────────────────────────────────
	for _, r := range endpointRules {
		if len(out) >= maxFindingsPerFile {
			break
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(content, -1) {
			var val string
			if r.grp == 0 {
				val = content[m[0]:m[1]]
			} else if len(m) > r.grp*2+1 && m[r.grp*2] >= 0 {
				val = content[m[r.grp*2]:m[r.grp*2+1]]
			} else {
				continue
			}
			if hasStaticExt(val) {
				continue
			}
			add(r.cat, r.sev, r.label, val, surround(m[0], m[1]), 0, false)
		}
	}

	// ── 云存储 ────────────────────────────────────────────────────────
	if len(out) < maxFindingsPerFile {
		for _, r := range cloudRules {
			for _, m := range r.re.FindAllStringSubmatchIndex(content, -1) {
				val := content[m[0]:m[1]]
				add(r.cat, r.sev, r.label, val, surround(m[0], m[1]), 0, true)
			}
		}
	}

	// ── 内网地址 ──────────────────────────────────────────────────────
	if len(out) < maxFindingsPerFile {
		for _, m := range reRFC1918.FindAllStringSubmatchIndex(content, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				add(CatIP, SevMedium, "内网 IP (RFC 1918)", content[m[2]:m[3]], surround(m[0], m[1]), 0, false)
			}
		}
		for _, m := range reLocalhost.FindAllStringSubmatchIndex(content, -1) {
			add(CatIP, SevLow, "localhost 地址", content[m[2]:m[3]], surround(m[0], m[1]), 0, false)
		}
	}

	// ── Source Map ────────────────────────────────────────────────────
	if len(out) < maxFindingsPerFile {
		for _, m := range reSourceMap.FindAllStringSubmatchIndex(content, -1) {
			add(CatSourceMap, SevHigh, "Source Map 引用", content[m[2]:m[3]], surround(m[0], m[1]), 0, true)
		}
	}

	// ── JWT ───────────────────────────────────────────────────────────
	if len(out) < maxFindingsPerFile {
		for _, m := range reJWT.FindAllStringIndex(content, -1) {
			val := content[m[0]:m[1]]
			ent := shannonEntropy(val)
			add(CatJWT, SevHigh, "JWT Token", val, surround(m[0], m[1]), ent, true)
		}
	}

	// ── 邮箱 ──────────────────────────────────────────────────────────
	// 修复：ContainsAny 按字符集匹配，"@2x@3x" 会导致所有含 @ 的邮箱被过滤。
	// 正确方式：用 strings.Contains 分别匹配字符串。
	if len(out) < maxFindingsPerFile {
		for _, m := range reEmail.FindAllStringIndex(content, -1) {
			val := content[m[0]:m[1]]
			if strings.Contains(val, "@2x") || strings.Contains(val, "@3x") || strings.HasSuffix(val, ".png") {
				continue
			}
			add(CatEmail, SevLow, "邮箱地址", val, surround(m[0], m[1]), 0, false)
		}
	}

	// ── 外部 URL ──────────────────────────────────────────────────────
	if len(out) < maxFindingsPerFile {
		for _, m := range reExtURL.FindAllStringSubmatchIndex(content, -1) {
			val := content[m[2]:m[3]]
			if isCommonCDN(val) {
				continue
			}
			add(CatURL, SevInfo, "外部 URL", val, surround(m[0], m[1]), 0, false)
		}
	}

	// ── JS 注释挖掘 ──────────────────────────────────────────────────
	extractComments(content, jf, taskID, now, seen, &out)

	return out
}

// extractComments 专门提取 JS 注释（// 与 /* */）中的敏感信息。
func extractComments(content string, jf JSFile, taskID, now string, seen map[string]bool, out *[]Finding) {
	addC := func(cat, sev, label, val, ctx string, ent float64) {
		if len(*out) >= maxFindingsPerFile {
			return
		}
		// 与 add() 使用相同的 key 格式，确保注释和代码段中的相同值能正确跨去重。
		key := cat + "|" + val
		if len(val) < 8 || seen[key] || isNoise(val) || isCodeFragment(val) {
			return
		}
		seen[key] = true
		if runes := []rune(val); len(runes) > 200 {
			val = string(runes[:200]) + "…"
		}
		*out = append(*out, Finding{
			ID: newFindingID(), TaskID: taskID,
			JSURL: jf.URL, PageURL: jf.PageURL,
			Category: cat, Severity: sev,
			Label:   "注释·" + label,
			Value:   val, Context: ctx,
			Entropy: ent,
			FoundAt: now,
		})
	}

	scanComment := func(comment string) {
		for _, m := range reCommentSecret.FindAllStringSubmatchIndex(comment, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			val := comment[m[2]:m[3]]
			ent := shannonEntropy(val)
			// 注释内凭据阈值高于规则扫描（4.0 vs 3.2）：注释文本语境更复杂，
			// Base64 编码的普通数据（如 i18n hash / data-URI 片段）也会达到 3.x，
			// 4.0 能有效过滤而不丢掉真实高熵密钥。
			if ent < 4.0 || isNoise(val) || isCodeFragment(val) {
				continue
			}
			ctx := strings.TrimSpace(comment)
			if ctxRunes := []rune(ctx); len(ctxRunes) > 200 {
				ctx = string(ctxRunes[:200]) + "…"
			}
			addC(CatSecret, SevMedium, "凭据", val, ctx, ent)
		}
	}

	for _, m := range reSingleComment.FindAllStringIndex(content, -1) {
		scanComment(content[m[0]:m[1]])
	}
	for _, m := range reBlockComment.FindAllStringIndex(content, -1) {
		scanComment(content[m[0]:m[1]])
	}
}
