package jsextract

import (
	"strings"
	"testing"
)

// TestExtract_NewRules 验证新增的 12 条服务规则能正确命中。
func TestExtract_NewRules(t *testing.T) {
	content := strings.Join([]string{
		// NPM token (36 chars after "npm_")
		`var NPM_TOKEN = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";`,
		// OpenAI key (old format: exactly 48 alphanumeric after "sk-")
		`const OPENAI = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";`,
		// HuggingFace (34 chars after "hf_")
		`const HF = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";`,
		// Databricks (32 chars after "dapi")
		`var DB_TOKEN = "dapiABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";`,
		// Shopify PAT (32 chars after "shppa_")
		`var SHOP = "shppa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";`,
		// AWS Access Key
		`var AWS_KEY = "AKIAIOSFODNN7EXAMPL1";`,
		// Stripe live key (≥24 chars after "sk_live_")
		`var STRIPE = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";`,
		// Discord webhook (ID 必须是数字)
		`var DWHOOK = "https://discord.com/api/webhooks/1234567890/ABCDEFGHIJKLMNOPQRSTUVWXYZab";`,
		// GitHub PAT (36 chars after "ghp_")
		`var GH = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";`,
	}, "\n")

	jf := JSFile{URL: "http://test.local/app.js", PageURL: "http://test.local/", Content: content}
	findings := Extract(jf, "task-test-rules")

	cats := make(map[string]int)
	labels := make(map[string]bool)
	for _, f := range findings {
		cats[f.Category]++
		labels[f.Label] = true
	}

	expected := []string{"NPM Access Token", "OpenAI API Key", "HuggingFace Token", "Databricks Token", "Shopify Private App Token"}
	for _, lbl := range expected {
		if !labels[lbl] {
			t.Errorf("未命中规则: %s", lbl)
		}
	}
	t.Logf("总命中: %d 条，分类: %v", len(findings), cats)
}

// TestExtract_InlineScript 验证内联脚本提取格式正确。
func TestExtract_InlineScript(t *testing.T) {
	content := `var apiKey = "AIzaSyDXabcdef1234567890ABCDE12345678";
fetch("/api/v1/admin/users");
var INTERNAL = "192.168.10.50";`

	jf := JSFile{
		URL:     "http://test.local/#inline-0",
		PageURL: "http://test.local/",
		Content: content,
	}
	findings := Extract(jf, "task-inline")

	if len(findings) == 0 {
		t.Fatal("内联脚本应命中至少 1 条 finding")
	}
	for _, f := range findings {
		t.Logf("[%s] %s = %s", f.Severity, f.Label, f.Value)
	}
}

// TestExtract_NoiseFilter 验证 semver 和占位符被正确过滤。
func TestExtract_NoiseFilter(t *testing.T) {
	if !isNoise("1.2.3-beta.4") {
		t.Error("semver 应被识别为噪音")
	}
	if !isNoise("changeme") {
		t.Error("changeme 应被识别为噪音")
	}
	if !isNoise("示例密钥") {
		t.Error("中文占位符应被识别为噪音")
	}
	if isNoise("AIzaSyDXABCDEFGHIJKLMNOPQRSTUVWXYZabc") {
		t.Error("真实 Google API Key 不应被过滤")
	}
	t.Log("噪音过滤测试通过")
}

// TestParseSourceMapContent 验证 Source Map JSON 解析正确还原 sourcesContent。
func TestParseSourceMapContent(t *testing.T) {
	mapContent := `{
  "version": 3,
  "sources": ["src/config.ts", "src/api/client.ts"],
  "sourcesContent": [
    "export const API_KEY = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';",
    "import axios from 'axios';\nconst BASE = '/api/v2';"
  ],
  "mappings": "AAAA"
}`
	jf := JSFile{
		URL:     "http://test.local/app.js.map",
		PageURL: "http://test.local/",
		Content: mapContent,
		IsMap:   true,
	}
	extras := ParseSourceMapContent(jf)
	if len(extras) != 2 {
		t.Fatalf("应解析出 2 个源文件，实际 %d 个", len(extras))
	}
	if !strings.Contains(extras[0].URL, "src/config.ts") {
		t.Errorf("第一个文件 URL 应含源文件名，实际: %s", extras[0].URL)
	}
	if !strings.Contains(extras[0].Content, "sk_live_") {
		t.Error("sourcesContent[0] 应包含 Stripe key")
	}
	// 在还原的源文件上运行提取，验证可以找到真实密钥
	findings := Extract(extras[0], "task-sourcemap")
	found := false
	for _, f := range findings {
		if f.Category == CatSecret {
			found = true
			t.Logf("sourcemap 还原源码中找到: [%s] %s = %s", f.Severity, f.Label, f.Value)
		}
	}
	if !found {
		t.Error("sourcemap 还原源码中应找到 Stripe live key")
	}
}

// TestExtract_NewPatterns 验证 process.env 降级值和模板字面量路径检测。
func TestExtract_NewPatterns(t *testing.T) {
	content := `
// process.env 降级密钥（最常见的前端硬编码模式）
const API_KEY = process.env.REACT_APP_API_KEY || "sk-live_ABCDEFGHIJKLMNOPQRSTUVabcd";
const BASE_URL = process.env.REACT_APP_BASE_URL || "https://api.internal.company.com/v2";

// 模板字面量路径
fetch(` + "`" + `${baseURL}/api/v1/users` + "`" + `);
const ep = ` + "`" + `${config.host}/graphql` + "`" + `;
`
	jf := JSFile{URL: "http://test.local/app.js", PageURL: "http://test.local/", Content: content}
	findings := Extract(jf, "task-patterns")

	labels := make(map[string]bool)
	for _, f := range findings {
		labels[f.Label] = true
		t.Logf("[%s] %s = %s", f.Category, f.Label, f.Value[:min2(len(f.Value), 60)])
	}
	if !labels["process.env 降级密钥"] {
		t.Error("应命中 process.env 降级密钥规则")
	}
	if !labels["process.env URL"] {
		t.Error("应命中 process.env URL 规则")
	}
	if !labels["模板字面量路径"] {
		t.Error("应命中模板字面量路径规则")
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestExtract_CommentFilter 验证注释误报过滤逻辑正常工作。
func TestExtract_CommentFilter(t *testing.T) {
	// 这些是测试中出现的典型误报
	codeFragments := []string{
		"key,\n",
		"element.key;\n",
		"names[i++]))",
		"step.value;\n",
		"require('./_toKey');\n",
		"this.nextJSXToken();\r\n\t",
		"false;\n",
		"(function()",
	}
	for _, v := range codeFragments {
		if !isCodeFragment(v) {
			t.Errorf("应识别为代码片段: %q", v)
		}
	}

	// 真实密钥不应被过滤
	realSecrets := []string{
		"sk_live_ABCDEFGHIJKLMNabcdefghij",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234",
		"AIzaSyDXABCDEFGHIJKLMNOPQRSTUVWXYZabc",
	}
	for _, v := range realSecrets {
		if isCodeFragment(v) {
			t.Errorf("真实密钥不应被标记为代码片段: %q", v)
		}
	}
	t.Log("注释过滤测试通过")
}

// TestSourceMap_NodeModulesFilter 验证 node_modules 源码被跳过。
func TestSourceMap_NodeModulesFilter(t *testing.T) {
	mapContent := `{
  "version": 3,
  "sources": [
    "node_modules/lodash/chunk.js",
    "node_modules/react/index.js",
    "src/api/client.ts",
    "~/memoize/plain.js"
  ],
  "sourcesContent": [
    "lodash chunk source...",
    "react index source...",
    "export const KEY = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';",
    "memoize source..."
  ],
  "mappings": "AAAA"
}`
	jf := JSFile{URL: "http://t.local/app.js.map", PageURL: "http://t.local/", Content: mapContent, IsMap: true}
	extras := ParseSourceMapContent(jf)

	if len(extras) != 1 {
		t.Fatalf("应只保留 1 个非 node_modules 文件，实际 %d 个", len(extras))
	}
	if !strings.Contains(extras[0].URL, "src/api/client.ts") {
		t.Errorf("应保留 src/api/client.ts，实际 URL: %s", extras[0].URL)
	}
	t.Log("node_modules 过滤测试通过")
}

// TestExtract_GitLabLinearSentry 验证 GitLab PAT、Linear API Key、Sentry DSN 规则命中。
func TestExtract_GitLabLinearSentry(t *testing.T) {
	content := strings.Join([]string{
		// GitLab PAT (20 chars after "glpat-")
		`var GL_TOKEN = "glpat-ABCDEFGHIJKLMNOPQRst";`,
		// GitLab Runner Registration Token
		`var GL_RUNNER = "glrt-ABCDEFGHIJKLMNOPQRst";`,
		// Linear API Key (40 chars after "lin_api_")
		`const LINEAR_KEY = "lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";`,
		// Sentry DSN
		`Sentry.init({dsn:"https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/9876543"});`,
	}, "\n")

	jf := JSFile{URL: "http://test.local/app.js", PageURL: "http://test.local/", Content: content}
	findings := Extract(jf, "task-gitlab")

	labels := make(map[string]bool)
	for _, f := range findings {
		labels[f.Label] = true
		t.Logf("[%s] %s = %s", f.Severity, f.Label, f.Value)
	}
	for _, want := range []string{"GitLab PAT", "GitLab Runner Registration Token", "Linear API Key", "Sentry DSN"} {
		if !labels[want] {
			t.Errorf("未命中规则: %s", want)
		}
	}
}

// TestExtract_TelegramTightened 验证 Telegram 规则收紧后：真实 token 仍命中，无 AA 前缀不命中。
func TestExtract_TelegramTightened(t *testing.T) {
	// 真实 Telegram Bot Token 格式（冒号后以 AA 开头）
	real := `var BOT = "1234567890:AAF3xyzABCDEFGHIJKLMNOPQRSTUVWXYZ12";`
	jf := JSFile{URL: "http://t.local/a.js", PageURL: "http://t.local/", Content: real}
	findings := Extract(jf, "task-tg-real")
	found := false
	for _, f := range findings {
		if f.Label == "Telegram Bot Token" {
			found = true
		}
	}
	if !found {
		t.Error("真实 Telegram token 应被命中")
	}

	// 无 AA 前缀的伪 token 不应命中
	fake := `var X = "1234567890:XYZabcdefghijklmnopqrstuvwxyz123456";`
	jf2 := JSFile{URL: "http://t.local/b.js", PageURL: "http://t.local/", Content: fake}
	findings2 := Extract(jf2, "task-tg-fake")
	for _, f := range findings2 {
		if f.Label == "Telegram Bot Token" {
			t.Errorf("无 AA 前缀不应命中 Telegram 规则，实际命中 value=%s", f.Value)
		}
	}
	t.Log("Telegram 收紧测试通过")
}

// TestExtract_MailgunFix 验证 Mailgun 规则修复：纯十六进制命中，含大写字母不命中。
func TestExtract_MailgunFix(t *testing.T) {
	// 正确 Mailgun key（32 位小写十六进制）
	validKey := `var MG = "key-abcdef0123456789abcdef0123456789";`
	jf := JSFile{URL: "http://t.local/a.js", PageURL: "http://t.local/", Content: validKey}
	findings := Extract(jf, "task-mg-valid")
	found := false
	for _, f := range findings {
		if f.Label == "Mailgun API Key" {
			found = true
		}
	}
	if !found {
		t.Error("合法 Mailgun key（纯十六进制）应被命中")
	}

	// 含大写字母（非 Mailgun 格式）不应命中
	invalidKey := `var MG2 = "key-ABCDEF0123456789abcdef0123456789";`
	jf2 := JSFile{URL: "http://t.local/b.js", PageURL: "http://t.local/", Content: invalidKey}
	findings2 := Extract(jf2, "task-mg-invalid")
	for _, f := range findings2 {
		if f.Label == "Mailgun API Key" {
			t.Errorf("含大写字母不应命中 Mailgun 规则，实际命中 value=%s", f.Value)
		}
	}
	t.Log("Mailgun 修复测试通过")
}

// TestExtract_Dedup 验证同文件内 category+value 去重正常工作。
func TestExtract_Dedup(t *testing.T) {
	// 同一密钥出现两次，应只产生一条 finding
	content := `
var KEY1 = "AKIAIOSFODNN7EXAMPL1";
console.log("AKIAIOSFODNN7EXAMPL1");
`
	jf := JSFile{URL: "http://test.local/dup.js", PageURL: "http://test.local/", Content: content}
	findings := Extract(jf, "task-dedup")

	count := 0
	for _, f := range findings {
		if f.Value == "AKIAIOSFODNN7EXAMPL1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("相同 value 应去重为 1 条，实际 %d 条", count)
	}
}
