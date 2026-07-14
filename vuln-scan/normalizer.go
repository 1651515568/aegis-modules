package vulnscan

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// httpsPortSet 自动推断为 HTTPS 的端口
var httpsPortSet = map[string]bool{
	"443": true, "4443": true, "8443": true, "9443": true, "10443": true,
}

// cidrRe 匹配 IPv4 CIDR
var cidrRe = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$`)

// separatorRe 行内多分隔符（逗号/分号/制表符/空格）
var separatorRe = regexp.MustCompile(`[,;\t ]+`)

// NormStats 规范化统计摘要
type NormStats struct {
	InputTokens int `json:"inputTokens"` // 拆分后 token 总数
	Output      int `json:"output"`      // 规范化后有效目标数
	Deduped     int `json:"deduped"`     // 去重删除数
	Skipped     int `json:"skipped"`     // 无法识别跳过数
	ProtoAdded  int `json:"protoAdded"`  // 自动补全协议数
}

// NormalizeTargets 接受任意混合格式的原始目标字符串，返回去重后的规范化列表及统计。
// 支持：IP、IP:port、CIDR、域名、域名:port、完整 URL；
// 分隔符：换行/逗号/分号/制表符/空格，可混用；
// 自动推断 HTTP/HTTPS 协议，去重（大小写不敏感）。
func NormalizeTargets(raw string) ([]string, NormStats) {
	tokens := splitTokens(raw)
	var stats NormStats
	stats.InputTokens = len(tokens)

	seen := make(map[string]bool)
	var results []string

	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.HasPrefix(tok, "#") {
			continue
		}
		normalized, added := normalizeOne(tok)
		if normalized == "" {
			stats.Skipped++
			continue
		}
		key := strings.ToLower(normalized)
		if seen[key] {
			stats.Deduped++
			continue
		}
		seen[key] = true
		results = append(results, normalized)
		if added {
			stats.ProtoAdded++
		}
	}

	sort.Strings(results)
	stats.Output = len(results)
	return results, stats
}

// splitTokens 将原始文本按所有常见分隔符拆分为 token 列表（忽略注释行）
func splitTokens(s string) []string {
	var tokens []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, p := range separatorRe.Split(line, -1) {
			p = strings.TrimSpace(p)
			if p != "" {
				tokens = append(tokens, p)
			}
		}
	}
	return tokens
}

// normalizeOne 规范化单个目标，返回规范化结果（空串=无效）及是否补全了协议
func normalizeOne(s string) (result string, protoAdded bool) {
	// ① 已有 http/https 协议 → 验证合法性后原样返回
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", false
		}
		return s, false
	}

	// ② 其他已知协议（ftp/ssh/tcp 等）→ 跳过
	if idx := strings.Index(s, "://"); idx > 0 && idx < 10 {
		return "", false
	}

	// ③ IPv4 CIDR → nuclei 原生支持，不加协议
	if cidrRe.MatchString(s) {
		if _, _, err := net.ParseCIDR(s); err == nil {
			return s, false
		}
	}

	// ④ IPv6（带方括号格式：[::1] 或 [::1]:8080）→ 补协议
	if strings.HasPrefix(s, "[") {
		scheme := "http://"
		if idx := strings.LastIndex(s, "]:"); idx >= 0 {
			if httpsPortSet[s[idx+2:]] {
				scheme = "https://"
			}
		}
		return scheme + s, true
	}

	// ⑤ host:port 格式（IP:port 或 domain:port）→ 根据端口推断协议
	if host, port, err := net.SplitHostPort(s); err == nil {
		scheme := "http://"
		if httpsPortSet[port] {
			scheme = "https://"
		}
		return scheme + host + ":" + port, true
	}

	// ⑥ 纯 IPv4（无端口）→ http://
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return "http://" + s, true
	}

	// ⑦ 域名/主机名（含路径）→ http://
	if strings.Contains(s, ".") || strings.EqualFold(s, "localhost") {
		return "http://" + s, true
	}

	// ⑧ 无法识别 → 跳过
	return "", false
}
