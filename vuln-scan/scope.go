package vulnscan

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	scopeFile      = "data/vuln-scan-scope.json"
	exclusionsFile = "data/vuln-scan-exclusions.json"
)

// ScopeConfig 定义授权扫描范围。
type ScopeConfig struct {
	CIDRs   []string `json:"cidrs"`   // 授权 IP 段，如 "10.0.0.0/8"
	Domains []string `json:"domains"` // 授权域名后缀，如 "example.com"（匹配 *.example.com）
	// Mode: "disabled"=不检查 | "warn"=超范围也允许但统计 | "enforce"=阻断超范围目标
	Mode string `json:"mode"`
}

// Exclusion 永久排除项（绝不扫描）。
type Exclusion struct {
	ID        string    `json:"id"`
	Pattern   string    `json:"pattern"` // IP、CIDR、域名后缀
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// ScopeFilterResult 目标过滤结果摘要。
type ScopeFilterResult struct {
	Allowed    []string `json:"allowed"`
	Excluded   int      `json:"excluded"`  // 被排除列表拦截的数量
	OutOfScope int      `json:"outOfScope"` // 超范围数量（enforce 模式下被阻断）
	Warned     int      `json:"warned"`     // 超范围但被放行（warn 模式）
}

// FilterTargets 对规范化后的目标列表同时应用排除列表和 scope 检查。
func (s *store) FilterTargets(targets []string) ScopeFilterResult {
	s.mu.RLock()
	sc := s.scope
	excls := make([]*Exclusion, len(s.exclusions))
	copy(excls, s.exclusions)
	s.mu.RUnlock()

	var res ScopeFilterResult
	scopeEnabled := sc.Mode != "disabled" && (len(sc.CIDRs) > 0 || len(sc.Domains) > 0)

	for _, t := range targets {
		host := extractScopeHost(t)

		// 1. 排除列表优先
		if isExcludedHost(host, excls) {
			res.Excluded++
			continue
		}

		// 2. Scope 检查
		if scopeEnabled {
			inScope := isInScopeHost(host, sc.CIDRs, sc.Domains)
			if !inScope {
				if sc.Mode == "enforce" {
					res.OutOfScope++
					continue // 阻断
				}
				// warn 模式：允许但计数
				res.Warned++
			}
		}

		res.Allowed = append(res.Allowed, t)
	}
	return res
}

// extractScopeHost 从目标 URL/IP/域名中提取主机部分。
func extractScopeHost(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err == nil && u.Host != "" {
			host, _, _ := net.SplitHostPort(u.Host)
			if host == "" {
				host = u.Host
			}
			return host
		}
	}
	if cidrRe.MatchString(target) {
		return target
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

// isExcludedHost 判断主机是否命中任意排除规则。
func isExcludedHost(host string, excls []*Exclusion) bool {
	for _, ex := range excls {
		if matchScopePattern(host, ex.Pattern) {
			return true
		}
	}
	return false
}

// isInScopeHost 判断主机是否在授权范围内。
// host 可能是裸 IP、CIDR 格式目标（如 10.0.0.1/24）或域名。
func isInScopeHost(host string, cidrs, domains []string) bool {
	hostIP := net.ParseIP(host)
	// 若 host 是 CIDR 格式目标（如 10.0.0.0/24），取其基础 IP 做范围判断
	if hostIP == nil && strings.Contains(host, "/") {
		if baseIP, _, err := net.ParseCIDR(host); err == nil {
			hostIP = baseIP
		}
	}
	for _, cidrStr := range cidrs {
		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if hostIP != nil && network.Contains(hostIP) {
			return true
		}
	}
	h := strings.ToLower(host)
	for _, domain := range domains {
		d := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://"))
		d = strings.TrimPrefix(d, "*.")
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// matchScopePattern 判断主机是否命中 pattern（IP/CIDR/域名后缀）。
func matchScopePattern(host, pattern string) bool {
	if strings.Contains(pattern, "/") {
		ip := net.ParseIP(host)
		_, network, err := net.ParseCIDR(pattern)
		if err == nil && ip != nil && network.Contains(ip) {
			return true
		}
	}
	if net.ParseIP(pattern) != nil {
		return strings.EqualFold(host, pattern)
	}
	h := strings.ToLower(host)
	p := strings.ToLower(strings.TrimPrefix(pattern, "*."))
	return h == p || strings.HasSuffix(h, "."+p)
}

// ── Store scope/exclusion 方法 ────────────────────────────────────────────────

func (s *store) getScope() ScopeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scope
}

func (s *store) setScope(sc ScopeConfig) {
	s.mu.Lock()
	s.scope = sc
	s.mu.Unlock()
	s.saveScope()
}

func (s *store) listExclusions() []*Exclusion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Exclusion, len(s.exclusions))
	copy(out, s.exclusions)
	return out
}

func (s *store) addExclusion(pattern, note string) *Exclusion {
	ex := &Exclusion{
		ID:        newTaskID(),
		Pattern:   strings.TrimSpace(pattern),
		Note:      strings.TrimSpace(note),
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.exclusions = append(s.exclusions, ex)
	s.mu.Unlock()
	s.saveExclusions()
	return ex
}

func (s *store) deleteExclusion(id string) bool {
	s.mu.Lock()
	found := false
	n := s.exclusions[:0]
	for _, ex := range s.exclusions {
		if ex.ID == id {
			found = true
		} else {
			n = append(n, ex)
		}
	}
	if found {
		s.exclusions = n
	}
	s.mu.Unlock()
	if found {
		s.saveExclusions()
	}
	return found
}

// ── Scope/Exclusion 持久化 ────────────────────────────────────────────────────

func (s *store) saveScope() {
	s.mu.RLock()
	sc := s.scope
	s.mu.RUnlock()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	atomicWrite(scopeFile, sc)
}

func (s *store) loadScope() {
	data, err := os.ReadFile(scopeFile)
	if err != nil {
		return
	}
	var sc ScopeConfig
	if json.Unmarshal(data, &sc) == nil {
		if sc.CIDRs == nil {
			sc.CIDRs = []string{}
		}
		if sc.Domains == nil {
			sc.Domains = []string{}
		}
		if sc.Mode == "" {
			sc.Mode = "disabled"
		}
		s.mu.Lock()
		s.scope = sc
		s.mu.Unlock()
	}
}

func (s *store) saveExclusions() {
	s.mu.RLock()
	excls := make([]*Exclusion, len(s.exclusions))
	copy(excls, s.exclusions)
	s.mu.RUnlock()
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	atomicWrite(exclusionsFile, excls)
}

func (s *store) loadExclusions() {
	data, err := os.ReadFile(exclusionsFile)
	if err != nil {
		return
	}
	var excls []*Exclusion
	if json.Unmarshal(data, &excls) == nil {
		s.mu.Lock()
		s.exclusions = excls
		s.mu.Unlock()
	}
}
