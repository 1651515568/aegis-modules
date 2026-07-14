package backup

// jsmine.go —— 静态 JS 挖掘(无头浏览器的轻量替代)。
//
// SPA 站点首页是空壳,链接由 JS 渲染,静态提链拿不到。但真实路径/文件名往往以**字符串
// 字面量**藏在 JS bundle 里,源码结构则藏在 source map 的 sources 里。这里不渲染、只静态
// 挖掘,以纯 Go、无浏览器依赖拿到大部分价值:
//   * JS bundle:正则提路径形字符串("/api/x"、"config/db.js"…);
//   * source map(.js.map):提 sources 原始源码路径(webpack://src/config/db.js …);
//   * asset-manifest.json / 构建清单:同样用路径形字符串提取。
// 产出统一喂回 discovery(派生备份变体、直探、喂递归)。

import (
	"path"
	"regexp"
	"strings"
)

const maxJSBytes = 2 << 20 // JS/map/manifest 单文件读取上限(bundle 可较大)

var (
	// JS 里被引号(单/双/反引号)包裹的疑似路径字符串。
	jsStrRe = regexp.MustCompile("[\"'`]([^\"'`\\s]{2,256})[\"'`]")
	// source map 的 "sources":[ ... ] 段。
	smSourcesRe = regexp.MustCompile(`"sources"\s*:\s*\[([^\]]*)\]`)
	smItemRe    = regexp.MustCompile(`"([^"]+)"`)
)

// mineJS 从 JS/JSON 正文提取疑似站内路径字符串(原样返回,后续由 resolveSameHost 归一化)。
func mineJS(body []byte) []string {
	var out []string
	for _, m := range jsStrRe.FindAllSubmatch(body, -1) {
		s := string(m[1])
		if looksLikePath(s) {
			out = append(out, s)
		}
	}
	return out
}

// looksLikePath 过滤出像「站内相对/根相对路径」的字符串,排除整段 URL、协议相对、含非法字符者。
func looksLikePath(s string) bool {
	if strings.ContainsAny(s, " <>{}()\\|^`") {
		return false
	}
	if strings.HasPrefix(s, "//") || strings.Contains(s, "://") {
		return false // 协议相对 / 绝对 URL(跨域,且多为第三方)
	}
	if strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "#") {
		return false
	}
	if strings.HasPrefix(s, "/") && len(s) > 1 {
		return true // 根相对路径
	}
	// 相对路径:需含「/」且文件名带扩展名,降低噪声(如 mime 类型、纯单词)。
	if strings.Contains(s, "/") && strings.Contains(path.Base(s), ".") {
		return true
	}
	return false
}

// mineSourceMap 从 .js.map 的 sources 提取原始源码文件路径(剥离 webpack:// 等前缀、跳过 node_modules)。
func mineSourceMap(body []byte) []string {
	m := smSourcesRe.FindSubmatch(body)
	if m == nil {
		return nil
	}
	var out []string
	for _, it := range smItemRe.FindAllSubmatch(m[1], -1) {
		src := string(it[1])
		if strings.Contains(src, "node_modules") || strings.Contains(src, "/~/") {
			continue // 依赖噪声跳过
		}
		// webpack://<namespace>/./<realpath> → realpath(真实源码路径在 "/./" 之后)。
		if i := strings.Index(src, "/./"); i >= 0 {
			src = src[i+3:]
		}
		// 去 scheme(webpack:// / vite:// 等)。
		if i := strings.Index(src, "://"); i >= 0 {
			src = src[i+3:]
		}
		// 去前导 ./ ../ /,去查询/锚。
		src = strings.TrimLeft(src, "./")
		if i := strings.IndexAny(src, "?#"); i >= 0 {
			src = src[:i]
		}
		if src = strings.TrimSpace(src); src != "" {
			out = append(out, src)
		}
	}
	return out
}

// isJSAsset / isSourceMap / isManifest 用于在爬取分发时识别可挖掘的资源。
func isJSAsset(rel, ctype string) bool {
	ext := strings.ToLower(path.Ext(rel))
	return ext == ".js" || ext == ".mjs" || strings.Contains(strings.ToLower(ctype), "javascript")
}

func isSourceMap(rel string) bool {
	return strings.HasSuffix(strings.ToLower(rel), ".map")
}

func isManifestJSON(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	return b == "asset-manifest.json" || b == "manifest.json" || strings.HasPrefix(b, "precache-manifest")
}
