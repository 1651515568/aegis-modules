package jsextract

// sourcemap.go — Source Map JSON 解析，还原 sourcesContent 为独立 JSFile。
//
// 现代前端项目打包时生成的 .map 文件包含 sourcesContent 字段，
// 其中是混淆前的原始 TypeScript/JavaScript 源码。
// 对原始源码运行提取规则，比对混淆后的 bundle 准确得多。

import (
	"encoding/json"
	"fmt"
	"strings"
)

type sourceMapJSON struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// maxSourcesPerMap 单个 Source Map 文件最多还原多少个源文件。
// 防止超大第三方库（如 swagger-ui 511 个 sourcesContent）产生大量低价值分析任务。
const maxSourcesPerMap = 100

// ParseSourceMapContent 解析 Source Map JSON，将 sourcesContent 还原为独立 JSFile。
// 每个 sourcesContent 条目对应一个原始源文件，使用合成 URL 标记（不可远程抓取）。
//
// 过滤策略：
//   - 跳过来自 node_modules 的第三方依赖源码（已知无害，噪声极高）
//   - 最多处理 maxSourcesPerMap 条
//
// 若解析失败或无 sourcesContent，返回 nil。
func ParseSourceMapContent(jf JSFile) []JSFile {
	if !jf.IsMap || len(jf.Content) < 10 {
		return nil
	}
	trimmed := strings.TrimSpace(jf.Content)
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	var sm sourceMapJSON
	if err := json.Unmarshal([]byte(jf.Content), &sm); err != nil {
		return nil
	}
	if len(sm.SourcesContent) == 0 {
		return nil
	}
	extras := make([]JSFile, 0, min(len(sm.SourcesContent), maxSourcesPerMap))
	for i, src := range sm.SourcesContent {
		if len(extras) >= maxSourcesPerMap {
			break
		}
		// 跳过第三方依赖（node_modules、~/ 是 webpack alias for node_modules）
		srcName := ""
		if i < len(sm.Sources) {
			srcName = sm.Sources[i]
		}
		if strings.Contains(srcName, "node_modules") || strings.HasPrefix(srcName, "~/") {
			continue
		}
		src = strings.TrimSpace(src)
		if len(src) < 20 {
			continue
		}
		extras = append(extras, JSFile{
			URL:     fmt.Sprintf("%s#source[%d]:%s", jf.URL, i, srcName),
			PageURL: jf.PageURL,
			Content: src,
			IsMap:   false,
		})
	}
	return extras
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
