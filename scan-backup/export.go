package backup

// export.go —— 命中结果导出:JSON / CSV / 独立 HTML 报告。
// 三种格式都只用已采集的脱敏 Hit 字段,不含任何文件体内容。

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
)

// exportJSON 导出为带缩进的 JSON(含一点扫描上下文)。
func exportJSON(hits []Hit, target, endedAt string) []byte {
	doc := persistedDoc{Hits: hits, Target: target, EndedAt: endedAt, SavedAt: nowStamp()}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return buf
}

// exportCSV 导出为 CSV(Excel 友好,UTF-8 BOM 头防中文乱码)。
func exportCSV(hits []Hit) []byte {
	var b bytes.Buffer
	b.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"id", "url", "file", "kind", "severity", "size", "code", "host", "rule", "at", "note"})
	for _, h := range hits {
		_ = w.Write([]string{
			h.ID, h.URL, h.File, h.Kind, h.Severity, h.Size,
			strconv.Itoa(h.Code), h.Host, h.Rule, h.At, h.Note,
		})
	}
	w.Flush()
	return b.Bytes()
}

// exportHTML 生成自包含的 HTML 报告(内联样式,可直接发给同事/留档)。
func exportHTML(hits []Hit, target, endedAt string) []byte {
	sev := map[string]int{"高危": 0, "中危": 0, "低危": 0}
	for _, h := range hits {
		if h.Code < 300 {
			sev[h.Severity]++
		}
	}
	var rows strings.Builder
	for _, h := range hits {
		rows.WriteString("<tr class=\"sev-" + sevClass(h.Severity) + "\">")
		rows.WriteString("<td class=\"mono\"><a href=\"" + esc(h.URL) + "\" rel=\"noreferrer noopener\" target=\"_blank\">" + esc(h.URL) + "</a></td>")
		rows.WriteString(td(h.File) + td(h.Kind) + tdBadge(h.Severity) + td(h.Size) + td(strconv.Itoa(h.Code)) + td(h.Host) + td(h.Note))
		rows.WriteString("</tr>\n")
	}
	tpl := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>RedOps 备份/敏感文件泄露报告</title>
<style>
:root{color-scheme:dark}
body{font-family:-apple-system,Segoe UI,Roboto,"Microsoft YaHei",sans-serif;background:#0b0e14;color:#c7d0dc;margin:0;padding:32px;}
h1{font-size:20px;margin:0 0 4px}.sub{color:#6b7689;font-size:13px;margin:0 0 20px}
.cards{display:flex;gap:14px;margin:0 0 22px;flex-wrap:wrap}
.card{background:#11161f;border:1px solid #1d2533;border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{font-size:12px;color:#6b7689}
.card.red .n{color:#f43f5e}.card.amber .n{color:#f59e0b}.card.cyan .n{color:#22d3ee}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1a2230;vertical-align:top}
th{color:#8a97a8;font-weight:600;font-size:12px;position:sticky;top:0;background:#0b0e14}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.mono a{color:#7dd3fc;text-decoration:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600}
.b-高危{background:rgba(244,63,94,.15);color:#fb7185}.b-中危{background:rgba(245,158,11,.15);color:#fbbf24}.b-低危{background:rgba(148,163,184,.15);color:#cbd5e1}
tr.sev-high td{background:rgba(244,63,94,.04)}
.foot{margin-top:20px;color:#4b5563;font-size:11px;line-height:1.7}
</style></head><body>
<h1>备份 / 敏感文件泄露报告</h1>
<p class="sub">目标: %s · 扫描完成于 %s · 生成于 %s · 仅 HEAD/Range(≤16B)探测,未下载文件体</p>
<div class="cards">
<div class="card red"><div class="n">%d</div><div class="l">高危(可访问)</div></div>
<div class="card amber"><div class="n">%d</div><div class="l">中危(可访问)</div></div>
<div class="card cyan"><div class="n">%d</div><div class="l">命中总数</div></div>
</div>
<table><thead><tr><th>命中 URL</th><th>文件</th><th>类型</th><th>等级</th><th>大小</th><th>状态码</th><th>主机</th><th>研判</th></tr></thead>
<tbody>
%s
</tbody></table>
<p class="foot">本报告由 RedOps「备份文件」模块生成。所有命中均仅经 HEAD / Range(≤16 字节)存在性探测确认,未下载任何文件体、未尝试鉴权或路径绕过。请仅用于已授权的安全评估。</p>
</body></html>`
	body := fmt.Sprintf(tpl, esc(target), esc(endedAt), nowStamp(), sev["高危"], sev["中危"], len(hits), rows.String())
	return []byte(body)
}

func sevClass(sev string) string {
	if sev == "高危" {
		return "high"
	}
	return "norm"
}

func esc(s string) string { return html.EscapeString(s) }
func td(s string) string  { return "<td>" + esc(s) + "</td>" }
func tdBadge(sev string) string {
	if sev == "" {
		sev = "—"
	}
	return "<td><span class=\"badge b-" + esc(sev) + "\">" + esc(sev) + "</span></td>"
}
