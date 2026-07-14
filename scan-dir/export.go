package scandir

// export.go —— 扫描结果导出:JSON / CSV / 独立 HTML 报告。
// 三种格式都只用已采集的命中字段(url/path/status/length/words/lines/redirect/contentType)。

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
)

// exportDoc 是 JSON 导出的外形(含一点扫描上下文)。
type exportDoc struct {
	Target  string `json:"target"`
	EndedAt string `json:"endedAt"`
	SavedAt string `json:"savedAt"`
	Count   int    `json:"count"`
	Hits    []Hit  `json:"hits"`
}

// export 导出当前扫描的命中。?format=json|csv|html(默认 json),以附件形式下载。
func (m *Module) export(w http.ResponseWriter, r *http.Request) {
	hits := m.store.list()
	st := m.store.status()
	var body []byte
	var ctype, fname string
	switch r.URL.Query().Get("format") {
	case "csv":
		body, ctype, fname = exportHitsCSV(hits), "text/csv; charset=utf-8", "dirscan-hits.csv"
	case "html":
		body, ctype, fname = exportHitsHTML(hits, st.Target, st.EndedAt), "text/html; charset=utf-8", "dirscan-report.html"
	default:
		body, ctype, fname = exportHitsJSON(hits, st.Target, st.EndedAt), "application/json; charset=utf-8", "dirscan-hits.json"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func exportHitsJSON(hits []Hit, target, endedAt string) []byte {
	doc := exportDoc{Target: target, EndedAt: endedAt, SavedAt: nowStamp(), Count: len(hits), Hits: hits}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return buf
}

func exportHitsCSV(hits []Hit) []byte {
	var b bytes.Buffer
	b.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"url", "path", "status", "length", "words", "lines", "redirect", "contentType", "depth"})
	for _, h := range hits {
		_ = w.Write([]string{
			h.URL, h.Path, strconv.Itoa(h.Status), strconv.FormatInt(h.Length, 10),
			strconv.Itoa(h.Words), strconv.Itoa(h.Lines), h.Redirect, h.ContentType, strconv.Itoa(h.Depth),
		})
	}
	w.Flush()
	return b.Bytes()
}

// exportHitsHTML 生成自包含的 HTML 报告(内联样式,可直接发给同事/留档)。
func exportHitsHTML(hits []Hit, target, endedAt string) []byte {
	codes := map[int]int{}
	for _, h := range hits {
		codes[h.Status]++
	}
	var rows strings.Builder
	for _, h := range hits {
		rows.WriteString("<tr>")
		rows.WriteString("<td class=\"mono code c" + statusClass(h.Status) + "\">" + esc(strconv.Itoa(h.Status)) + "</td>")
		rows.WriteString("<td class=\"mono\"><a href=\"" + esc(h.URL) + "\" target=\"_blank\" rel=\"noreferrer\">" + esc(h.Path) + "</a></td>")
		rows.WriteString("<td class=\"mono num\">" + esc(strconv.FormatInt(h.Length, 10)) + "</td>")
		rows.WriteString("<td class=\"mono num\">" + esc(strconv.Itoa(h.Words)) + "</td>")
		rows.WriteString("<td class=\"mono num\">" + esc(strconv.Itoa(h.Lines)) + "</td>")
		rows.WriteString("<td class=\"mono\">" + esc(h.Redirect) + "</td>")
		rows.WriteString("</tr>\n")
	}
	tpl := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>AEGIS 目录扫描报告</title>
<style>
:root{color-scheme:dark}
body{font-family:-apple-system,Segoe UI,Roboto,"Microsoft YaHei",sans-serif;background:#0b0e14;color:#c7d0dc;margin:0;padding:32px;}
h1{font-size:20px;margin:0 0 4px}.sub{color:#6b7689;font-size:13px;margin:0 0 20px}
.cards{display:flex;gap:14px;margin:0 0 22px;flex-wrap:wrap}
.card{background:#11161f;border:1px solid #1d2533;border-radius:10px;padding:14px 18px;min-width:110px}
.card .n{font-size:26px;font-weight:700}.card .l{font-size:12px;color:#6b7689}
.card.cyan .n{color:#22d3ee}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1a2230;vertical-align:top}
th{color:#8a97a8;font-weight:600;font-size:12px;position:sticky;top:0;background:#0b0e14}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.num{text-align:right;color:#8a97a8}
a{color:#7dd3fc;text-decoration:none}a:hover{text-decoration:underline}
.code{font-weight:700}.c2{color:#34d399}.c3{color:#22d3ee}.c4{color:#f59e0b}.c5{color:#f87171}.c0{color:#9ca3af}
.foot{margin-top:20px;color:#4b5563;font-size:11px;line-height:1.7}
</style></head><body>
<h1>目录扫描报告</h1>
<p class="sub">目标: %s · 扫描完成于 %s · 生成于 %s</p>
<div class="cards">
<div class="card cyan"><div class="n">%d</div><div class="l">命中路径</div></div>
<div class="card"><div class="n">%s</div><div class="l">状态码分布</div></div>
</div>
<table><thead><tr><th>状态</th><th>路径</th><th>长度</th><th>词</th><th>行</th><th>跳转</th></tr></thead>
<tbody>
%s
</tbody></table>
<p class="foot">本报告由 AEGIS「目录扫描」能力生成。请仅用于已授权的安全评估。</p>
</body></html>`
	body := fmt.Sprintf(tpl, esc(target), esc(endedAt), nowStamp(), len(hits), esc(codeDist(codes)), rows.String())
	return []byte(body)
}

// codeDist 把状态码计数压成 "200×12  301×3  403×1" 形式。
func codeDist(codes map[int]int) string {
	if len(codes) == 0 {
		return "—"
	}
	// 固定顺序:小码在前。
	order := []int{200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500, 503}
	var parts []string
	used := map[int]bool{}
	for _, c := range order {
		if n, ok := codes[c]; ok {
			parts = append(parts, strconv.Itoa(c)+"×"+strconv.Itoa(n))
			used[c] = true
		}
	}
	for c, n := range codes {
		if !used[c] {
			parts = append(parts, strconv.Itoa(c)+"×"+strconv.Itoa(n))
		}
	}
	return strings.Join(parts, "  ")
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2"
	case code >= 300 && code < 400:
		return "3"
	case code >= 400 && code < 500:
		return "4"
	case code >= 500:
		return "5"
	default:
		return "0"
	}
}

func esc(s string) string { return html.EscapeString(s) }
