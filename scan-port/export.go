package portscan

// export.go —— 扫描结果导出:JSON / CSV / 独立 HTML 报告。
// 三种格式都只用已采集的开放端口字段(host/port/proto/service/banner)。

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
	Ports   []Port `json:"ports"`
}

// export 导出当前扫描的开放端口。?format=json|csv|html(默认 json),以附件形式下载。
func (m *Module) export(w http.ResponseWriter, r *http.Request) {
	ports := m.store.list()
	st := m.store.status()
	var body []byte
	var ctype, fname string
	switch r.URL.Query().Get("format") {
	case "csv":
		body, ctype, fname = exportPortsCSV(ports), "text/csv; charset=utf-8", "portscan-ports.csv"
	case "html":
		body, ctype, fname = exportPortsHTML(ports, st.Target, st.EndedAt), "text/html; charset=utf-8", "portscan-report.html"
	default:
		body, ctype, fname = exportPortsJSON(ports, st.Target, st.EndedAt), "application/json; charset=utf-8", "portscan-ports.json"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// exportPortsJSON 导出为带缩进的 JSON。
func exportPortsJSON(ports []Port, target, endedAt string) []byte {
	doc := exportDoc{Target: target, EndedAt: endedAt, SavedAt: nowStamp(), Count: len(ports), Ports: ports}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return buf
}

// exportPortsCSV 导出为 CSV(Excel 友好,UTF-8 BOM 头防中文乱码)。
func exportPortsCSV(ports []Port) []byte {
	var b bytes.Buffer
	b.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"host", "port", "proto", "service", "banner"})
	for _, p := range ports {
		_ = w.Write([]string{p.Host, strconv.Itoa(p.Port), p.Proto, p.Service, p.Banner})
	}
	w.Flush()
	return b.Bytes()
}

// exportPortsHTML 生成自包含的 HTML 报告(内联样式,可直接发给同事/留档)。
func exportPortsHTML(ports []Port, target, endedAt string) []byte {
	hosts := map[string]bool{}
	tcp, udp := 0, 0
	for _, p := range ports {
		hosts[p.Host] = true
		switch p.Proto {
		case "udp":
			udp++
		default:
			tcp++
		}
	}
	var rows strings.Builder
	for _, p := range ports {
		rows.WriteString("<tr>")
		rows.WriteString(td(p.Host))
		rows.WriteString("<td class=\"mono port\">" + esc(strconv.Itoa(p.Port)) + "</td>")
		rows.WriteString(tdBadge(p.Proto) + td(p.Service))
		rows.WriteString("<td class=\"mono\">" + esc(p.Banner) + "</td>")
		rows.WriteString("</tr>\n")
	}
	tpl := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>AEGIS 端口扫描报告</title>
<style>
:root{color-scheme:dark}
body{font-family:-apple-system,Segoe UI,Roboto,"Microsoft YaHei",sans-serif;background:#0b0e14;color:#c7d0dc;margin:0;padding:32px;}
h1{font-size:20px;margin:0 0 4px}.sub{color:#6b7689;font-size:13px;margin:0 0 20px}
.cards{display:flex;gap:14px;margin:0 0 22px;flex-wrap:wrap}
.card{background:#11161f;border:1px solid #1d2533;border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{font-size:12px;color:#6b7689}
.card.cyan .n{color:#22d3ee}.card.amber .n{color:#f59e0b}.card.green .n{color:#34d399}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1a2230;vertical-align:top}
th{color:#8a97a8;font-weight:600;font-size:12px;position:sticky;top:0;background:#0b0e14}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.port{color:#22d3ee}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;background:rgba(148,163,184,.15);color:#cbd5e1}
.foot{margin-top:20px;color:#4b5563;font-size:11px;line-height:1.7}
</style></head><body>
<h1>端口扫描报告</h1>
<p class="sub">目标: %s · 扫描完成于 %s · 生成于 %s</p>
<div class="cards">
<div class="card cyan"><div class="n">%d</div><div class="l">开放端口</div></div>
<div class="card green"><div class="n">%d</div><div class="l">涉及主机</div></div>
<div class="card amber"><div class="n">%d / %d</div><div class="l">TCP / UDP</div></div>
</div>
<table><thead><tr><th>主机</th><th>端口</th><th>协议</th><th>服务</th><th>Banner</th></tr></thead>
<tbody>
%s
</tbody></table>
<p class="foot">本报告由 AEGIS「端口扫描」能力生成。请仅用于已授权的安全评估。</p>
</body></html>`
	body := fmt.Sprintf(tpl, esc(target), esc(endedAt), nowStamp(), len(ports), len(hosts), tcp, udp, rows.String())
	return []byte(body)
}

func esc(s string) string { return html.EscapeString(s) }
func td(s string) string  { return "<td>" + esc(s) + "</td>" }
func tdBadge(s string) string {
	if s == "" {
		s = "—"
	}
	return "<td><span class=\"badge\">" + esc(s) + "</span></td>"
}
