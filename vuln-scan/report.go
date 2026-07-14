package vulnscan

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"
)

// ReportData 报告模板数据。
type ReportData struct {
	TaskName    string
	TaskID      string
	TargetCount int
	StartedAt   string
	StoppedAt   string
	Duration    string
	GeneratedAt string
	Stats       map[string]int
	Results     []ReportResult
}

type ReportResult struct {
	Severity    string
	SeverityZH  string
	SevClass    string
	Name        string
	TemplateID  string
	Host        string
	MatchedAt   string
	IP          string
	Tags        string
	Status      string
	StatusZH    string
	AnalystNote string
	FoundAt     string
	CurlCmd     string
	Request     string
	Response    string
}

var sevZH = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
}
var sevClass = map[string]string{
	"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
	"low": "sev-low", "info": "sev-info",
}
var statusZH = map[string]string{
	"": "待确认", "pending": "待确认", "confirmed": "已确认",
	"fp": "假阳性", "follow_up": "待跟进",
}

// GenerateHTMLReport 生成 HTML 格式漏洞报告。
func GenerateHTMLReport(task *Task, results []*Result) ([]byte, error) {
	// 过滤 FP
	var filtered []*Result
	for _, r := range results {
		if !r.FalsePositive {
			filtered = append(filtered, r)
		}
	}

	// 按严重度排序
	sort.SliceStable(filtered, func(i, j int) bool {
		return sevOrder(filtered[i].Severity) < sevOrder(filtered[j].Severity)
	})

	stats := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(filtered)}
	var rows []ReportResult
	for _, r := range filtered {
		sev := strings.ToLower(r.Severity)
		if _, ok := stats[sev]; ok {
			stats[sev]++
		}
		rows = append(rows, ReportResult{
			Severity:    r.Severity,
			SeverityZH:  sevZH[sev],
			SevClass:    sevClass[sev],
			Name:        r.Name,
			TemplateID:  r.TemplateID,
			Host:        r.Host,
			MatchedAt:   r.MatchedAt,
			IP:          r.IP,
			Tags:        strings.Join(r.Tags, ", "),
			Status:      r.Status,
			StatusZH:    statusZH[r.Status],
			AnalystNote: r.AnalystNote,
			FoundAt:     r.FoundAt.Format("2006-01-02 15:04:05"),
			CurlCmd:     r.CurlCmd,
			Request:     truncate(r.Request, 2048),
			Response:    truncate(r.Response, 2048),
		})
	}

	dur := ""
	if !task.StartedAt.IsZero() && !task.StoppedAt.IsZero() {
		d := task.StoppedAt.Sub(task.StartedAt)
		h := int(d.Hours()); m := int(d.Minutes()) % 60; s := int(d.Seconds()) % 60
		if h > 0 {
			dur = fmt.Sprintf("%d小时%d分%d秒", h, m, s)
		} else if m > 0 {
			dur = fmt.Sprintf("%d分%d秒", m, s)
		} else {
			dur = fmt.Sprintf("%d秒", s)
		}
	}

	data := ReportData{
		TaskName:    task.Name,
		TaskID:      task.ID,
		TargetCount: task.TargetCount,
		StartedAt:   task.StartedAt.Format("2006-01-02 15:04:05"),
		StoppedAt:   task.StoppedAt.Format("2006-01-02 15:04:05"),
		Duration:    dur,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Stats:       stats,
		Results:     rows,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"splitTags": splitTagsForTmpl,
	}).Parse(reportHTMLTmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const reportHTMLTmpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>漏洞扫描报告 — {{.TaskName}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#f8f9fa;color:#1a1a2e;font-size:14px;line-height:1.6}
.page{max-width:1100px;margin:0 auto;padding:32px 24px}
/* 头部 */
header{background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);color:#fff;padding:40px;border-radius:12px;margin-bottom:24px;position:relative;overflow:hidden}
header::before{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%2300d4ff' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");pointer-events:none}
.header-title{font-size:28px;font-weight:700;margin-bottom:8px;position:relative}
.header-title span{color:#00d4ff}
.header-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:20px;position:relative}
.meta-item{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:12px 16px}
.meta-label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
.meta-value{font-size:15px;font-weight:600;color:#e6edf3}
/* 统计 */
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.stat-card{border-radius:10px;padding:16px;text-align:center;border:1px solid}
.stat-count{font-size:28px;font-weight:700;line-height:1}
.stat-label{font-size:12px;margin-top:6px;font-weight:500}
.sev-critical{background:#fff5f5;border-color:#fed7d7;color:#c53030}.sev-critical .stat-count{color:#e53e3e}
.sev-high{background:#fff8f0;border-color:#fbd38d;color:#c05621}.sev-high .stat-count{color:#ed8936}
.sev-medium{background:#fffff0;border-color:#faf089;color:#975a16}.sev-medium .stat-count{color:#d69e2e}
.sev-low{background:#ebf8ff;border-color:#bee3f8;color:#2c5282}.sev-low .stat-count{color:#3182ce}
.sev-info{background:#f7fafc;border-color:#e2e8f0;color:#4a5568}.sev-info .stat-count{color:#718096}
/* 漏洞列表 */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #e2e8f0;display:flex;align-items:center;gap:8px}
.section-title::before{content:'';width:4px;height:20px;background:#00d4ff;border-radius:2px;display:inline-block}
.finding{border:1px solid #e2e8f0;border-radius:10px;margin-bottom:16px;overflow:hidden;page-break-inside:avoid}
.finding-header{display:flex;align-items:flex-start;gap:12px;padding:16px;cursor:pointer;background:#fff}
.finding-header:hover{background:#f7fafc}
.sev-badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;white-space:nowrap;flex-shrink:0}
.badge-critical{background:#fff5f5;color:#c53030;border:1px solid #fed7d7}
.badge-high{background:#fff8f0;color:#c05621;border:1px solid #fbd38d}
.badge-medium{background:#fffff0;color:#975a16;border:1px solid #faf089}
.badge-low{background:#ebf8ff;color:#2c5282;border:1px solid #bee3f8}
.badge-info{background:#f7fafc;color:#4a5568;border:1px solid #e2e8f0}
.finding-title{flex:1;min-width:0}
.finding-name{font-size:15px;font-weight:600;color:#1a202c;margin-bottom:4px}
.finding-host{font-family:'Courier New',monospace;font-size:12px;color:#2b6cb0;word-break:break-all}
.finding-body{background:#f8f9fa;border-top:1px solid #e2e8f0;padding:16px}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:12px}
.detail-item{background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 12px}
.detail-label{font-size:10px;color:#718096;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.detail-value{font-size:13px;font-weight:500;color:#2d3748;word-break:break-all}
.analyst-note{background:#fffbeb;border:1px solid #f6e05e;border-radius:6px;padding:10px 12px;margin-bottom:12px;font-size:13px;color:#744210}
.analyst-note::before{content:'💬 分析师备注：';font-weight:600;display:block;margin-bottom:4px}
details{margin-top:12px}
details summary{font-size:12px;color:#4a5568;cursor:pointer;padding:6px 0;font-weight:500}
details summary:hover{color:#2b6cb0}
pre{background:#1a1a2e;color:#e2e8f0;padding:12px;border-radius:6px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin-top:6px;max-height:200px}
.tags{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.tag{background:#edf2f7;color:#4a5568;padding:2px 8px;border-radius:12px;font-size:11px}
/* 状态 */
.status-badge{padding:2px 8px;border-radius:12px;font-size:11px;font-weight:500}
.status-confirmed{background:#f0fff4;color:#276749;border:1px solid #9ae6b4}
.status-follow_up{background:#fffff0;color:#975a16;border:1px solid #faf089}
.status-pending{background:#f7fafc;color:#718096;border:1px solid #e2e8f0}
/* 页脚 */
footer{text-align:center;margin-top:40px;padding:20px;color:#718096;font-size:12px;border-top:1px solid #e2e8f0}
/* 打印 */
@media print{
  body{background:#fff}
  .page{padding:16px}
  header{background:#1a1a2e!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .finding{break-inside:avoid}
}
.no-results{text-align:center;padding:48px;color:#718096;background:#fff;border-radius:10px;border:1px dashed #e2e8f0}
</style>
</head>
<body>
<div class="page">

<header>
  <div class="header-title">&#x1F6E1; 漏洞扫描报告 — <span>{{.TaskName}}</span></div>
  <div class="header-meta">
    <div class="meta-item"><div class="meta-label">任务 ID</div><div class="meta-value" style="font-size:12px;font-family:monospace">{{.TaskID}}</div></div>
    <div class="meta-item"><div class="meta-label">扫描目标数</div><div class="meta-value">{{.TargetCount}} 个</div></div>
    <div class="meta-item"><div class="meta-label">发现漏洞</div><div class="meta-value">{{.Stats.total}} 个（已排除假阳性）</div></div>
    <div class="meta-item"><div class="meta-label">扫描时间</div><div class="meta-value" style="font-size:13px">{{.StartedAt}}</div></div>
    <div class="meta-item"><div class="meta-label">持续时长</div><div class="meta-value">{{.Duration}}</div></div>
    <div class="meta-item"><div class="meta-label">报告生成</div><div class="meta-value" style="font-size:12px">{{.GeneratedAt}}</div></div>
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card sev-critical"><div class="stat-count">{{.Stats.critical}}</div><div class="stat-label">&#x1F534; 严重</div></div>
  <div class="stat-card sev-high"><div class="stat-count">{{.Stats.high}}</div><div class="stat-label">&#x1F7E0; 高危</div></div>
  <div class="stat-card sev-medium"><div class="stat-count">{{.Stats.medium}}</div><div class="stat-label">&#x1F7E1; 中危</div></div>
  <div class="stat-card sev-low"><div class="stat-count">{{.Stats.low}}</div><div class="stat-label">&#x1F535; 低危</div></div>
  <div class="stat-card sev-info"><div class="stat-count">{{.Stats.info}}</div><div class="stat-label">&#x26AA; 信息</div></div>
</div>

<div class="section-title">漏洞详情清单（共 {{.Stats.total}} 条）</div>

{{if not .Results}}
<div class="no-results">&#x2705; 未发现漏洞（或所有结果均标记为假阳性）</div>
{{else}}
{{range .Results}}
<div class="finding">
  <div class="finding-header">
    <span class="sev-badge badge-{{.SevClass}}">{{.SeverityZH}}</span>
    <div class="finding-title">
      <div class="finding-name">{{.Name}}</div>
      <div class="finding-host">{{.MatchedAt}}</div>
    </div>
    {{if ne .Status "pending"}}<span class="status-badge status-{{.Status}}">{{.StatusZH}}</span>{{end}}
  </div>
  <div class="finding-body">
    <div class="detail-grid">
      <div class="detail-item"><div class="detail-label">主机</div><div class="detail-value">{{.Host}}</div></div>
      <div class="detail-item"><div class="detail-label">模板 ID</div><div class="detail-value" style="font-family:monospace;font-size:11px">{{.TemplateID}}</div></div>
      {{if .IP}}<div class="detail-item"><div class="detail-label">IP 地址</div><div class="detail-value">{{.IP}}</div></div>{{end}}
      <div class="detail-item"><div class="detail-label">发现时间</div><div class="detail-value">{{.FoundAt}}</div></div>
    </div>
    {{if .Tags}}<div class="tags">{{range (splitTags .Tags)}}<span class="tag">#{{.}}</span>{{end}}</div>{{end}}
    {{if .AnalystNote}}<div class="analyst-note">{{.AnalystNote}}</div>{{end}}
    {{if .CurlCmd}}<details><summary>&#x1F4CB; curl 验证命令</summary><pre>{{.CurlCmd}}</pre></details>{{end}}
    {{if .Request}}<details><summary>&#x1F4E4; HTTP 请求</summary><pre>{{.Request}}</pre></details>{{end}}
    {{if .Response}}<details><summary>&#x1F4E5; HTTP 响应</summary><pre>{{.Response}}</pre></details>{{end}}
  </div>
</div>
{{end}}
{{end}}

<footer>
  <p>本报告由 AEGIS 红队攻防平台自动生成 &nbsp;·&nbsp; 生成时间：{{.GeneratedAt}}</p>
  <p style="margin-top:4px;color:#a0aec0">⚠ 此报告包含敏感安全信息，请妥善保管，禁止未授权传播</p>
</footer>
</div>
</body>
</html>`

// splitTagsForTmpl 供模板使用。
func splitTagsForTmpl(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ", ") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}
