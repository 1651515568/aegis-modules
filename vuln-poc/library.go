package vulnpoc

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
	"redops/core"
)

const libDBPath = "data/vuln-poc-library.db"

// TemplateInfo 是从 nuclei 模板 YAML 中提取的元数据。
type TemplateInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	Tags        []string `json:"tags"`
	CveID       string   `json:"cveId,omitempty"`
	FilePath    string   `json:"filePath"`
	Category    string   `json:"category"`
	Source      string   `json:"source"`
}

type LibraryPage struct {
	Items    []TemplateInfo `json:"items"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
	Indexed  bool           `json:"indexed"`
	Progress int            `json:"progress"`
}

type LibraryStats struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	ByCategory map[string]int `json:"byCategory"`
	BySource   map[string]int `json:"bySource"`
	Indexed    bool           `json:"indexed"`
	Progress   int            `json:"progress"`
}

type library struct {
	db       *sql.DB
	log      core.Logger
	indexed  atomic.Bool
	progress atomic.Int32
	once     sync.Once
	mu       sync.Mutex
}

func newLibrary(log core.Logger) *library {
	return &library{log: log}
}

func (l *library) open() error {
	if err := os.MkdirAll("data", 0o755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", libDBPath+"?_journal=WAL&_timeout=5000&cache=shared")
	if err != nil {
		return fmt.Errorf("打开漏洞库 SQLite 失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	l.db = db

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS templates (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL DEFAULT '',
			severity    TEXT NOT NULL DEFAULT 'info',
			description TEXT DEFAULT '',
			author      TEXT DEFAULT '',
			tags        TEXT DEFAULT '',
			cve_id      TEXT DEFAULT '',
			file_path   TEXT NOT NULL,
			category    TEXT NOT NULL DEFAULT '',
			source      TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_sev  ON templates(severity);
		CREATE INDEX IF NOT EXISTS idx_cat  ON templates(category);
		CREATE INDEX IF NOT EXISTS idx_src  ON templates(source);
	`)
	if err != nil {
		return fmt.Errorf("创建漏洞库表失败: %w", err)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM templates").Scan(&count)
	if count > 0 {
		l.indexed.Store(true)
		l.progress.Store(100)
		l.log.Info("漏洞库已就绪", "count", count)
	}
	return nil
}

// StartBuild 在后台启动索引（只执行一次）。
func (l *library) StartBuild() {
	go l.once.Do(func() {
		if l.indexed.Load() {
			return
		}
		l.log.Info("后台建立漏洞库索引…")
		l.indexAll()
	})
}

// Rebuild 强制重建索引。
func (l *library) Rebuild() {
	l.mu.Lock()
	l.indexed.Store(false)
	l.progress.Store(0)
	l.once = sync.Once{}
	l.mu.Unlock()
	go l.once.Do(l.indexAll)
}

// ─── YAML 解析 ───────────────────────────────────────────────────────────────

type nucleiMeta struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        interface{} `yaml:"name"`
		Author      interface{} `yaml:"author"`
		Severity    interface{} `yaml:"severity"`
		Description interface{} `yaml:"description"`
		Tags        interface{} `yaml:"tags"`
		Metadata    interface{} `yaml:"metadata"`
		Classification struct {
			CveID interface{} `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

func toStr(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case []interface{}:
		parts := make([]string, 0, len(x))
		for _, p := range x {
			s := strings.TrimSpace(fmt.Sprint(p))
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func parseMeta(path string) (id, name, severity, desc, author, tags, cveID string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var m nucleiMeta
	if err := yaml.Unmarshal(data, &m); err != nil {
		return
	}

	id = strings.TrimSpace(m.ID)
	name = toStr(m.Info.Name)
	severity = strings.ToLower(toStr(m.Info.Severity))
	if severity == "" {
		severity = "info"
	}
	desc = toStr(m.Info.Description)
	if len(desc) > 512 {
		desc = desc[:512]
	}
	author = toStr(m.Info.Author)
	tags = toStr(m.Info.Tags)
	cveID = toStr(m.Info.Classification.CveID)
	return
}

// ─── 质量过滤 ─────────────────────────────────────────────────────────────────

// 跳过纯探测目录（适用于官方/自定义源）
var skipPathSegments = []string{
	"/technologies/",
	"/dns/",
	"/network/",
	"/ssl/",
	"/file/",
	"/helpers/",
	"technologies/",
	"dns/",
}

// 漏洞利用关键词（info 级别保留判断）
var exploitKeywords = []string{
	"rce", "sqli", "sql-injection", "xss", "lfi", "rfi", "ssrf",
	"unauth", "unauthorized", "upload", "code-execution",
	"default-login", "default-password", "traversal", "injection",
	"bypass", "takeover", "disclosure", "leak", "idor",
	"redirect", "xxe", "deseriali", "ssti", "exposure",
	"misconfig", "backdoor", "webshell", "fileread", "rdi",
	"arbitrary", "sensitive",
}

// isUsefulTemplate 判断模板是否值得收录。
// source=="解密POC" 时全部保留（已人工筛选的漏洞 POC 库）。
func isUsefulTemplate(source, relPath, severity, tags string) bool {
	if source == "解密POC" {
		return true
	}
	// 跳过纯探测目录
	lPath := strings.ToLower(filepath.ToSlash(relPath))
	for _, seg := range skipPathSegments {
		if strings.Contains(lPath, seg) {
			return false
		}
	}
	// 非 info 全部保留
	if severity != "info" {
		return true
	}
	// info 级别：有漏洞利用关键词才保留
	lTags := strings.ToLower(tags)
	for _, kw := range exploitKeywords {
		if strings.Contains(lTags, kw) {
			return true
		}
	}
	return false
}

// ─── 核心索引逻辑 ─────────────────────────────────────────────────────────────

// resolveTemplateDir 优先返回模块目录内的路径，不存在则回退到 home 目录。
// modRel 是相对引擎工作目录的路径（如 "modules/vuln-poc/poc-exploits"）。
func resolveTemplateDir(modRel, homeName string) string {
	if info, err := os.Stat(modRel); err == nil && info.IsDir() {
		return modRel
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, homeName)
	}
	return homeName
}

func (l *library) indexAll() {
	type rootDef struct {
		path   string
		source string
	}
	roots := []rootDef{
		{resolveTemplateDir("modules/vuln-poc/poc-exploits", "poc-exploits"), "解密POC"},
		{resolveTemplateDir("modules/vuln-poc/nuclei-templates", "nuclei-templates"), "官方"},
		{resolveTemplateDir("modules/vuln-poc/custom-templates", "custom-templates"), "自定义"},
	}
	// filepath.Walk/WalkDir 不跟随符号链接，提前解析真实路径
	for i := range roots {
		if real, err := filepath.EvalSymlinks(roots[i].path); err == nil {
			roots[i].path = real
		}
	}

	// 先统计有效文件数（路径层面过滤，不解析 YAML）
	total := 0
	for _, r := range roots {
		if _, err := os.Stat(r.path); os.IsNotExist(err) {
			continue
		}
		_ = filepath.WalkDir(r.path, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
				return nil
			}
			if r.source == "解密POC" {
				total++
				return nil
			}
			rel, _ := filepath.Rel(r.path, path)
			lPath := strings.ToLower(filepath.ToSlash(rel))
			for _, seg := range skipPathSegments {
				if strings.Contains(lPath, seg) {
					return nil
				}
			}
			total++
			return nil
		})
	}
	l.log.Info("预估有效模板文件", "total", total)
	if total == 0 {
		l.indexed.Store(true)
		l.progress.Store(100)
		return
	}

	// 清空旧数据
	_, _ = l.db.Exec("DELETE FROM templates")

	tx, err := l.db.Begin()
	if err != nil {
		l.log.Error("漏洞库索引：begin tx 失败", "err", err)
		return
	}

	const insSQL = `INSERT OR REPLACE INTO templates
		(id,name,severity,description,author,tags,cve_id,file_path,category,source)
		VALUES(?,?,?,?,?,?,?,?,?,?)`
	stmt, err := tx.Prepare(insSQL)
	if err != nil {
		_ = tx.Rollback()
		l.log.Error("漏洞库索引：prepare 失败", "err", err)
		return
	}

	done := 0
	batchN := 0
	lastPct := -1

	commitBatch := func() {
		stmt.Close()
		stmt = nil
		if commitErr := tx.Commit(); commitErr != nil {
			l.log.Error("漏洞库索引：commit 失败", "err", commitErr)
		}
		tx = nil
		newTx, bErr := l.db.Begin()
		if bErr != nil {
			l.log.Error("漏洞库索引：begin tx 失败", "err", bErr)
			return
		}
		newStmt, pErr := newTx.Prepare(insSQL)
		if pErr != nil {
			_ = newTx.Rollback()
			l.log.Error("漏洞库索引：prepare 失败", "err", pErr)
			return
		}
		tx = newTx
		stmt = newStmt
	}

	for _, r := range roots {
		if _, err := os.Stat(r.path); os.IsNotExist(err) {
			l.log.Info("跳过不存在的模板目录", "path", r.path)
			continue
		}
		_ = filepath.WalkDir(r.path, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
				return nil
			}

			rel, _ := filepath.Rel(r.path, path)
			parts := strings.SplitN(rel, string(filepath.Separator), 2)
			category := parts[0]
			if r.source == "官方" {
				category = "官方漏洞库"
			}

			id, name, sev, desc, author, tags, cveID := parseMeta(path)
			if id == "" {
				id = rel
			}
			if name == "" {
				name = strings.TrimSuffix(filepath.Base(path), ".yaml")
			}

			// 质量过滤
			if !isUsefulTemplate(r.source, rel, sev, tags) {
				return nil
			}

			uniqueID := r.source + ":" + rel

			if stmt == nil {
				return filepath.SkipAll
			}
			_, _ = stmt.Exec(uniqueID, name, sev, desc, author, tags, cveID, path, category, r.source)

			done++
			batchN++
			if batchN >= 1000 {
				commitBatch()
				batchN = 0
			}

			pct := done * 100 / total
			if pct > 100 {
				pct = 100
			}
			if pct != lastPct {
				l.progress.Store(int32(pct))
				lastPct = pct
				if pct%10 == 0 {
					l.log.Info("漏洞库索引进度", "pct", pct, "done", done)
				}
			}
			return nil
		})
	}

	if stmt != nil {
		stmt.Close()
	}
	if tx != nil {
		if err := tx.Commit(); err != nil {
			l.log.Error("漏洞库最终 commit 失败", "err", err)
			return
		}
	}

	l.indexed.Store(true)
	l.progress.Store(100)
	l.log.Info("漏洞库索引完成", "total", done)
}

// ─── 查询接口 ─────────────────────────────────────────────────────────────────

type LibraryQuery struct {
	Search   string
	Severity string
	Category string
	Source   string
	Page     int
	PageSize int
}

func (l *library) Query(q LibraryQuery) LibraryPage {
	if l.db == nil {
		return LibraryPage{Items: []TemplateInfo{}, Indexed: l.indexed.Load(), Progress: int(l.progress.Load())}
	}
	if q.PageSize <= 0 {
		q.PageSize = 50
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	offset := (q.Page - 1) * q.PageSize

	where, args := buildWhere(q)

	var total int
	countArgs := append([]interface{}{}, args...)
	_ = l.db.QueryRow("SELECT COUNT(*) FROM templates WHERE "+where, countArgs...).Scan(&total)

	queryArgs := append(args, q.PageSize, offset)
	rows, err := l.db.Query(
		"SELECT id,name,severity,description,author,tags,cve_id,file_path,category,source FROM templates WHERE "+
			where+` ORDER BY CASE severity
			WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
			WHEN 'low' THEN 4 ELSE 5 END, name ASC LIMIT ? OFFSET ?`,
		queryArgs...,
	)

	items := []TemplateInfo{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t TemplateInfo
			var tagsStr string
			_ = rows.Scan(&t.ID, &t.Name, &t.Severity, &t.Description, &t.Author,
				&tagsStr, &t.CveID, &t.FilePath, &t.Category, &t.Source)
			if tagsStr != "" {
				t.Tags = strings.Split(tagsStr, ",")
			} else {
				t.Tags = []string{}
			}
			items = append(items, t)
		}
	}

	return LibraryPage{
		Items:    items,
		Total:    total,
		Page:     q.Page,
		PageSize: q.PageSize,
		Indexed:  l.indexed.Load(),
		Progress: int(l.progress.Load()),
	}
}

func buildWhere(q LibraryQuery) (string, []interface{}) {
	parts := []string{"1=1"}
	args := []interface{}{}

	if q.Search != "" {
		parts = append(parts, "(LOWER(name) LIKE ? OR LOWER(tags) LIKE ? OR LOWER(cve_id) LIKE ? OR LOWER(id) LIKE ?)")
		kw := "%" + strings.ToLower(q.Search) + "%"
		args = append(args, kw, kw, kw, kw)
	}
	if q.Severity != "" {
		parts = append(parts, "severity = ?")
		args = append(args, strings.ToLower(q.Severity))
	}
	if q.Category != "" {
		parts = append(parts, "category = ?")
		args = append(args, q.Category)
	}
	if q.Source != "" {
		parts = append(parts, "source = ?")
		args = append(args, q.Source)
	}

	return strings.Join(parts, " AND "), args
}

func (l *library) Stats() LibraryStats {
	s := LibraryStats{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		BySource:   make(map[string]int),
		Indexed:    l.indexed.Load(),
		Progress:   int(l.progress.Load()),
	}
	if l.db == nil {
		return s
	}
	_ = l.db.QueryRow("SELECT COUNT(*) FROM templates").Scan(&s.Total)

	if rows, err := l.db.Query("SELECT severity, COUNT(*) FROM templates GROUP BY severity"); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			if rows.Scan(&k, &v) == nil {
				s.BySeverity[k] = v
			}
		}
	}
	if rows, err := l.db.Query("SELECT category, COUNT(*) FROM templates GROUP BY category ORDER BY COUNT(*) DESC LIMIT 30"); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			if rows.Scan(&k, &v) == nil {
				s.ByCategory[k] = v
			}
		}
	}
	if rows, err := l.db.Query("SELECT source, COUNT(*) FROM templates GROUP BY source"); err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			if rows.Scan(&k, &v) == nil {
				s.BySource[k] = v
			}
		}
	}
	return s
}
