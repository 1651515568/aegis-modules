package scandir

// findings.go —— 模块自有表 m_scan_dir_findings 的读写。
//
// 「模块申请的表,由模块自己维护」:表结构在 migrations/0001_findings.sql 声明、框架在启用时
// 建好;本文件负责按系统 task_id 写入命中、按 task_id 取回。与内存态 /hits(仅最近一次
// 扫描视图)互补:本表持久、可按任意历史 task_id 查询。

import (
	"net/http"
	"strconv"
	"time"

	"redops/core"
)

// saveFindings 把当前命中按 task_id 归档落库（覆盖式：同 task_id 重跑先清后写，事务保证原子性）。
func (m *Module) saveFindings(taskID string) {
	if m.db == nil {
		return
	}
	tbl := m.db.Table("findings")
	now := time.Now().Format("2006-01-02 15:04:05")
	hits := m.store.list()

	if err := m.db.WithTx(func(tx core.DB) error {
		if _, err := tx.Exec("DELETE FROM "+tbl+" WHERE task_id=?", taskID); err != nil {
			return err
		}
		for _, h := range hits {
			hitID := strconv.Itoa(h.Status) + "|" + h.URL
			if _, err := tx.Exec(
				"INSERT OR REPLACE INTO "+tbl+
					" (task_id, hit_id, url, path, status, length, words, lines, redirect, content_type, depth, severity, kind, found_at, created_at)"+
					" VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
				taskID, hitID, h.URL, h.Path, h.Status, h.Length, h.Words, h.Lines, h.Redirect, h.ContentType, h.Depth, h.Severity, h.Kind, now, now,
			); err != nil {
				m.log.Warn("finding insert failed", "task", taskID, "hit", hitID, "err", err)
			}
		}
		return nil
	}); err != nil {
		m.log.Warn("saveFindings tx failed", "task", taskID, "err", err)
	}
}

// findingRow 是归档命中的对外形态。
type findingRow struct {
	TaskID      string `json:"taskId"`
	HitID       string `json:"hitId"`
	URL         string `json:"url"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Length      int64  `json:"length"`
	Words       int    `json:"words"`
	Lines       int    `json:"lines"`
	Redirect    string `json:"redirect"`
	ContentType string `json:"contentType"`
	Depth       int    `json:"depth"`
	Severity    string `json:"severity"`
	Kind        string `json:"kind"`
	FoundAt     string `json:"foundAt"`
}

// listFindings 取某次任务归档的命中:GET /findings?taskId=<id>。
func (m *Module) listFindings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 taskId"})
		return
	}
	tbl := m.db.Table("findings")
	rows, err := m.db.Query(
		"SELECT task_id, hit_id, url, path, status, length, words, lines, redirect, content_type, depth, severity, kind, found_at"+
			" FROM "+tbl+" WHERE task_id=? ORDER BY rowid", taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	items := make([]findingRow, 0)
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.TaskID, &f.HitID, &f.URL, &f.Path, &f.Status, &f.Length,
			&f.Words, &f.Lines, &f.Redirect, &f.ContentType, &f.Depth, &f.Severity, &f.Kind, &f.FoundAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "数据库读取错误: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
