package bruteforce

// findings.go —— 模块自有表 m_brute_force_results 的读写。
//
// 遵循 scan-backup 同款「独立 findings 文件」模式：
//   saveFindings(taskID)  — goroutine 完成后归档成功凭据
//   listFindings(w, r)    — GET /findings?taskId= 取回归档命中
//   clearFindings(taskID) — DELETE /findings/clear?taskId= 清除指定任务命中

import (
	"net/http"
	"time"
)

// findingRow 是归档凭据的对外形态（与 BruteResult 字段对齐）。
type findingRow struct {
	TaskID   string `json:"taskId"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
	Success  int    `json:"success"` // SQLite BOOLEAN：1=成功，0=失败
	ErrMsg   string `json:"errMsg"`
	FoundAt  string `json:"foundAt"`
}

// saveFindings 把本次爆破成功的凭据按 task_id 归档写库（覆盖式：同 task_id 重跑先清后写）。
func (m *Module) saveFindings(taskID string, results []BruteResult) {
	if m.db == nil {
		return
	}
	tbl := m.db.Table("results")
	// 先清除同 task_id 的旧记录，确保幂等。
	if _, err := m.db.Exec("DELETE FROM "+tbl+" WHERE task_id=?", taskID); err != nil {
		m.log.Warn("findings clear failed", "task", taskID, "err", err)
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, r := range results {
		if !r.Success {
			continue // findings 只归档成功凭据，失败尝试不入命中表（避免 TaskDetail 误当命中展示）
		}
		foundAt := r.FoundAt
		if foundAt == "" {
			foundAt = now
		}
		success := 0
		if r.Success {
			success = 1
		}
		if _, err := m.db.Exec(
			`INSERT OR REPLACE INTO `+tbl+
				` (task_id, protocol, target, username, password, success, errmsg, found_at)`+
				` VALUES (?,?,?,?,?,?,?,?)`,
			taskID, r.Protocol, r.Target, r.Username, r.Password,
			success, r.ErrMsg, foundAt,
		); err != nil {
			m.log.Warn("finding insert failed", "task", taskID, "target", r.Target, "err", err)
		}
	}
}

// listFindings 取某次任务归档的凭据：GET /findings?taskId=<id>[&successOnly=true]。
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
	successOnly := r.URL.Query().Get("successOnly") == "true"

	tbl := m.db.Table("results")
	query := `SELECT task_id, protocol, target, username, password, success, errmsg, found_at` +
		` FROM ` + tbl + ` WHERE task_id=?`
	args := []any{taskID}
	if successOnly {
		query += ` AND success=1`
	}
	query += ` ORDER BY found_at DESC`

	rows, err := m.db.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	items := make([]findingRow, 0)
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(
			&f.TaskID, &f.Protocol, &f.Target, &f.Username, &f.Password,
			&f.Success, &f.ErrMsg, &f.FoundAt,
		); err != nil {
			continue
		}
		items = append(items, f)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// clearFindings 清除指定 task_id 的归档记录：POST /findings/clear?taskId=<id>。
func (m *Module) clearFindings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 taskId"})
		return
	}
	tbl := m.db.Table("results")
	res, err := m.db.Exec("DELETE FROM "+tbl+" WHERE task_id=?", taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// exportFindings 导出指定 task_id 的归档记录：GET /export?taskId=<id>&format=json|csv。
func (m *Module) exportFindings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 taskId"})
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	tbl := m.db.Table("results")
	rows, err := m.db.Query(
		`SELECT task_id, protocol, target, username, password, success, errmsg, found_at`+
			` FROM `+tbl+` WHERE task_id=? AND success=1 ORDER BY found_at DESC`,
		taskID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var items []findingRow
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(
			&f.TaskID, &f.Protocol, &f.Target, &f.Username, &f.Password,
			&f.Success, &f.ErrMsg, &f.FoundAt,
		); err != nil {
			continue
		}
		items = append(items, f)
	}

	prefix := taskID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="brute-force-`+prefix+`.csv"`)
		w.WriteHeader(http.StatusOK)
		// UTF-8 BOM（Excel 友好）
		_, _ = w.Write([]byte("\xef\xbb\xbf"))
		_, _ = w.Write([]byte("协议,目标,用户名,密码,发现时间\n"))
		for _, f := range items {
			line := csvEscape(f.Protocol) + "," + csvEscape(f.Target) + "," +
				csvEscape(f.Username) + "," + csvEscape(f.Password) + "," +
				csvEscape(f.FoundAt) + "\n"
			_, _ = w.Write([]byte(line))
		}
	default: // json
		w.Header().Set("Content-Disposition", `attachment; filename="brute-force-`+prefix+`.json"`)
		writeJSON(w, http.StatusOK, map[string]any{"taskId": taskID, "items": items})
	}
}

func csvEscape(s string) string {
	// 含逗号、引号或换行则加双引号并转义内部引号
	needsQuote := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return s
	}
	result := `"`
	for _, c := range s {
		if c == '"' {
			result += `""`
		} else {
			result += string(c)
		}
	}
	return result + `"`
}
