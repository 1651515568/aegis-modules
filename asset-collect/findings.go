package assetcollect

// findings.go —— 模块自有表 m_asset_collect_results 的读写。
//
// 遵循 scan-backup 同款「独立 findings 文件」模式：
//   saveFindings(taskID, results) — goroutine 完成后归档资产
//   listFindings(w, r)           — GET /findings?taskId= 取回归档资产
//   clearFindings(w, r)          — POST /findings/clear?taskId= 清除指定任务

import (
	"net/http"
	"time"
)

// assetFindingRow 是归档资产的对外形态。
type assetFindingRow struct {
	TaskID  string `json:"taskId"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Org     string `json:"org"`
	Source  string `json:"source"`
	Meta    string `json:"meta"`
	FoundAt string `json:"foundAt"`
}

// saveFindings 把本次收集结果按 task_id 归档写库（覆盖式：同 task_id 重跑先清后写）。
func (m *Module) saveFindings(taskID string, results []CollectedAsset) {
	if m.db == nil {
		return
	}
	tbl := m.db.Table("results")
	if _, err := m.db.Exec("DELETE FROM "+tbl+" WHERE task_id=?", taskID); err != nil {
		m.log.Warn("findings clear failed", "task", taskID, "err", err)
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, a := range results {
		foundAt := a.FoundAt
		if foundAt == "" {
			foundAt = now
		}
		if _, err := m.db.Exec(
			`INSERT OR REPLACE INTO `+tbl+
				` (task_id, type, value, org, source, meta, found_at)`+
				` VALUES (?,?,?,?,?,?,?)`,
			taskID, a.Type, a.Value, a.Org, a.Source, a.Meta, foundAt,
		); err != nil {
			m.log.Warn("finding insert failed", "task", taskID, "value", a.Value, "err", err)
		}
	}
}

// listFindings 取某次任务归档的资产：GET /findings?taskId=<id>[&type=<type>]。
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
	filterType := r.URL.Query().Get("type")

	tbl := m.db.Table("results")
	query := `SELECT task_id, type, value, org, source, meta, found_at` +
		` FROM ` + tbl + ` WHERE task_id=?`
	args := []any{taskID}
	if filterType != "" {
		query += ` AND type=?`
		args = append(args, filterType)
	}
	query += ` ORDER BY type, value`

	rows, err := m.db.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	items := make([]assetFindingRow, 0)
	for rows.Next() {
		var f assetFindingRow
		if err := rows.Scan(
			&f.TaskID, &f.Type, &f.Value, &f.Org, &f.Source, &f.Meta, &f.FoundAt,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "数据库读取错误: " + err.Error()})
		return
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
