package subdomain

// findings.go —— 模块自有表 m_scan_subdomain_results 的读写。
//
// 遵循 scan-backup 同款「独立 findings 文件」模式：
//   saveFindings(taskID, results) — goroutine 完成后归档（覆盖式重跑）
//   listFindings(w, r)           — GET /findings?taskId= 取回归档结果
//   clearFindings(w, r)          — POST /findings/clear?taskId= 清除指定任务

import (
	"net/http"
	"strings"
	"time"

	"redops/core"
)

// saveFindings 把本次枚举结果按 task_id 归档写库（覆盖式：同 task_id 重跑先清后写，事务保证原子性）。
func (m *Module) saveFindings(taskID string, results []SubdomainResult) {
	if m.db == nil {
		return
	}
	table := m.db.Table("results")
	now := time.Now().Format("2006-01-02 15:04:05")

	if err := m.db.WithTx(func(tx core.DB) error {
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE task_id=?", taskID); err != nil {
			return err
		}
		for _, r := range results {
			ipStr := strings.Join(r.IP, ",")
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO `+table+` (task_id,subdomain,ip,cdn,status,title,source,found_at)
	             VALUES (?,?,?,?,?,?,?,?)`,
				taskID, r.Subdomain, ipStr, r.CDN, r.Status, r.Title, r.Source, now,
			); err != nil {
				m.log.Warn("subdomain insert failed", "task", taskID, "sub", r.Subdomain, "err", err)
			}
		}
		return nil
	}); err != nil {
		m.log.Warn("saveFindings tx failed", "task", taskID, "err", err)
	}
}

// listFindings 按 taskId 读取归档的子域名结果：GET /findings?taskId=<id>。
func (m *Module) listFindings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "taskId 不能为空"})
		return
	}
	tbl := m.db.Table("results")
	rows, err := m.db.Query(
		`SELECT subdomain, ip, cdn, status, title, source, found_at FROM `+tbl+` WHERE task_id=? ORDER BY subdomain`,
		taskID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type row struct {
		Subdomain string `json:"subdomain"`
		IP        string `json:"ip"`
		CDN       string `json:"cdn"`
		Status    int    `json:"status"`
		Title     string `json:"title"`
		Source    string `json:"source"`
		FoundAt   string `json:"foundAt"`
	}
	items := make([]row, 0)
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.Subdomain, &item.IP, &item.CDN, &item.Status, &item.Title, &item.Source, &item.FoundAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "数据库读取错误: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// clearFindings 清除指定 task_id 的归档记录：POST /findings/clear?taskId=<id>。
func (m *Module) clearFindings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "taskId 不能为空"})
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
