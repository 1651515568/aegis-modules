package jsextract

import (
	"net/http"
	"time"

	"redops/core"
)

// maxFindingsDB 单次任务写库上限，防止 saveFindings 写入超大数据集导致 SQLite 卡顿。
// 引擎侧 Extract 已有 maxFindingsPerFile 限制，此处作为最终防线。
const maxFindingsDB = 5000

func (m *Module) saveFindings(taskID string, findings []Finding) {
	if m.db == nil {
		return
	}
	table := m.db.Table("findings")
	now := time.Now().Format("2006-01-02 15:04:05")

	if err := m.db.WithTx(func(tx core.DB) error {
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE task_id=?", taskID); err != nil {
			return err
		}
		written := 0
		for i := range findings {
			if written >= maxFindingsDB {
				m.log.Warn("findings truncated at db limit", "task", taskID, "written", written, "total", len(findings))
				break
			}
			f := &findings[i]
			if f.FoundAt == "" {
				f.FoundAt = now
			}
			conf := 0
			if f.Confident {
				conf = 1
			}
			if _, err := tx.Exec(
				`INSERT OR IGNORE INTO `+table+`
				 (id,task_id,js_url,page_url,category,severity,label,value,ctx,entropy,confident,found_at)
				 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
				f.ID, taskID, f.JSURL, f.PageURL, f.Category, f.Severity,
				f.Label, f.Value, f.Context, f.Entropy, conf, f.FoundAt,
			); err != nil {
				m.log.Warn("insert finding failed", "task", taskID, "id", f.ID, "err", err)
				continue
			}
			written++
		}
		return nil
	}); err != nil {
		m.log.Warn("saveFindings tx failed", "task", taskID, "err", err)
	}
}

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
	table := m.db.Table("findings")
	rows, err := m.db.Query(
		`SELECT id,js_url,page_url,category,severity,label,value,ctx,
		        COALESCE(entropy,0),COALESCE(confident,0),found_at
		 FROM `+table+` WHERE task_id=? ORDER BY
		   CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
		   rowid`,
		taskID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type row struct {
		ID        string  `json:"id"`
		TaskID    string  `json:"taskId"`
		JSURL     string  `json:"jsUrl"`
		PageURL   string  `json:"pageUrl"`
		Category  string  `json:"category"`
		Severity  string  `json:"severity"`
		Label     string  `json:"label"`
		Value     string  `json:"value"`
		Context   string  `json:"ctx"`
		Entropy   float64 `json:"entropy"`
		Confident bool    `json:"confident"`
		FoundAt   string  `json:"foundAt"`
	}
	items := make([]row, 0)
	for rows.Next() {
		var f row
		var confInt int
		f.TaskID = taskID
		if err := rows.Scan(&f.ID, &f.JSURL, &f.PageURL, &f.Category, &f.Severity,
			&f.Label, &f.Value, &f.Context, &f.Entropy, &confInt, &f.FoundAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		f.Confident = confInt == 1
		items = append(items, f)
	}
	// 检查迭代过程中是否发生错误
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "数据库读取错误: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

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
	table := m.db.Table("findings")
	res, err := m.db.Exec("DELETE FROM "+table+" WHERE task_id=?", taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}
