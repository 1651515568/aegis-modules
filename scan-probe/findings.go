package probe

// findings.go —— 模块自有表 m_scan_probe_results 的读写。
//
// 遵循 scan-backup 同款「独立 findings 文件」模式：
//   saveFindings(taskID, results) — goroutine 完成后归档（覆盖式重跑）
//   listFindings(w, r)           — GET /findings?taskId= 取回归档结果
//   clearFindings(w, r)          — POST /findings/clear?taskId= 清除指定任务

import (
	"encoding/json"
	"net/http"
	"time"

	"redops/core"
)

type findingRow struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	CMS         string   `json:"cms"`
	Framework   string   `json:"framework"`
	WAF         string   `json:"waf"`
	Server      string   `json:"server"`
	Title       string   `json:"title"`
	StatusCode  int      `json:"statusCode"`
	OS          string   `json:"os"`
	FaviconHash int32    `json:"faviconHash,omitempty"`
	Components  []string `json:"components,omitempty"`
	FoundAt     string   `json:"foundAt"`
}

// saveFindings 把本次探测结果按 task_id 归档写库（覆盖式：同 task_id 重跑先清后写，事务保证原子性）。
func (m *Module) saveFindings(taskID string, results []ProbeResult) {
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
			comps := r.Components
			if comps == nil {
				comps = []string{}
			}
			compsJSON, _ := json.Marshal(comps)
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO `+table+` (task_id,host,port,protocol,cms,framework,waf,server,title,status_code,os,favicon_hash,components,found_at)
	             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				taskID, r.Host, r.Port, r.Protocol, r.CMS, r.Framework, r.WAF, r.Server, r.Title, r.StatusCode, r.OS, r.FaviconHash, string(compsJSON), now,
			); err != nil {
				m.log.Warn("findings insert failed", "task", taskID, "host", r.Host, "err", err)
			}
		}
		return nil
	}); err != nil {
		m.log.Warn("saveFindings tx failed", "task", taskID, "err", err)
	}
}

// listFindings 取某次任务归档的探测结果：GET /findings?taskId=<id>。
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
	table := m.db.Table("results")
	rows, err := m.db.Query(
		"SELECT host,port,protocol,cms,framework,waf,server,title,status_code,os,favicon_hash,components,found_at"+
			" FROM "+table+" WHERE task_id=? ORDER BY rowid",
		taskID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	items := make([]findingRow, 0)
	for rows.Next() {
		var fr findingRow
		var compsJSON string
		if err := rows.Scan(&fr.Host, &fr.Port, &fr.Protocol, &fr.CMS, &fr.Framework,
			&fr.WAF, &fr.Server, &fr.Title, &fr.StatusCode, &fr.OS, &fr.FaviconHash,
			&compsJSON, &fr.FoundAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal([]byte(compsJSON), &fr.Components)
		items = append(items, fr)
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 taskId"})
		return
	}
	table := m.db.Table("results")
	res, err := m.db.Exec("DELETE FROM "+table+" WHERE task_id=?", taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}
