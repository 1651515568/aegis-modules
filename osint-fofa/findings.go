package osintfofa

// findings.go —— 模块自有表 m_osint_fofa_findings 的读写。
//
// 遵循 scan-backup / asset-collect 同款「独立 findings 文件」模式：
//
//	saveFindings(taskID, assets) — 查询 goroutine 完成后归档资产
//	listFindings(w, r)           — GET /findings?taskId= 取回归档资产
//	clearFindings(w, r)          — POST /findings/clear?taskId= 清除指定任务

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"time"
)

// findingRow 是归档资产的对外形态，与 Asset 结构字段对齐。
type findingRow struct {
	TaskID    string `json:"taskId"`
	AssetID   string `json:"assetId"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Domain    string `json:"domain"`
	Protocol  string `json:"protocol"`
	Title     string `json:"title"`
	Banner    string `json:"banner"`
	Country   string `json:"country"`
	City      string `json:"city"`
	OS        string `json:"os"`
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt"`
}

// makeAssetID 根据 taskID + ip + port 生成稳定的复合主键，用于 INSERT OR REPLACE 幂等写入。
func makeAssetID(taskID, ip string, port int) string {
	h := md5.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%d", taskID, ip, port)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// saveFindings 把本次查询结果按 task_id 归档写库（覆盖式：同 task_id 重跑先清后写）。
func (m *Module) saveFindings(taskID string, assets []Asset) {
	if m.db == nil {
		return
	}
	tbl := m.db.Table("findings")
	// 先删除同 task_id 旧记录，再批量插入（覆盖语义）
	if _, err := m.db.Exec("DELETE FROM "+tbl+" WHERE task_id=?", taskID); err != nil {
		m.log.Warn("osint-fofa findings 清旧记录失败", "task", taskID, "err", err)
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, a := range assets {
		assetID := makeAssetID(taskID, a.IP, a.Port)
		_, err := m.db.Exec(
			`INSERT OR REPLACE INTO `+tbl+
				` (task_id, asset_id, ip, port, domain, protocol, title, banner, country, city, os, source, created_at)`+
				` VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			taskID, assetID, a.IP, a.Port, a.Domain, a.Protocol,
			a.Title, a.Banner, a.Country, a.City, a.OS, a.Source, now,
		)
		if err != nil {
			m.log.Warn("osint-fofa finding 写入失败", "task", taskID, "ip", a.IP, "port", a.Port, "err", err)
		}
	}
	m.log.Info("osint-fofa findings 已归档", "task", taskID, "count", len(assets))
}

// listFindings 取某次任务归档的资产：GET /findings?taskId=<id>[&source=<platform>]。
func (m *Module) listFindings(w http.ResponseWriter, r *http.Request) {
	if m.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "持久化未就绪"})
		return
	}
	taskID := r.URL.Query().Get("taskId")
	if taskID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 taskId 参数"})
		return
	}
	filterSource := r.URL.Query().Get("source")

	tbl := m.db.Table("findings")
	query := `SELECT task_id, asset_id, ip, port, domain, protocol, title, banner, country, city, os, source, created_at` +
		` FROM ` + tbl + ` WHERE task_id=?`
	args := []any{taskID}
	if filterSource != "" {
		query += ` AND source=?`
		args = append(args, filterSource)
	}
	query += ` ORDER BY source, ip, port`

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
			&f.TaskID, &f.AssetID, &f.IP, &f.Port, &f.Domain,
			&f.Protocol, &f.Title, &f.Banner, &f.Country, &f.City,
			&f.OS, &f.Source, &f.CreatedAt,
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要 taskId 参数"})
		return
	}
	tbl := m.db.Table("findings")
	res, err := m.db.Exec("DELETE FROM "+tbl+" WHERE task_id=?", taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	m.log.Info("osint-fofa findings 已清除", "task", taskID, "deleted", n)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}
