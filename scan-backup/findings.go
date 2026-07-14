package backup

// findings.go —— 模块自有表 m_scan_backup_findings 的读写。
//
// 这是「模块申请的表，由模块自己维护」的示范：表结构在 migrations/0001_findings.sql
// 声明、框架在启用时建好；本文件负责按系统 task_id 写入命中、按 task_id 取回。
// 与内存态 /hits(仅最近一次扫描视图)互补：本表持久、可按任意历史 task_id 查询。

import (
	"encoding/json"
	"net/http"
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
			refs := h.Refs
			if refs == nil {
				refs = []string{}
			}
			chain := h.Chain
			if chain == nil {
				chain = []string{}
			}
			refsJSON, _ := json.Marshal(refs)
			chainJSON, _ := json.Marshal(chain)
			if _, err := tx.Exec(
				"INSERT OR REPLACE INTO "+tbl+
					" (task_id, hit_id, url, file, kind, severity, code, host, rule, note, found_at, created_at,"+
					"  detail, sample, remediation, refs, chain, evidence_request, evidence_response, evidence_note)"+
					" VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
				taskID, h.ID, h.URL, h.File, h.Kind, h.Severity, h.Code, h.Host, h.Rule, h.Note, h.At, now,
				h.Detail, h.Sample, h.Remediation, string(refsJSON), string(chainJSON),
				h.Evidence.Request, h.Evidence.Response, h.Evidence.Note,
			); err != nil {
				m.log.Warn("finding insert failed", "task", taskID, "hit", h.ID, "err", err)
			}
		}
		return nil
	}); err != nil {
		m.log.Warn("saveFindings tx failed", "task", taskID, "err", err)
	}
}

// findingRow 是归档命中的对外形态（与内存态 Hit 字段完全对齐）。
type findingRow struct {
	TaskID      string   `json:"taskId"`
	HitID       string   `json:"hitId"`
	URL         string   `json:"url"`
	File        string   `json:"file"`
	Kind        string   `json:"kind"`
	Severity    string   `json:"severity"`
	Code        int      `json:"code"`
	Host        string   `json:"host"`
	Rule        string   `json:"rule"`
	Note        string   `json:"note"`
	FoundAt     string   `json:"foundAt"`
	Detail      string   `json:"detail"`
	Sample      string   `json:"sample"`
	Remediation string   `json:"remediation"`
	Refs        []string `json:"refs"`
	Chain       []string `json:"chain"`
	Evidence    Evidence `json:"evidence"`
}

// listFindings 取某次任务归档的命中：GET /findings?taskId=<id>。
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
		"SELECT task_id, hit_id, url, file, kind, severity, code, host, rule, note, found_at,"+
			" detail, sample, remediation, refs, chain, evidence_request, evidence_response, evidence_note"+
			" FROM "+tbl+" WHERE task_id=? ORDER BY rowid", taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	items := make([]findingRow, 0)
	for rows.Next() {
		var f findingRow
		var refsJSON, chainJSON string
		if err := rows.Scan(
			&f.TaskID, &f.HitID, &f.URL, &f.File, &f.Kind,
			&f.Severity, &f.Code, &f.Host, &f.Rule, &f.Note, &f.FoundAt,
			&f.Detail, &f.Sample, &f.Remediation, &refsJSON, &chainJSON,
			&f.Evidence.Request, &f.Evidence.Response, &f.Evidence.Note,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal([]byte(refsJSON), &f.Refs)
		_ = json.Unmarshal([]byte(chainJSON), &f.Chain)
		if f.Refs == nil {
			f.Refs = []string{}
		}
		if f.Chain == nil {
			f.Chain = []string{}
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "数据库读取错误: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
