package sslaudit

// findings.go —— m_ssl_audit_findings / m_ssl_audit_certs 的读写。
//
// saveFindings 把当次扫描结果按 task_id 归档（覆盖式）。
// listFindings 按 task_id 从库中取回归档发现（GET /findings?taskId=）。

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"redops/core"
)

// saveFindings 把 results 落入 SQLite（同 task_id 先清后写，事务保证原子性）。
func (m *Module) saveFindings(taskID string, results []*HostResult) {
	if m.db == nil {
		return
	}
	ftbl := m.db.Table("findings")
	ctbl := m.db.Table("certs")
	now := time.Now().Format(time.RFC3339)

	if err := m.db.WithTx(func(tx core.DB) error {
		if _, err := tx.Exec("DELETE FROM "+ftbl+" WHERE task_id=?", taskID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM "+ctbl+" WHERE task_id=?", taskID); err != nil {
			return err
		}
		for _, r := range results {
			if r.Cert != nil {
				cd := r.Cert
				sans := strings.Join(cd.SANs, ",")
				if _, err := tx.Exec(
					"INSERT OR REPLACE INTO "+ctbl+
						" (id,task_id,host,port,subject,issuer,not_before,not_after,days_left,"+
						"key_type,key_bits,sig_algo,sans,tls_version,cipher,hsts,self_signed,scan_err,found_at)"+
						" VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
					cd.ID, taskID, cd.Host, cd.Port, cd.Subject, cd.Issuer,
					cd.NotBefore.Format(time.RFC3339), cd.NotAfter.Format(time.RFC3339), cd.DaysLeft,
					cd.KeyType, cd.KeyBits, cd.SigAlgo, sans,
					cd.TLSVersion, cd.Cipher, cd.HSTS, boolInt(cd.SelfSigned), r.ScanErr, now,
				); err != nil {
					m.log.Warn("ssl-audit cert insert failed", "task", taskID, "host", cd.Host, "err", err)
				}
			}
			for _, f := range r.Findings {
				if _, err := tx.Exec(
					"INSERT OR REPLACE INTO "+ftbl+
						" (id,task_id,host,port,severity,category,label,detail,evidence,found_at)"+
						" VALUES (?,?,?,?,?,?,?,?,?,?)",
					f.ID, taskID, f.Host, f.Port,
					f.Severity, f.Category, f.Label, f.Detail, f.Evidence,
					f.FoundAt.Format(time.RFC3339),
				); err != nil {
					m.log.Warn("ssl-audit finding insert failed", "task", taskID, "id", f.ID, "err", err)
				}
			}
		}
		return nil
	}); err != nil {
		m.log.Warn("ssl-audit saveFindings tx failed", "task", taskID, "err", err)
	}
}

// findingRow 是归档发现的对外 JSON 形态。
type findingRow struct {
	ID       string `json:"id"`
	TaskID   string `json:"taskId"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Label    string `json:"label"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	FoundAt  string `json:"foundAt"`
}

// certRow 是归档证书的对外 JSON 形态。
type certRow struct {
	ID         string `json:"id"`
	TaskID     string `json:"taskId"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	DaysLeft   int    `json:"daysLeft"`
	KeyType    string `json:"keyType"`
	KeyBits    int    `json:"keyBits"`
	SigAlgo    string `json:"sigAlgo"`
	SANs       []string `json:"sans"`
	TLSVersion string `json:"tlsVersion"`
	Cipher     string `json:"cipher"`
	HSTS       string `json:"hsts"`
	SelfSigned bool   `json:"selfSigned"`
	ScanErr    string `json:"scanErr"`
	FoundAt    string `json:"foundAt"`
}

// listFindings 取某次任务归档的发现与证书：GET /findings?taskId=<id>
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

	ftbl := m.db.Table("findings")
	frows, err := m.db.Query(
		"SELECT id,task_id,host,port,severity,category,label,detail,evidence,found_at"+
			" FROM "+ftbl+" WHERE task_id=?"+
			" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
		taskID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("查询发现失败: %v", err)})
		return
	}
	defer frows.Close()

	findings := make([]findingRow, 0)
	for frows.Next() {
		var f findingRow
		if err2 := frows.Scan(&f.ID, &f.TaskID, &f.Host, &f.Port,
			&f.Severity, &f.Category, &f.Label, &f.Detail, &f.Evidence, &f.FoundAt); err2 != nil {
			continue
		}
		findings = append(findings, f)
	}
	if err := frows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("遍历发现失败: %v", err)})
		return
	}

	ctbl := m.db.Table("certs")
	crows, err := m.db.Query(
		"SELECT id,task_id,host,port,subject,issuer,not_before,not_after,days_left,"+
			"key_type,key_bits,sig_algo,sans,tls_version,cipher,hsts,self_signed,scan_err,found_at"+
			" FROM "+ctbl+" WHERE task_id=? ORDER BY host",
		taskID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "certs": []certRow{}})
		return
	}
	defer crows.Close()

	certs := make([]certRow, 0)
	for crows.Next() {
		var c certRow
		var selfSign int
		var sansStr string
		if err2 := crows.Scan(&c.ID, &c.TaskID, &c.Host, &c.Port,
			&c.Subject, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.DaysLeft,
			&c.KeyType, &c.KeyBits, &c.SigAlgo, &sansStr,
			&c.TLSVersion, &c.Cipher, &c.HSTS, &selfSign, &c.ScanErr, &c.FoundAt); err2 != nil {
			continue
		}
		c.SelfSigned = selfSign != 0
		if sansStr != "" {
			c.SANs = strings.Split(sansStr, ",")
		} else {
			c.SANs = []string{}
		}
		certs = append(certs, c)
	}
	if err := crows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("遍历证书失败: %v", err)})
		return
	}

	// items = security findings (兼容 AEGIS 统一台账; findings/certs 保留向后兼容)
	writeJSON(w, http.StatusOK, map[string]any{"items": findings, "findings": findings, "certs": certs})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
