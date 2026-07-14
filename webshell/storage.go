package webshell

import (
	"database/sql"
	"fmt"
	"time"

	"redops/core"
)

type shellRecord struct {
	ID            string  `json:"id"`
	URL           string  `json:"url"`
	ShellType     string  `json:"shellType"`
	Protocol      string  `json:"protocol"`
	CustomHeaders string  `json:"customHeaders"`
	Password      string  `json:"password,omitempty"`
	Note          string  `json:"note"`
	Status        string  `json:"status"`
	OSInfo        string  `json:"osInfo"`
	ServerInfo    string  `json:"serverInfo"`
	PHPVersion    string  `json:"phpVersion"`
	CWD           string  `json:"cwd"`
	RunUser       string  `json:"runUser"`
	Hostname      string  `json:"hostname"`
	ServerIP      string  `json:"serverIp"`
	CreatedAt     string  `json:"createdAt"`
	LastSeen      *string `json:"lastSeen"`
}

type shellStore struct {
	db core.DB
}

func newShellStore(db core.DB) *shellStore {
	return &shellStore{db: db}
}

func (s *shellStore) list() ([]shellRecord, error) {
	rows, err := s.db.Query(
		"SELECT id,url,shell_type,protocol,custom_headers,note,status,os_info,server_info,php_version,cwd,run_user,hostname,server_ip,created_at,last_seen FROM "+
			s.db.Table("shells")+" ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shells []shellRecord
	for rows.Next() {
		var sh shellRecord
		var lastSeen sql.NullString
		if err := rows.Scan(&sh.ID, &sh.URL, &sh.ShellType, &sh.Protocol, &sh.CustomHeaders, &sh.Note, &sh.Status,
			&sh.OSInfo, &sh.ServerInfo, &sh.PHPVersion, &sh.CWD, &sh.RunUser,
			&sh.Hostname, &sh.ServerIP, &sh.CreatedAt, &lastSeen); err != nil {
			continue
		}
		if lastSeen.Valid {
			sh.LastSeen = &lastSeen.String
		}
		shells = append(shells, sh)
	}
	if shells == nil {
		shells = []shellRecord{}
	}
	return shells, nil
}

func (s *shellStore) get(id string) (*shellRecord, error) {
	row := s.db.QueryRow(
		"SELECT id,url,shell_type,protocol,custom_headers,password,note,status,os_info,server_info,php_version,cwd,run_user,hostname,server_ip,created_at,last_seen FROM "+
			s.db.Table("shells")+" WHERE id=?", id,
	)
	var sh shellRecord
	var lastSeen sql.NullString
	err := row.Scan(&sh.ID, &sh.URL, &sh.ShellType, &sh.Protocol, &sh.CustomHeaders, &sh.Password, &sh.Note, &sh.Status,
		&sh.OSInfo, &sh.ServerInfo, &sh.PHPVersion, &sh.CWD, &sh.RunUser,
		&sh.Hostname, &sh.ServerIP, &sh.CreatedAt, &lastSeen)
	if err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		sh.LastSeen = &lastSeen.String
	}
	// 解密密码（兼容旧的明文记录）
	if sh.Password, err = shellPWDecrypt(sh.Password); err != nil {
		return nil, fmt.Errorf("密码解密失败: %w", err)
	}
	return &sh, nil
}

func (s *shellStore) add(sh *shellRecord) error {
	encPW, err := shellPWEncrypt(sh.Password)
	if err != nil {
		return fmt.Errorf("密码加密失败: %w", err)
	}
	_, err = s.db.Exec(
		"INSERT INTO "+s.db.Table("shells")+
			"(id,url,shell_type,protocol,custom_headers,password,note,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
		sh.ID, sh.URL, sh.ShellType, sh.Protocol, sh.CustomHeaders, encPW, sh.Note, "unknown",
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func (s *shellStore) updateInfo(id string, info *SysInfo, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		"UPDATE "+s.db.Table("shells")+
			" SET status=?,os_info=?,server_info=?,php_version=?,cwd=?,run_user=?,hostname=?,server_ip=?,last_seen=? WHERE id=?",
		status, info.OS, info.Server, info.PHP, info.CWD, info.User, info.Hostname, info.IP, now, id,
	)
	return err
}

func (s *shellStore) updateStatus(id, status string) error {
	_, err := s.db.Exec(
		"UPDATE "+s.db.Table("shells")+" SET status=? WHERE id=?", status, id,
	)
	return err
}

func (s *shellStore) updateNote(id, note string) error {
	_, err := s.db.Exec(
		"UPDATE "+s.db.Table("shells")+" SET note=? WHERE id=?", note, id,
	)
	return err
}

func (s *shellStore) delete(id string) error {
	_, err := s.db.Exec("DELETE FROM "+s.db.Table("shells")+" WHERE id=?", id)
	return err
}
