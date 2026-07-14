package backup

// dict.go —— 备份/敏感文件字典与候选 URL 生成。
//
// 字典素材内嵌自业界知名词表(SecLists, danielmiessler)与 OWASP WSTG-CONF-04
// 「为每个已知文件名生成备份变体」的方法论:
//   - wordlists/db-backups.txt  数据库 / 全站导出备份名 (SecLists Common-DB-Backups)
//   - wordlists/sensitive.txt   敏感文件 / 配置 / VCS 泄露固定路径
//   - wordlists/archives.txt    通用归档「基名」,运行时 × 归档扩展名展开
// 此外按目标主机名 / URL 自身文件名动态派生候选(域名拼接归档、文件名套备份后缀)。

import (
	_ "embed"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func itoa(n int) string { return strconv.Itoa(n) }

//go:embed wordlists/db-backups.txt
var rawDBBackups string

//go:embed wordlists/sensitive.txt
var rawSensitive string

//go:embed wordlists/archives.txt
var rawArchives string

//go:embed wordlists/common.txt
var rawCommon string

//go:embed wordlists/raft-medium-files.txt
var rawRaftMediumFiles string

//go:embed wordlists/raft-medium-dirs.txt
var rawRaftMediumDirs string

// 归档扩展名 —— 与 archives.txt 基名、主机名做笛卡尔积。
var archiveExts = []string{".zip", ".rar", ".tar.gz", ".tar.bz2", ".7z", ".tgz", ".gz", ".tar"}

// 编辑器 / 部署遗留后缀 —— 套在「目标 URL 自身文件名」或常见入口页上 (OWASP)。
var editorSuffixes = []string{"~", ".bak", ".old", ".orig", ".save", ".swp", ".tmp", ".copy", ".inc", ".1", ".2", ".000"}

// ---- 组合式「带日期/版本」备份候选 ----
// 实战中大量备份以「基名+年份」命名(db_2024.sql / backup-2025.zip / {host}2023.tar.gz)。
// 用紧凑的基名 × 年份 × 分隔符 × 扩展名矩阵在运行时展开,以极小的维护成本换巨大的覆盖面。
var datedBases = []string{
	"backup", "www", "web", "site", "db", "database", "dump",
	"data", "sql", "release", "full", "wwwroot", "app", "old",
}
var datedYears = []string{"2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026"}
var dateSeps = []string{"", "_", "-"}
var datedExts = []string{".zip", ".rar", ".tar.gz", ".7z", ".sql", ".bak", ".gz", ".tar"}

// datedCount 是「带日期」矩阵的静态规模(不含按主机派生部分),供 dictInfo 展示。
var datedCount = len(datedBases) * len(datedYears) * len(dateSeps) * len(datedExts)

// genDatedCandidates 为目标生成「基名/主机名 × 年份 × 分隔符 × 扩展名」的带日期备份候选。
func genDatedCandidates(u *url.URL) []candidate {
	bases := append([]string(nil), hostTokens(u)...) // 主机名派生的带日期归档命中率尤高,排最前
	bases = append(bases, datedBases...)
	out := make([]candidate, 0, len(bases)*len(datedYears)*len(dateSeps)*len(datedExts))
	for _, base := range bases {
		for _, y := range datedYears {
			for _, sep := range dateSeps {
				for _, ext := range datedExts {
					rel := base + sep + y + ext
					out = append(out, candidate{rel: rel, rule: "带日期备份: " + base + sep + y + "{ext}", kind: classifyKind(rel, "", "")})
				}
			}
		}
	}
	return out
}

// 目标只给了域名(无具体文件)时,对这些常见入口页套编辑器后缀探测源码泄露。
var commonPages = []string{"index.php", "index.html", "index.aspx", "index.jsp", "config.php", "login.php", "admin.php", "web.config", "default.aspx", "global.asax"}

func parseList(raw string) []string {
	var out []string
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

var (
	dictDB               = parseList(rawDBBackups)        // 数据库 / 全站导出
	dictSensitive        = parseList(rawSensitive)        // 敏感文件 / 配置 / VCS
	dictArchBase         = parseList(rawArchives)         // 归档基名
	dictCommon           = parseList(rawCommon)           // 常见 Web 路径(管理入口/CMS/框架/API)
	dictRaftMediumFiles  = parseList(rawRaftMediumFiles)  // raft-medium-files 内嵌精选
	dictRaftMediumDirs   = parseList(rawRaftMediumDirs)   // raft-medium-directories 内嵌精选
)

// embeddedPreset 返回已内嵌二进制的预置字典，无需网络下载。
func embeddedPreset(name string) ([]string, bool) {
	switch name {
	case "raft-medium-files":
		return dictRaftMediumFiles, true
	case "raft-medium-dirs":
		return dictRaftMediumDirs, true
	}
	return nil, false
}

// candidate 是一个待探测的相对路径 + 元信息。
type candidate struct {
	rel   string // 站点根相对路径,如 "backup.zip" / ".git/config" / "app/config.php.bak"
	rule  string // 命中规则(展示用)
	kind  string // 预判类型(探测时可被魔数 / Content-Type 纠正)
	isDir bool   // true=目录存在性探测(命中则驱动递归),不计为文件命中
}

// genCandidates 为单个目标 URL 生成去重后的候选列表(按价值排序后截断到 maxPerHost)。
func genCandidates(u *url.URL, maxPerHost int, includeEditor bool) []candidate {
	if maxPerHost <= 0 {
		maxPerHost = 800
	}
	var ordered []candidate

	// 1) 敏感文件 / 配置 / VCS —— 价值高、数量小,优先。
	for _, p := range dictSensitive {
		ordered = append(ordered, candidate{rel: p, rule: "敏感文件字典: " + p, kind: classifyKind(p, "", "")})
	}

	// 1b) 常见 Web 路径(管理入口/CMS/框架/API/调试端点) —— 覆盖面宽,紧跟高价值敏感文件。
	for _, p := range dictCommon {
		ordered = append(ordered, candidate{rel: p, rule: "常见路径字典: " + p, kind: classifyKind(p, "", "")})
	}

	// 2) 主机名派生归档 —— 「域名.zip」类,实战命中率高。
	for _, tok := range hostTokens(u) {
		for _, ext := range archiveExts {
			rel := tok + ext
			ordered = append(ordered, candidate{rel: rel, rule: "主机名派生: {host}" + ext, kind: "源码"})
		}
	}

	// 3) 数据库 / 全站导出备份名。
	for _, p := range dictDB {
		ordered = append(ordered, candidate{rel: p, rule: "数据库备份字典: " + p, kind: classifyKind(p, "", "")})
	}

	// 4) 通用归档基名 × 扩展名(backup.zip / www.tar.gz 等经典高价值名,
	// 必须排在体量巨大的「带日期」组合之前,否则默认预算下会被挤出而漏扫)。
	for _, b := range dictArchBase {
		for _, ext := range archiveExts {
			rel := b + ext
			ordered = append(ordered, candidate{rel: rel, rule: "归档字典: " + b + "{ext}", kind: "源码"})
		}
	}

	// 5) 带日期 / 版本的备份(主机名/基名 × 年份 × 分隔符 × 扩展名)—— 命中率高但体量大,
	// 故排在经典归档名之后,用以填充剩余预算(主机名带日期在该组内最前)。
	ordered = append(ordered, genDatedCandidates(u)...)

	// 6) 编辑器 / 部署遗留后缀(套在 URL 自身文件名或常见入口页上)。
	if includeEditor {
		for _, rel := range editorBackupTargets(u) {
			ordered = append(ordered, candidate{rel: rel, rule: "编辑器遗留: " + path.Base(rel), kind: classifyKind(rel, "", "")})
		}
	}

	// 去重 + 截断。
	seen := make(map[string]struct{}, len(ordered))
	out := make([]candidate, 0, len(ordered))
	for _, c := range ordered {
		key := strings.ToLower(strings.TrimPrefix(c.rel, "/"))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
		if len(out) >= maxPerHost {
			break
		}
	}
	return out
}

// hostTokens 从主机名派生归档基名: www.bank-corp.com -> {www.bank-corp.com, bank-corp.com, bank-corp}。
// 纯 IP 主机不派生(八位组拼接无意义)。
func hostTokens(u *url.URL) []string {
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	set := map[string]struct{}{host: {}}
	h := strings.TrimPrefix(host, "www.")
	set[h] = struct{}{}
	labels := strings.Split(h, ".")
	if len(labels) > 0 && labels[0] != "" {
		set[labels[0]] = struct{}{} // 主标签: bank-corp
	}
	if len(labels) >= 2 {
		set[strings.Join(labels[:len(labels)-1], ".")] = struct{}{} // 去 TLD: bank-corp(单段时与上同)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

// editorBackupTargets 针对目标 URL 自身的文件名(若有)套编辑器后缀;
// 若目标只给了域名 / 目录,则对常见入口页套后缀。
func editorBackupTargets(u *url.URL) []string {
	dir, file := path.Split(strings.TrimPrefix(u.Path, "/"))
	var bases []struct{ d, f string }
	if file != "" && strings.Contains(file, ".") {
		bases = append(bases, struct{ d, f string }{dir, file})
	} else {
		for _, p := range commonPages {
			bases = append(bases, struct{ d, f string }{dir, p})
		}
	}
	var out []string
	for _, b := range bases {
		for _, suf := range editorSuffixes {
			out = append(out, b.d+b.f+suf) // 文件名后缀: config.php.bak / config.php~
		}
	}
	return out
}

// classifyKind 依路径 / Content-Type / 魔数标签判定文件类型。
// 魔数优先(最可靠),其次路径特征,最后 Content-Type 兜底。
func classifyKind(rel, ctype, magic string) string {
	switch magic {
	case "zip", "rar", "7z", "gzip", "bzip2", "tar":
		return "源码"
	case "sqlite":
		return "数据库"
	case "git-config", "pem", "php":
		return "配置"
	}
	lp := strings.ToLower(rel)
	switch {
	case containsAny(lp, ".git/", ".svn/", ".hg/", ".bzr/", "cvs/"),
		containsAny(lp, ".env", "config", ".htaccess", ".htpasswd", "web.xml", "web.config",
			"credentials", "id_rsa", "id_dsa", "id_ecdsa", "secrets", ".yml", ".yaml",
			".properties", ".ini", ".netrc", ".npmrc", ".pgpass", "settings", "appsettings",
			"dockerfile", "docker-compose", "pom.xml", "build.gradle", ".pem"):
		// .json 不在此列：纯数据接口响应也以 .json 结尾，泛匹配会把低风险数据文件误升为「配置」。
		// config*.json / settings*.json 等已被上方 "config"/"settings" 子串匹配兜住。
		return "配置"
	case containsAny(lp, ".sql", "dump", "mysql", ".sqlite", ".mdb"), strings.HasSuffix(lp, ".db"):
		return "数据库"
	}
	for _, e := range archiveExts {
		if strings.HasSuffix(lp, e) {
			return "源码"
		}
	}
	switch {
	case containsAny(ctype, "zip", "x-rar", "gzip", "x-7z", "x-tar", "octet-stream"):
		return "源码"
	case strings.Contains(ctype, "sql"):
		return "数据库"
	}
	return "其它"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// dictInfo 给 /dict 端点 —— 暴露字典规模与来源。
func dictInfo() map[string]any {
	return map[string]any{
		"categories": []map[string]any{
			{"key": "sensitive", "label": "敏感文件 / 配置 / VCS 泄露", "count": len(dictSensitive)},
			{"key": "common", "label": "常见 Web 路径 (管理入口/CMS/框架/API)", "count": len(dictCommon)},
			{"key": "raft-medium-files", "label": "raft-medium-files 内嵌精选（常见文件名）", "count": len(dictRaftMediumFiles)},
			{"key": "raft-medium-dirs", "label": "raft-medium-dirs 内嵌精选（常见目录名）", "count": len(dictRaftMediumDirs)},
			{"key": "db", "label": "数据库 / 全站导出 (SecLists Common-DB-Backups)", "count": len(dictDB)},
			{"key": "archive", "label": "通用归档基名 × " + itoa(len(archiveExts)) + " 扩展名", "count": len(dictArchBase) * len(archiveExts)},
			{"key": "dated", "label": "带日期/版本备份 (基名 × " + itoa(len(datedYears)) + " 年 × " + itoa(len(dateSeps)) + " 分隔 × " + itoa(len(datedExts)) + " 扩展)", "count": datedCount},
			{"key": "editor", "label": "编辑器 / 部署遗留后缀 (OWASP)", "count": len(editorSuffixes)},
		},
		"embedded": map[string]int{
			"raft-medium-files": len(dictRaftMediumFiles),
			"raft-medium-dirs":  len(dictRaftMediumDirs),
		},
		"baseEntries":    len(dictSensitive) + len(dictCommon) + len(dictDB) + len(dictArchBase)*len(archiveExts) + datedCount,
		"archiveExts":    archiveExts,
		"editorSuffixes": editorSuffixes,
		"sources":        []string{"SecLists (danielmiessler/SecLists)", "OWASP WSTG-CONF-04"},
	}
}
