package backup

// classify.go —— 命中结果的研判 / 文案生成(把一次真实探测转成可复盘的 Hit 字段)。

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"
)

func nowStamp() string { return time.Now().Format("2006-01-02 15:04") }

func hitID(host, rel string) string {
	sum := sha1.Sum([]byte(host + "|" + rel))
	// 8 字节（64 bit）：生日碰撞概率 ~50% 需要 2^32 条目，远高于单次扫描规模，可忽略。
	return "bk-" + hex.EncodeToString(sum[:8])
}

// fileLabel 取相对路径里有意义的文件名/目录名用于展示。
func fileLabel(rel string) string {
	rel = strings.TrimPrefix(rel, "/")
	if strings.Contains(rel, "/") {
		// .git/config -> .git/ ; app/config.php.bak -> config.php.bak
		if strings.HasPrefix(rel, ".") {
			parts := strings.SplitN(rel, "/", 2)
			return parts[0] + "/"
		}
		return path.Base(rel)
	}
	return rel
}

func humanSize(n int64) string {
	if n < 0 {
		return "—"
	}
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	f := float64(n)
	i := -1
	for f >= u && i < len(units)-1 {
		f /= u
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// severityFor —— 风险定级。受限(>=300,如 403)统一中危;可访问按类型定级。
func severityFor(kind string, code int, rel string) string {
	if code >= 300 {
		return "中危"
	}
	lp := strings.ToLower(rel)
	switch kind {
	case "数据库", "源码":
		return "高危"
	case "配置":
		if containsAny(lp, ".env", ".git", ".svn", "id_rsa", "id_dsa", "credentials",
			"secrets", ".pgpass", ".netrc", "wp-config", "config.php", "database.yml", ".pem") {
			return "高危"
		}
		return "中危"
	default:
		return "低危"
	}
}

func noteFor(kind string, protected bool) string {
	if protected {
		return "资源存在但访问受限(403/401),待评估"
	}
	switch kind {
	case "数据库":
		return "可访问的数据库 / 全站导出,疑似含业务数据"
	case "源码":
		return "可访问的源码 / 整站归档备份"
	case "配置":
		return "可访问的配置 / 凭据文件,疑似含敏感信息"
	default:
		return "可访问的疑似备份 / 临时文件"
	}
}

func detailFor(kind string, protected bool) string {
	base := map[string]string{
		"数据库": "命中数据库导出 / 备份文件。此类文件常含完整用户、交易或配置数据,泄露危害极高。",
		"源码":  "命中源码 / 整站归档备份。可还原服务端逻辑,进而暴露二次漏洞与硬编码凭据。",
		"配置":  "命中配置 / 凭据 / 版本控制文件。常含数据库连接串、AK/SK、密钥等敏感信息。",
		"其它":  "命中疑似备份 / 临时归档文件,需结合文件名与上下文进一步评估。",
	}[kind]
	if base == "" {
		base = "命中疑似敏感文件。"
	}
	if protected {
		return base + " 本次探测得到 401/403(资源存在但受限),仅记录存在性,未尝试任何鉴权或路径绕过。"
	}
	return base + " 本次仅通过 HEAD / Range 确认存在并读取头部魔数,未下载文件体、未还原任何内容。"
}

func sampleFor(magic, ctype string, protected bool) string {
	if protected {
		return "[实测] 返回 401/403,资源存在但访问受限;未读取任何内容,未做绕过尝试。"
	}
	id := magic
	if id == "" {
		id = "未读到可识别魔数"
	}
	ct := ctype
	if ct == "" {
		ct = "(无)"
	}
	return fmt.Sprintf("[实测·已脱敏] 魔数=%s · Content-Type=%s;仅读取前 ≤16 字节识别类型,未下载文件体。", id, ct)
}

func evidenceRequest(full, host string, protected bool) string {
	rel := full
	if i := strings.Index(full, "://"); i >= 0 {
		if j := strings.Index(full[i+3:], "/"); j >= 0 {
			rel = full[i+3+j:]
		} else {
			rel = "/"
		}
	}
	if protected {
		return fmt.Sprintf("HEAD %s HTTP/1.1\nHost: %s\nUser-Agent: %s", rel, host, scanUserAgent)
	}
	return fmt.Sprintf("HEAD %s HTTP/1.1\nHost: %s\n(随后) GET %s  Range: bytes=0-15", rel, host, rel)
}

func evidenceResponse(code int, ctype string, clen int64, magic string, protected bool) string {
	ct := ctype
	if ct == "" {
		ct = "—"
	}
	lines := []string{fmt.Sprintf("HTTP/1.1 %d %s", code, statusText(code)), "Content-Type: " + ct}
	if clen >= 0 {
		lines = append(lines, fmt.Sprintf("Content-Length: %d", clen))
	}
	if protected {
		lines = append(lines, "[实测] 状态码表明资源存在但受限 → 标记待评估")
	} else if magic != "" {
		lines = append(lines, "[实测] 头部魔数="+magic+" → 据此判定类型")
	} else {
		lines = append(lines, "[实测] 仅凭状态码 + 类型 + 长度判定存在")
	}
	return strings.Join(lines, "\n")
}

func probeMethodNote(protected bool) string {
	if protected {
		return "HEAD 得到 401/403"
	}
	return "HEAD + Range 魔数确认"
}

func remediationFor(kind, rel string) string {
	lp := strings.ToLower(rel)
	switch {
	case strings.Contains(lp, ".git") || strings.Contains(lp, ".svn") || strings.Contains(lp, ".hg"):
		return "禁止将版本控制目录部署到生产;在 Web 服务器拦截 /.git/、/.svn/ 等路径;改用构建产物部署而非整仓上传。"
	case strings.Contains(lp, ".env"):
		return "立即下线 .env 并轮换其中全部密钥 / 口令;在 Web 服务器拦截 dotfile;敏感配置改由密钥管理服务下发。"
	}
	switch kind {
	case "数据库":
		return "立即下线数据库导出文件并评估泄露影响;导出文件禁止置于 Web 目录;落地加密 + 访问审计;视情况启动数据泄露应急。"
	case "源码":
		return "从 Web 根目录移除打包文件;禁止将备份产物置于可对外访问目录;在反代 / WAF 拦截 .zip/.rar/.tar.gz 等归档后缀直接访问。"
	case "配置":
		return "删除暴露的配置 / 编辑器遗留文件;轮换其中疑似暴露的口令与密钥;在服务器禁止以文本形式返回 .bak/.old/.swp 等后缀。"
	default:
		return "确认该文件为何位于 Web 可达目录并下线;复核目录访问控制与目录列举设置。"
	}
}

func refsFor(kind string) []string {
	common := []string{"OWASP WSTG-CONF-04: Old Backup & Unreferenced Files", "字典: SecLists (danielmiessler)"}
	switch kind {
	case "数据库":
		return append([]string{"OWASP: Sensitive Data Exposure"}, common...)
	case "源码":
		return append([]string{"CWE-540 Source Code Exposure"}, common...)
	case "配置":
		return append([]string{"CWE-538 File and Directory Information Exposure"}, common...)
	default:
		return common
	}
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 206:
		return "Partial Content"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 405:
		return "Method Not Allowed"
	default:
		return ""
	}
}
