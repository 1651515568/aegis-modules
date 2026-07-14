package scandir

// classify.go —— 命中路径的敏感度分级。
//
// 目录爆破的价值在于「命中里哪些值得立刻看」。这里按路径/扩展名特征把命中分到
// critical/high/medium/low/info,并给一句中文 kind 说明,供前端高亮与分诊排序。
// 规则按严重度从高到低匹配,首个命中即返回(与 SeverityTag 的取值对齐)。

import "strings"

// classify 依据相对路径(小写化后)判定命中的敏感度与类别。
func classify(path string) (severity, kind string) {
	p := strings.ToLower(path)
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
	}
	hasAny := func(ss ...string) bool {
		for _, s := range ss {
			if strings.Contains(p, s) {
				return true
			}
		}
		return false
	}
	suffixAny := func(ss ...string) bool {
		for _, s := range ss {
			if strings.HasSuffix(base, s) {
				return true
			}
		}
		return false
	}

	switch {
	// critical:源码/凭证/数据库泄露——直接高危
	case hasAny("/.git/", "/.svn/", "/.hg/", "/.bzr/") || base == ".git" || base == ".svn":
		return "critical", "版本控制目录泄露(可能可还原源码)"
	case base == ".env" || strings.HasPrefix(base, ".env.") || hasAny("/.env"):
		return "critical", "环境变量文件(常含密钥/口令)"
	case hasAny("id_rsa", "id_dsa", "/.ssh/", ".ppk", "id_ed25519"):
		return "critical", "SSH/私钥文件"
	case base == ".htpasswd" || hasAny("/.aws/credentials", "/.aws/config"):
		return "critical", "凭证文件"
	case suffixAny(".sql", ".sql.gz", ".sql.zip", ".dump", ".bak.sql"):
		return "critical", "数据库导出/备份"
	case suffixAny(".bak", ".old", ".save", ".orig", ".swp", "~", ".tmp") ||
		suffixAny(".zip", ".tar.gz", ".tgz", ".tar", ".rar", ".7z", ".gz"):
		return "critical", "备份/归档文件(可能含源码或数据)"
	case base == "wp-config.php" || base == "web.config" || base == "configuration.php" ||
		base == "settings.py" || base == "database.yml" || base == ".dockercfg":
		return "critical", "含敏感配置的配置文件"

	// high:管理面/调试/敏感配置入口
	// 调试端点先匹配：包含 phpinfo/actuator 的路径（如 /admin/actuator）
	// 应归入"调试/信息泄露"而非"管理后台"，避免分类混淆。
	case hasAny("phpinfo", "/server-status", "/server-info", "/actuator", "/_profiler", "/debug", "/trace"):
		return "high", "调试/信息泄露端点"
	case hasAny("/admin", "/manager", "/console", "/dashboard", "/phpmyadmin", "/pma", "/adminer") || base == "admin.php":
		return "high", "管理后台/控制台入口"
	case hasAny("/swagger", "/api-docs", "/openapi", "/graphql", "/graphiql"):
		return "high", "API 文档/调试接口"
	case suffixAny(".config", ".conf", ".ini", ".yml", ".yaml", ".properties", ".pem", ".key", ".crt") ||
		base == "config.php" || base == "config.json":
		return "high", "配置/证书文件"
	case base == ".ds_store" || base == ".htaccess" || base == "robots.txt" || base == "sitemap.xml" ||
		hasAny("/.well-known/security.txt"):
		return "medium", "信息泄露(目录/路径线索)"

	// medium:认证/上传/接口面
	case hasAny("/login", "/logout", "/register", "/signin", "/auth", "/upload", "/api/", "/api2", "/v1/", "/v2/"):
		return "medium", "认证/上传/接口端点"
	case suffixAny(".log", ".txt", ".json", ".xml", ".csv"):
		return "low", "文本/数据文件"
	}
	return "info", ""
}

// sevRank 给严重度一个可排序权重(高在前)。
func sevRank(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
