package scandir

// dict.go —— 内置字典注册表、%EXT% 占位符展开、运行时外部字典加载与目标/路径规范化。
//
// 字典体系参考业界主流目录扫描工具(dirsearch / ffuf / feroxbuster / gobuster / dirb):
//
//   内置字典(随引擎编译,见 wordlists/,均取自权威上游):
//     - common      SecLists Discovery/Web-Content/common.txt(经典 dirb/common,~4.7k)
//     - dirsearch   dirsearch 默认 db/dicc.txt(~9.6k,含 %EXT% 占位符)
//     - quickhits   SecLists quickhits.txt(高价值敏感/泄露文件,~2.5k)
//     - api         SecLists api/api-endpoints.txt(API 端点)
//     - raft-files  SecLists raft-medium-files.txt(RAFT 文件族,~17k)
//     - raft-dirs   SecLists raft-medium-directories.txt(RAFT 目录族,~30k)
//
//   外部字典(运行时投放,无须重编译):把任意 .txt 丢进 data/scan-dir/wordlists/,
//     即以 id "file:<名>" 出现在可选列表。便于直接接入 SecLists 的
//     directory-list-2.3-medium、OneListForAll、ffuf/feroxbuster 自带等超大字典。
//
//   占位符:遵循 dirsearch 约定——词条中的 %EXT% 会被「扩展名」逐个替换;
//     无占位符的「目录型」词条(不含 '.')则按 force-extensions 追加每个扩展名(等价 ffuf 的
//     -e / dirsearch 的 -f)。已含扩展名的具体文件名原样保留。

import (
	"embed"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//go:embed wordlists/*.txt
var wordlistsFS embed.FS

// userWordlistDir 是运行时外部字典目录(相对引擎 cwd)。把 .txt 丢进来即可被加载。
const userWordlistDir = "data/scan-dir/wordlists"

// builtinDef 描述一个内置字典:id、展示名、来源说明、嵌入文件名。
type builtinDef struct {
	id     string
	label  string
	source string
	file   string
}

// builtins 是内置字典注册表(展示顺序即此顺序:由小到大、由精到全)。
var builtins = []builtinDef{
	{"combined", "【最强默认】全合并(quickhits+api+spring-boot+国内+common)", "5个专项字典去重合并，覆盖最广", ""},
	{"quickhits", "QuickHits(敏感/泄露文件)", "SecLists quickhits.txt", "wordlists/quickhits.txt"},
	{"api", "API 端点", "SecLists api/api-endpoints.txt", "wordlists/api-endpoints.txt"},
	{"spring-boot", "Spring Boot(Actuator/Swagger/H2)", "实战 Spring Boot 常见暴露路径", "wordlists/spring-boot.txt"},
	{"china-cms", "国内CMS/OA/中间件", "ThinkPHP/通达OA/泛微OA/致远OA/Nacos/Dubbo等高频路径", "wordlists/china-cms.txt"},
	{"common", "Common(经典通用)", "SecLists common.txt(含 dirb)", "wordlists/seclists-common.txt"},
	{"dirsearch", "dirsearch(含 %EXT%)", "dirsearch db/dicc.txt", "wordlists/dirsearch.txt"},
	{"raft-files", "RAFT 文件族", "SecLists raft-medium-files.txt", "wordlists/raft-medium-files.txt"},
	{"raft-dirs", "RAFT 目录族", "SecLists raft-medium-directories.txt", "wordlists/raft-medium-directories.txt"},
}

// rawCache 缓存已解析的字典模板,避免重复解析大字典。
var (
	rawCache = map[string][]string{}
	cacheMu  sync.RWMutex
)

// combinedSubIDs 是 "combined" 虚拟字典的合并来源(按优先级排列:高价值在前)。
// 包含全部内置字典，去重后一次扫描覆盖最大路径集合。
var combinedSubIDs = []string{
	"quickhits",   // 高价值敏感/泄露文件（最高优先级）
	"api",         // API 端点
	"spring-boot", // Spring Boot Actuator/Swagger/H2
	"china-cms",   // 国内 CMS/OA/中间件
	"common",      // 经典通用路径
	"dirsearch",   // dirsearch 默认字典（含 %EXT% 模板，无扩展名时跳过）
	"raft-files",  // RAFT 文件族
	"raft-dirs",   // RAFT 目录族
}

// loadCombined 去重合并 combinedSubIDs 中的所有字典模板,结果写入缓存后返回。
// 调用时 cacheMu 不得持锁(内部会重新加锁写缓存)。
func loadCombined() ([]string, bool) {
	seen := make(map[string]struct{})
	var out []string
	for _, sub := range combinedSubIDs {
		tpl, ok := loadTemplates(sub)
		if !ok {
			continue
		}
		for _, t := range tpl {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	cacheMu.Lock()
	rawCache["combined"] = out
	cacheMu.Unlock()
	return out, true
}

// loadTemplates 按字典 id 返回其原始「模板词条」(去注释/空行/去重,保留 %EXT% 占位符)。
// id 形如内置 id(如 "dirsearch")、虚拟合并 id "combined"、或外部 "file:<名>"。
// 未知 id 返回 nil,false。
func loadTemplates(id string) ([]string, bool) {
	cacheMu.RLock()
	if v, ok := rawCache[id]; ok {
		cacheMu.RUnlock()
		return v, true
	}
	cacheMu.RUnlock()

	// 虚拟合并字典：运行时去重合并多个专项字典，无对应嵌入文件。
	if id == "combined" {
		return loadCombined()
	}

	var raw string
	var found bool
	if strings.HasPrefix(id, "file:") {
		name := strings.TrimPrefix(id, "file:")
		if safeWordlistName(name) {
			if b, err := os.ReadFile(filepath.Join(userWordlistDir, name)); err == nil {
				raw, found = string(b), true
			}
		}
	} else {
		for _, d := range builtins {
			if d.id == id {
				if b, err := wordlistsFS.ReadFile(d.file); err == nil {
					raw, found = string(b), true
				}
				break
			}
		}
	}
	if !found {
		return nil, false
	}
	tpl := parseWordlist(raw)
	cacheMu.Lock()
	rawCache[id] = tpl
	cacheMu.Unlock()
	return tpl, true
}

// safeWordlistName 防目录穿越:外部字典名仅允许基名 .txt。
func safeWordlistName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return false
	}
	return strings.HasSuffix(strings.ToLower(name), ".txt")
}

// parseWordlist 把原始词表文本解析为有序、去重的模板词条(忽略注释/空行,去前导斜杠)。
func parseWordlist(raw string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 4096)
	for _, ln := range strings.Split(raw, "\n") {
		w := strings.TrimRight(ln, "\r")
		w = strings.TrimSpace(w)
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		w = strings.TrimPrefix(w, "/")
		if w == "" {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

// diskWordlistMeta 描述一个外部字典(展示用)。
type diskWordlistMeta struct {
	id    string
	label string
}

// diskWordlists 列出 userWordlistDir 下的 .txt 外部字典(best-effort,目录不存在则空)。
func diskWordlists() []diskWordlistMeta {
	entries, err := os.ReadDir(userWordlistDir)
	if err != nil {
		return nil
	}
	out := make([]diskWordlistMeta, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !safeWordlistName(name) {
			continue
		}
		out = append(out, diskWordlistMeta{id: "file:" + name, label: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out
}

// dictInfo 暴露全部可用字典(内置 + 外部)及规模/来源,供前端动态渲染选择器。
func dictInfo() map[string]any {
	type entry struct {
		ID     string `json:"id"`
		Label  string `json:"label"`
		Source string `json:"source"`
		Count  int    `json:"count"`
	}
	lists := make([]entry, 0, len(builtins)+4)
	for _, d := range builtins {
		n := 0
		if tpl, ok := loadTemplates(d.id); ok {
			n = len(tpl)
		}
		lists = append(lists, entry{ID: d.id, Label: d.label, Source: d.source, Count: n})
	}
	for _, d := range diskWordlists() {
		n := 0
		if tpl, ok := loadTemplates(d.id); ok {
			n = len(tpl)
		}
		lists = append(lists, entry{ID: d.id, Label: d.label + "(外部)", Source: userWordlistDir, Count: n})
	}
	return map[string]any{
		"lists":          lists,
		"userDir":        userWordlistDir,
		"placeholderTag": "%EXT%",
	}
}

// parseExtensions 解析「扩展名」输入(逗号/空白分隔),规整为不带前导点的小写切片;空输入返回空。
func parseExtensions(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		e := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(f, ".")))
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

// expandTemplates 把模板词条按扩展名展开为最终探测路径(参考 dirsearch / ffuf 约定):
//   - 含 %EXT% 占位符:对每个扩展名替换一次(无扩展名则丢弃该条)。
//   - 不含占位符且不含 '.'(目录/基名):保留原条目(作目录探测),并为每个扩展名追加 base.ext。
//   - 已含 '.' 的具体文件名(index.php、.env):原样保留,不再追加扩展名。
//
// 例:["index.%EXT%","admin","backup.zip"] × [php,bak]
//   → index.php, index.bak, admin, admin.php, admin.bak, backup.zip
func expandTemplates(templates, exts []string) []string {
	out := make([]string, 0, len(templates)*(1+len(exts)))
	seen := make(map[string]struct{})
	add := func(w string) {
		if w == "" {
			return
		}
		if _, ok := seen[w]; ok {
			return
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	for _, t := range templates {
		if strings.Contains(t, "%EXT%") {
			for _, e := range exts {
				add(strings.ReplaceAll(t, "%EXT%", e))
			}
			continue
		}
		add(t)
		if strings.Contains(t, ".") {
			continue // 已是具体文件名
		}
		for _, e := range exts {
			add(t + "." + e)
		}
	}
	return out
}

// normalizeTarget 把单个目标整理成可爆破的「基 URL」(以 / 结尾)。
// 支持 host、host:port、http(s)://host[:port][/sub]。无 scheme 默认 http。
// 用户给定的子路径会被保留为爆破基(在其之下拼词条)。
func normalizeTarget(raw string) (string, bool) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", false
	}
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	u.Path = p
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), true
}

// joinURL 在以 / 结尾的基 URL 之下拼接相对路径(去掉相对路径的前导 /)。
func joinURL(base, rel string) string {
	return base + strings.TrimPrefix(rel, "/")
}
