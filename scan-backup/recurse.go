package backup

// recurse.go —— 递归目录发现。
//
// 思路:扫描中先探测一组「高价值目录」是否存在;对确认存在的目录,再在其下投放一批
// 高价值候选(主机名归档 / 通用归档 / 数据库导出 / 关键敏感文件),并可继续向更深一层
// 递归。整个过程受三道闸约束,防止候选爆炸:
//   1. 仅在「干净 404」站点上递归(soft-404 站点路径判定不可靠,直接关闭递归);
//   2. 每主机一个原子预算(budget),递归新增候选总数封顶;
//   3. 深度上限 MaxDepth(默认 1);同主机候选去重(seen)避免多路径重复探测。

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

// recurseDirs —— 值得探测存在性的目录名(确认存在则在其下递归)。不含 .git 等已由
// sensitive 字典覆盖的 VCS 目录,避免在其下投放无意义候选。
var recurseDirs = []string{
	"backup", "backups", "bak", "old", "new", "temp", "tmp",
	"upload", "uploads", "files", "file", "data", "db", "database",
	"admin", "www", "web", "site", "public", "static", "assets", "media",
	"download", "downloads", "archive", "release", "dist", "build",
	"src", "app", "include", "inc", "conf", "config", "private", "logs",
}

// recurseArchBases —— 递归时在目录下投放的归档基名(精简子集,× archiveExts 展开)。
var recurseArchBases = []string{
	"backup", "www", "web", "site", "db", "data", "dump",
	"release", "old", "full", "backup_db", "wwwroot",
}

// recurseDBNames —— 递归时在目录下投放的数据库导出名(精简子集)。
var recurseDBNames = []string{
	"backup.sql", "dump.sql", "database.sql", "db.sql", "data.sql",
	"backup.sql.gz", "dump.sql.gz", "backup.bak", "db.bak",
}

// recurseSensitive —— 递归时在目录下投放的关键敏感文件(精简子集)。
var recurseSensitive = []string{
	".env", "config.php.bak", "web.config.bak", ".git/config", "wp-config.php.bak",
}

// 递归目录下也投放「近年带日期」备份(子目录里同样常见 backup-2025.zip / db_2024.sql)。
var recurseDatedBases = []string{"backup", "db", "www", "data", "site", "release"}
var recurseDatedYears = []string{"2023", "2024", "2025", "2026"}
var recurseDatedExts = []string{".zip", ".sql", ".tar.gz", ".bak", ".rar"}

// hostCtx 是单个目标在一次扫描中的递归状态(seen 去重 + budget 预算 + 完成计数)。
type hostCtx struct {
	u           *url.URL
	base        baseline
	label       string // host 标签(用于断点续扫标记完成)
	seenMu      sync.Mutex
	seen        map[string]struct{}
	budget      int64 // 原子;递归新增候选可用预算(根候选不消耗)
	outstanding int64 // 原子;该主机未完成探测数(含 seed token);归零即该主机扫完
}

// scanRun 持有一次扫描的共享并发设施,供递归 enqueue/work 使用。
type scanRun struct {
	sc     *scanner
	ctx    context.Context
	client *http.Client
	opt    scanOptions
	sem    chan struct{}
	wg     sync.WaitGroup
}

// enqueue 投放一个候选到并发池。recursive=true 时从该主机递归预算扣减,耗尽即丢弃。
func (r *scanRun) enqueue(hc *hostCtx, cand candidate, depth int, recursive bool) {
	if r.ctx.Err() != nil {
		return
	}
	key := strings.ToLower(strings.TrimPrefix(cand.rel, "/"))
	hc.seenMu.Lock()
	if _, dup := hc.seen[key]; dup {
		hc.seenMu.Unlock()
		return
	}
	hc.seen[key] = struct{}{}
	hc.seenMu.Unlock()

	if recursive && atomic.AddInt64(&hc.budget, -1) < 0 {
		return // 递归预算耗尽
	}

	r.sc.store.addTotal(1)
	atomic.AddInt64(&hc.outstanding, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.hostDecr(hc) // 平衡 outstanding;归零触发该主机完成回调
		r.sem <- struct{}{}
		defer func() { <-r.sem }()
		if r.ctx.Err() != nil {
			return
		}
		r.work(hc, cand, depth)
	}()
}

// hostDecr 递减主机未完成计数;归零表示该主机全部候选探完 → 标记完成并增量落盘(断点续扫)。
// 注意:扫描被取消/超时时,排队中的 worker 会因 ctx 失效而提前返回并把计数归零,但此时该主机
// 并未真正扫完 —— 这种情况下不标记完成,以便续扫时重跑该主机。
func (r *scanRun) hostDecr(hc *hostCtx) {
	if atomic.AddInt64(&hc.outstanding, -1) == 0 && r.ctx.Err() == nil {
		r.sc.store.markTargetDone(hc.label)
		r.sc.store.persist()
		r.sc.log.Info("backup host completed", "host", hc.label)
	}
}

// work 探测单个候选;目录候选命中则触发递归,文件候选命中则记录。
func (r *scanRun) work(hc *hostCtx, cand candidate, depth int) {
	defer r.sc.store.incProbed()
	if cand.isDir {
		if r.sc.dirExists(r.ctx, r.client, hc.u, hc.base, cand.rel) {
			r.onDirFound(hc, cand.rel, depth)
		}
		return
	}
	if hit := r.sc.probe(r.ctx, r.client, probeJob{u: hc.u, cand: cand, base: hc.base}); hit != nil {
		r.sc.store.addHit(*hit)
	}
}

// onDirFound 在确认存在的目录下投放子候选,并按深度继续向下探测目录。
func (r *scanRun) onDirFound(hc *hostCtx, dirRel string, depth int) {
	if depth >= r.opt.MaxDepth {
		return
	}
	prefix := strings.TrimSuffix(dirRel, "/") + "/"
	for _, c := range genChildFileCandidates(hc.u, prefix) {
		r.enqueue(hc, c, depth+1, true)
	}
	// 更深一层目录探测(仅当还没到最大深度)。
	if depth+1 < r.opt.MaxDepth {
		for _, d := range recurseDirs {
			rel := prefix + d + "/"
			r.enqueue(hc, candidate{rel: rel, rule: "递归目录: /" + rel, isDir: true}, depth+1, true)
		}
	}
}

// genChildFileCandidates 为一个已确认存在的目录前缀生成高价值文件候选。
func genChildFileCandidates(u *url.URL, prefix string) []candidate {
	var out []candidate
	add := func(rel, rule, kind string) {
		out = append(out, candidate{rel: prefix + rel, rule: rule, kind: kind})
	}
	// 价值优先排序:命中预算可能被截断,故把高价值的数据库导出 / 敏感文件 / 主机名归档
	// 排在通用归档基名矩阵之前,确保要害候选不被预算截掉。
	for _, n := range recurseDBNames {
		add(n, "递归·数据库: /"+prefix+n, classifyKind(n, "", ""))
	}
	for _, s := range recurseSensitive {
		add(s, "递归·敏感文件: /"+prefix+s, classifyKind(s, "", ""))
	}
	// 近年带日期备份(基名 × 年份 × 分隔符 × 扩展名)。
	for _, base := range recurseDatedBases {
		for _, y := range recurseDatedYears {
			for _, sep := range dateSeps {
				for _, ext := range recurseDatedExts {
					rel := base + sep + y + ext
					add(rel, "递归·带日期: /"+prefix+rel, classifyKind(rel, "", ""))
				}
			}
		}
	}
	for _, tok := range hostTokens(u) {
		for _, ext := range archiveExts {
			add(tok+ext, "递归·主机名归档: /"+prefix+tok+ext, "源码")
		}
	}
	for _, b := range recurseArchBases {
		for _, ext := range archiveExts {
			add(b+ext, "递归·归档: /"+prefix+b+ext, "源码")
		}
	}
	return out
}

// dirExists 探测一个目录是否存在(仅在干净 404 站点上可信)。绝不下载、不绕过。
func (sc *scanner) dirExists(ctx context.Context, client *http.Client, u *url.URL, base baseline, rel string) bool {
	if !base.clean404 {
		return false // soft-404 站点路径判定不可靠,不递归
	}
	code, _, _, _ := sc.do(ctx, client, http.MethodHead, probeURL(u, rel))
	switch code {
	case http.StatusOK, http.StatusPartialContent,
		http.StatusMovedPermanently, http.StatusFound,
		http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}
