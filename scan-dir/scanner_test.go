package scandir

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"redops/core"
)

// ---- 纯函数:字典与目标规范化 ----

func TestParseWordlist(t *testing.T) {
	got := parseWordlist("admin\n# comment\n\n  api  \n/admin\nadmin\n")
	want := []string{"admin", "api"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWordlist=%v want %v", got, want)
	}
}

func TestParseExtensions(t *testing.T) {
	got := parseExtensions(" php, .bak ,txt,php ")
	want := []string{"php", "bak", "txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseExtensions=%v want %v", got, want)
	}
	if parseExtensions("") != nil {
		t.Fatalf("空输入应为 nil")
	}
}

func TestExpandTemplates(t *testing.T) {
	// 目录型追加扩展名 + 具体文件名原样 + %EXT% 占位符替换。
	got := expandTemplates([]string{"admin", "index.php", ".env", "shell.%EXT%"}, []string{"php", "bak"})
	want := []string{"admin", "admin.php", "admin.bak", "index.php", ".env", "shell.php", "shell.bak"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTemplates=%v want %v", got, want)
	}
	// 无扩展名时 %EXT% 条目被丢弃。
	got2 := expandTemplates([]string{"admin", "x.%EXT%"}, nil)
	if !reflect.DeepEqual(got2, []string{"admin"}) {
		t.Fatalf("无扩展名时应丢弃 %%EXT%% 条目,得 %v", got2)
	}
}

func TestLoadTemplatesBuiltin(t *testing.T) {
	for _, id := range []string{"quickhits", "api", "common", "dirsearch", "raft-files", "raft-dirs"} {
		tpl, ok := loadTemplates(id)
		if !ok || len(tpl) == 0 {
			t.Errorf("内置字典 %q 应可加载且非空", id)
		}
	}
	if _, ok := loadTemplates("nope-xyz"); ok {
		t.Errorf("未知字典应返回 false")
	}
	// dirsearch 字典应含 %EXT% 占位符条目。
	tpl, _ := loadTemplates("dirsearch")
	hasExt := false
	for _, w := range tpl {
		if strings.Contains(w, "%EXT%") {
			hasExt = true
			break
		}
	}
	if !hasExt {
		t.Errorf("dirsearch 字典应包含 %%EXT%% 占位符条目")
	}
}

func TestSafeWordlistName(t *testing.T) {
	ok := []string{"my.txt", "directory-list-2.3-medium.txt"}
	bad := []string{"../etc/passwd", "a/b.txt", "..\\x.txt", "noext", "x.csv"}
	for _, n := range ok {
		if !safeWordlistName(n) {
			t.Errorf("%q 应合法", n)
		}
	}
	for _, n := range bad {
		if safeWordlistName(n) {
			t.Errorf("%q 应被拒", n)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"example.com":               "http://example.com/",
		"http://a.com":              "http://a.com/",
		"https://a.com:8443/app":    "https://a.com:8443/app/",
		"http://a.com/x/":           "http://a.com/x/",
		"a.com:8080":                "http://a.com:8080/",
		"https://a.com/p?q=1#frag":  "https://a.com/p/",
	}
	for in, want := range cases {
		got, ok := normalizeTarget(in)
		if !ok || got != want {
			t.Errorf("normalizeTarget(%q)=%q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := normalizeTarget("ftp://x.com"); ok {
		t.Errorf("非 http(s) scheme 应被拒")
	}
	if _, ok := normalizeTarget("   "); ok {
		t.Errorf("空目标应被拒")
	}
}

func TestJoinURL(t *testing.T) {
	if got := joinURL("http://a.com/", "/admin"); got != "http://a.com/admin" {
		t.Fatalf("joinURL=%q", got)
	}
	if got := joinURL("http://a.com/x/", "y.php"); got != "http://a.com/x/y.php" {
		t.Fatalf("joinURL=%q", got)
	}
}

func TestParseCodeSet(t *testing.T) {
	got := parseCodeSet("200, 301-303 ,403")
	for _, c := range []int{200, 301, 302, 303, 403} {
		if _, ok := got[c]; !ok {
			t.Errorf("缺状态码 %d", c)
		}
	}
	if _, ok := got[304]; ok {
		t.Errorf("304 不应在集合中")
	}
	if len(parseCodeSet("")) != 0 {
		t.Errorf("空输入应为空集")
	}
}

func TestParseHeaders(t *testing.T) {
	got := parseHeaders([]string{"Cookie: a=b", "X-Test:  v ", "", "bad-line", ":noval"})
	if got["Cookie"] != "a=b" || got["X-Test"] != "v" {
		t.Fatalf("parseHeaders=%v", got)
	}
	if len(got) != 2 {
		t.Fatalf("应只解析出 2 个有效头,得 %v", got)
	}
}

// ---- interesting:状态过滤 + 软 404 抑制 ----

func TestInteresting(t *testing.T) {
	sc := &scanner{}
	excl := respFilters{exclude: map[int]struct{}{404: {}}}
	if sc.interesting(probeResult{status: 404}, excl, baseline{}) {
		t.Errorf("404 应被排除")
	}
	if !sc.interesting(probeResult{status: 200, length: 100}, excl, baseline{}) {
		t.Errorf("200 应保留")
	}
	// include 集合限定
	incl := respFilters{include: map[int]struct{}{200: {}, 301: {}}}
	if sc.interesting(probeResult{status: 403}, incl, baseline{}) {
		t.Errorf("include 不含 403 应被过滤")
	}
	// ffuf 风格 size/words/lines 过滤
	fsz := respFilters{length: map[int64]struct{}{1234: {}}}
	if sc.interesting(probeResult{status: 200, length: 1234}, fsz, baseline{}) {
		t.Errorf("匹配 filterLength 应被过滤")
	}
	fw := respFilters{words: map[int]struct{}{42: {}}}
	if sc.interesting(probeResult{status: 200, words: 42}, fw, baseline{}) {
		t.Errorf("匹配 filterWords 应被过滤")
	}
	// 软 404:同状态 + 同质长度 → 抑制
	bl := baseline{active: true, status: 200, length: 1000}
	if sc.interesting(probeResult{status: 200, length: 1010}, excl, bl) {
		t.Errorf("软 404 同质页应被抑制")
	}
	if !sc.interesting(probeResult{status: 200, length: 5000}, excl, bl) {
		t.Errorf("长度差异大应判为真实命中")
	}
}

func TestLooksLikeDir(t *testing.T) {
	if !looksLikeDir("admin", probeResult{status: 200}) {
		t.Errorf("200 无扩展名应判目录")
	}
	if looksLikeDir("index.php", probeResult{status: 200}) {
		t.Errorf("含扩展名不应判目录")
	}
	if !looksLikeDir("app", probeResult{status: 301, redirect: "http://x/app/"}) {
		t.Errorf("301 跳到尾斜杠应判目录")
	}
}

// ---- limiter:最小间隔 ----

func TestLimiterReserve(t *testing.T) {
	base := time.Unix(1000, 0)
	cur := base
	l := newLimiter(10) // 100ms 间隔
	l.nowFn = func() time.Time { return cur }
	if d := l.reserve(); d != 0 {
		t.Fatalf("首槽应立即放行,得 %v", d)
	}
	if d := l.reserve(); d != 100*time.Millisecond {
		t.Fatalf("第二槽应等 100ms,得 %v", d)
	}
	// 不限速
	if newLimiter(0).reserve() != 0 {
		t.Fatalf("不限速应恒为 0")
	}
}

func TestRetryAfterDelay(t *testing.T) {
	if d := retryAfterDelay("2", 0); d != 2*time.Second {
		t.Fatalf("Retry-After:2 应等 2s,得 %v", d)
	}
	if d := retryAfterDelay("", 0); d != backoffBase {
		t.Fatalf("无头第 0 次应为 base,得 %v", d)
	}
}

// ---- 端到端:对本地 httptest 站点真实爆破 ----

func TestScanEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		case "/admin/":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("admin area"))
		case "/config.php":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<?php secret ?>"))
		case "/login":
			w.WriteHeader(403)
		default:
			http.NotFound(w, r) // 真 404,无 wildcard
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{
		Targets:     []string{srv.URL},
		Wordlist:    "custom",
		CustomWords: []string{"admin", "config", "login", "doesnotexist"},
		Extensions:  "php",
		Concurrency: 8,
		Method:      "GET",
	}
	st.beginScan("t1", "test", opt.Targets, opt)
	sc.run(context.Background(), opt)

	if s := st.status(); s.Err != "" {
		t.Fatalf("扫描报错: %s", s.Err)
	}
	hits := st.list()
	paths := map[string]int{} // path -> status
	for _, h := range hits {
		paths[h.Path] = h.Status
	}
	if paths["/admin"] != 301 {
		t.Errorf("应命中 /admin(301),得 %v", paths["/admin"])
	}
	if paths["/config.php"] != 200 {
		t.Errorf("应命中 /config.php(200),得 %v", paths["/config.php"])
	}
	if paths["/login"] != 403 {
		t.Errorf("应命中 /login(403),得 %v", paths["/login"])
	}
	if _, ok := paths["/doesnotexist"]; ok {
		t.Errorf("不存在路径不应命中")
	}
}

func TestScanWildcardSuppression(t *testing.T) {
	// 站点对任意路径都回 200 + 同质内容 → 应被软 404 抑制(除非长度显著不同)。
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/realbig") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("X", 9000)))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("default soft-404 body padding here"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{
		Targets:     []string{srv.URL},
		Wordlist:    "custom",
		CustomWords: []string{"a", "b", "c", "realbig"},
		Concurrency: 4,
		Method:      "GET",
	}
	st.beginScan("t2", "test", opt.Targets, opt)
	sc.run(context.Background(), opt)

	var got []string
	for _, h := range st.list() {
		got = append(got, h.Path)
	}
	sort.Strings(got)
	if len(got) != 1 || got[0] != "/realbig" {
		t.Fatalf("wildcard 站点应只命中长度显著不同的 /realbig,得 %v", got)
	}
	if st.status().Filtered == 0 {
		t.Errorf("应有被软 404 抑制的计数")
	}
}

func TestApplyAffixes(t *testing.T) {
	got := applyAffixes([]string{"admin", "index.php"}, []string{"."}, []string{"~", ".bak"})
	want := []string{"admin", ".admin", "admin~", "admin.bak", "index.php", ".index.php", "index.php~", "index.php.bak"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applyAffixes=%v want %v", got, want)
	}
	// 无前后缀时原样返回
	if got := applyAffixes([]string{"a"}, nil, nil); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("无前后缀应原样,得 %v", got)
	}
}

func TestExtractLinks(t *testing.T) {
	body := []byte(`<html><a href="/admin/panel">x</a><script src="/static/app.js"></script>
	<a href="https://evil.com/out">ext</a> fetch("/api/v2/users") <a href="#frag">f</a></html>`)
	got := extractLinks("http://t.local/index.html", body)
	set := map[string]bool{}
	for _, u := range got {
		set[u] = true
	}
	if !set["http://t.local/admin/panel"] || !set["http://t.local/static/app.js"] || !set["http://t.local/api/v2/users"] {
		t.Fatalf("应抽出同主机链接,得 %v", got)
	}
	if set["https://evil.com/out"] {
		t.Fatalf("不应包含外站链接")
	}
}

func TestValidFuzzTarget(t *testing.T) {
	if !validFuzzTarget("http://a.com/FUZZ") || !validFuzzTarget("https://a.com/api?x=FUZZ") {
		t.Fatalf("合法 FUZZ 目标应通过")
	}
	if validFuzzTarget("FUZZ") || validFuzzTarget("ftp://a.com/FUZZ") {
		t.Fatalf("无 scheme/host 或非 http 应拒")
	}
}

func TestInterestingRegexAndLen(t *testing.T) {
	sc := &scanner{}
	// filterRegex:正文匹配则剔除
	fr := respFilters{filterRe: regexp.MustCompile("Access Denied")}
	if sc.interesting(probeResult{status: 200, body: []byte("Access Denied page")}, fr, baseline{}) {
		t.Errorf("filterRegex 命中应被过滤")
	}
	// matchRegex:不匹配则剔除
	mr := respFilters{matchRe: regexp.MustCompile("admin")}
	if sc.interesting(probeResult{status: 200, body: []byte("nothing here")}, mr, baseline{}) {
		t.Errorf("matchRegex 不匹配应被过滤")
	}
	if !sc.interesting(probeResult{status: 200, body: []byte("admin console")}, mr, baseline{}) {
		t.Errorf("matchRegex 匹配应保留")
	}
	// min/max length
	mm := respFilters{minLen: 100, maxLen: 1000}
	if sc.interesting(probeResult{status: 200, length: 50}, mm, baseline{}) {
		t.Errorf("小于 minLen 应被过滤")
	}
	if sc.interesting(probeResult{status: 200, length: 2000}, mm, baseline{}) {
		t.Errorf("大于 maxLen 应被过滤")
	}
	if !sc.interesting(probeResult{status: 200, length: 500}, mm, baseline{}) {
		t.Errorf("区间内应保留")
	}
}

func TestScanFuzzAndCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="/hidden/deep">d</a>`)) // 抽链发现
		case "/hidden/deep":
			_, _ = w.Write([]byte("treasure"))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// crawl:从 /start 抽出 /hidden/deep 并探测命中
	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{Targets: []string{srv.URL}, Wordlist: "custom",
		CustomWords: []string{"start", "nope"}, Concurrency: 4, Crawl: true}
	st.beginScan("c1", "t", opt.Targets, opt)
	sc.run(context.Background(), opt)
	paths := map[string]bool{}
	for _, h := range st.list() {
		paths[h.Path] = true
	}
	if !paths["/start"] || !paths["/hidden/deep"] {
		t.Fatalf("crawl 应命中 /start 与抽链发现的 /hidden/deep,得 %v", paths)
	}

	// FUZZ:目标含 FUZZ 时逐词替换
	st2 := newStore("")
	sc2 := newScanner(core.NewLogger(), st2)
	opt2 := scanOptions{Targets: []string{srv.URL + "/FUZZ"}, Wordlist: "custom",
		CustomWords: []string{"start", "nope"}, Concurrency: 4}
	st2.beginScan("f1", "t", opt2.Targets, opt2)
	sc2.run(context.Background(), opt2)
	got := map[string]bool{}
	for _, h := range st2.list() {
		got[h.Path] = true
	}
	if !got["start"] {
		t.Fatalf("FUZZ 模式应命中 start,得 %v", got)
	}
}

func TestSimilarity(t *testing.T) {
	a := []byte("<html><body>Not Found: /aaaaa</body></html>")
	b := []byte("<html><body>Not Found: /bbbbb</body></html>")
	if s := similarity(a, b); s < 0.8 {
		t.Errorf("仅路径回显不同的模板页应高度相似,得 %.2f", s)
	}
	c := []byte("totally different real content with code and data tables")
	if s := similarity(a, c); s > 0.5 {
		t.Errorf("不同内容应低相似,得 %.2f", s)
	}
}

func TestGenerateBackups(t *testing.T) {
	got := generateBackups("http://t.local/app/config.php")
	set := map[string]bool{}
	for _, u := range got {
		set[u] = true
	}
	for _, want := range []string{
		"http://t.local/app/config.php.bak",
		"http://t.local/app/config.php~",
		"http://t.local/app/.config.php.swp",
	} {
		if !set[want] {
			t.Errorf("应衍生 %s,得 %v", want, got)
		}
	}
}

// 动态软 404:站点对任意路径回 200 且把路径回显进模板(长度漂移)。相似度判定应抑制噪声,
// 但放过正文显著不同的真实命中。
func TestScanDynamicSoft404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realpage" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("REAL DISTINCT CONTENT: dashboard with widgets, tables, and admin links everywhere"))
			return
		}
		// 其它任何路径:200 + 把路径回显进同一模板(长度因路径而漂移)。
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><head><title>Welcome</title></head><body>" +
			"The page you requested (" + r.URL.Path + ") is part of our friendly site. " +
			"Please use the navigation menu to find what you need.</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{Targets: []string{srv.URL}, Wordlist: "custom",
		CustomWords: []string{"foo", "bar", "baz", "qux", "realpage"}, Concurrency: 4}
	st.beginScan("d1", "t", opt.Targets, opt)
	sc.run(context.Background(), opt)

	var paths []string
	for _, h := range st.list() {
		paths = append(paths, h.Path)
	}
	sort.Strings(paths)
	if len(paths) != 1 || paths[0] != "/realpage" {
		t.Fatalf("动态软 404 应仅保留正文不同的 /realpage,得 %v", paths)
	}
}

func TestMapFuzzHelpers(t *testing.T) {
	if !mapHasFuzz(map[string]string{"X-Token": "FUZZ"}) || mapHasFuzz(map[string]string{"A": "b"}) {
		t.Fatalf("mapHasFuzz 判定错误")
	}
	out := replaceFuzzHeaders(map[string]string{"X-Id": "v-FUZZ"}, "42")
	if out["X-Id"] != "v-42" {
		t.Fatalf("replaceFuzzHeaders=%v", out)
	}
}

// 任意方法 + 请求体 FUZZ:对标 ffuf -X POST -d 'p=FUZZ'。
func TestScanMethodBodyFuzz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		_ = r.ParseForm()
		if r.PostFormValue("user") == "admin" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("welcome admin"))
			return
		}
		w.WriteHeader(401)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{
		Targets: []string{srv.URL + "/login"}, Method: "POST", RequestBody: "user=FUZZ",
		Wordlist: "custom", CustomWords: []string{"guest", "admin", "root"},
		StatusInclude: "200", Concurrency: 4,
	}
	st.beginScan("mb1", "t", opt.Targets, opt)
	sc.run(context.Background(), opt)

	hits := st.list()
	if len(hits) != 1 || hits[0].Path != "admin" {
		t.Fatalf("仅 user=admin 应得 200,得 %v", hits)
	}
}

func TestProxyValidation(t *testing.T) {
	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{Targets: []string{"http://x.local"}, Wordlist: "custom",
		CustomWords: []string{"a"}, Proxy: "not a url://??"}
	st.beginScan("p1", "t", opt.Targets, opt)
	sc.run(context.Background(), opt)
	if st.status().Err == "" {
		t.Fatalf("非法 proxy 应使扫描失败")
	}
}

func TestAddHitDedup(t *testing.T) {
	st := newStore("")
	st.beginScan("h", "t", nil, scanOptions{})
	if !st.addHit(Hit{URL: "http://a/x"}) {
		t.Fatalf("首次应为新命中")
	}
	if st.addHit(Hit{URL: "http://a/x"}) {
		t.Fatalf("重复 URL 应被去重")
	}
	if len(st.list()) != 1 {
		t.Fatalf("去重后应只有 1 条,得 %d", len(st.list()))
	}
}

func TestStoreResumeMechanics(t *testing.T) {
	st := newStore("")
	st.beginScan("r", "t", []string{"http://a/"}, scanOptions{Wordlist: "common"})
	st.markBaseDone("http://a/b1/", []PendingBase{{URL: "http://a/b2/", Depth: 1}})
	st.finishScan("已取消")
	if !st.status().Resumable {
		t.Fatalf("有剩余队列应可续扫")
	}
	q, comp, ok := st.resumeState()
	if !ok || len(q) != 1 || q[0].url != "http://a/b2/" {
		t.Fatalf("resumeState 队列错误: %v ok=%v", q, ok)
	}
	if _, done := comp["http://a/b1/"]; !done {
		t.Fatalf("已完成集合应含 b1")
	}
	opt, ok := st.beginResume()
	if !ok || opt.Wordlist != "common" || !st.status().Running {
		t.Fatalf("beginResume 应恢复运行态并返回原 opt")
	}
}

// 端到端续扫:构造一个「被中断」的任务(队列里留一个基目录),续扫后应扫完它。
func TestScanResumeEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("admin"))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	opt := scanOptions{Targets: []string{srv.URL}, Wordlist: "custom",
		CustomWords: []string{"admin", "nope"}, Concurrency: 4}
	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	st.beginScan("re1", "t", opt.Targets, opt)
	// 模拟中断:队列里留下基目录,标记非运行 + 可续扫。
	st.setPending([]PendingBase{{URL: srv.URL + "/", Depth: 0}})
	st.finishScan("已取消")

	ropt, ok := st.beginResume()
	if !ok {
		t.Fatalf("应可续扫")
	}
	sc.runResumable(context.Background(), ropt, true)

	var paths []string
	for _, h := range st.list() {
		paths = append(paths, h.Path)
	}
	if len(paths) != 1 || paths[0] != "/admin" {
		t.Fatalf("续扫应扫完基目录并命中 /admin,得 %v", paths)
	}
	if st.status().Resumable {
		t.Fatalf("续扫完成后不应再可续扫")
	}
}

func TestCombineWords(t *testing.T) {
	cb := combineWords([]string{"a", "b"}, []string{"1", "2"}, "clusterbomb")
	if len(cb) != 4 {
		t.Fatalf("clusterbomb 应 2×2=4,得 %d", len(cb))
	}
	pf := combineWords([]string{"a", "b", "c"}, []string{"1", "2"}, "pitchfork")
	if len(pf) != 2 {
		t.Fatalf("pitchfork 应取短长度 2,得 %d", len(pf))
	}
	w1, w2, multi := splitCombo(pf[0])
	if !multi || w1 != "a" || w2 != "1" {
		t.Fatalf("splitCombo=%q,%q,%v", w1, w2, multi)
	}
	if _, _, m := splitCombo("solo"); m {
		t.Fatalf("无分隔应为单关键字")
	}
}

func TestCombineWordsEdgeCases(t *testing.T) {
	// 空第二词表 → clusterbomb 应产出 0 条
	if got := combineWords([]string{"a", "b"}, nil, "clusterbomb"); len(got) != 0 {
		t.Errorf("空 w2 clusterbomb 应=0,得 %d", len(got))
	}
	// 空第一词表
	if got := combineWords(nil, []string{"1", "2"}, "clusterbomb"); len(got) != 0 {
		t.Errorf("空 w1 clusterbomb 应=0,得 %d", len(got))
	}
	// 单元素 × 单元素 clusterbomb = 1
	cb1 := combineWords([]string{"x"}, []string{"y"}, "clusterbomb")
	if len(cb1) != 1 {
		t.Errorf("1×1 clusterbomb 应=1,得 %d", len(cb1))
	}
	w1, w2, multi := splitCombo(cb1[0])
	if !multi || w1 != "x" || w2 != "y" {
		t.Errorf("1×1 splitCombo=%q,%q,%v", w1, w2, multi)
	}
	// pitchfork 空第二词表 → 取短(0 条)
	if got := combineWords([]string{"a", "b"}, nil, "pitchfork"); len(got) != 0 {
		t.Errorf("空 w2 pitchfork 应=0,得 %d", len(got))
	}
	// pitchfork 长度不等 → 取短
	pf := combineWords([]string{"a", "b", "c", "d"}, []string{"1", "2"}, "pitchfork")
	if len(pf) != 2 {
		t.Errorf("pitchfork 应取短(2),得 %d", len(pf))
	}
	// 未知 mode 退化为 clusterbomb
	unk := combineWords([]string{"a"}, []string{"1", "2"}, "unknown")
	if len(unk) != 2 {
		t.Errorf("未知 mode 应退化 clusterbomb(1×2=2),得 %d", len(unk))
	}
}

// TestScanClusterbombEndToEnd 验证 clusterbomb 所有组合均被探测到。
func TestScanClusterbombEndToEnd(t *testing.T) {
	var hits []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user := r.FormValue("u")
		pass := r.FormValue("p")
		mu.Lock()
		hits = append(hits, user+":"+pass)
		mu.Unlock()
		if user == "admin" && pass == "pass2" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(403)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{
		Targets:      []string{srv.URL + "/search"},
		Method:       "POST",
		RequestBody:  "u=FUZZ&p=FUZ2Z",
		Wordlist:     "custom",
		CustomWords:  []string{"guest", "admin"},
		Wordlist2:    "custom",
		CustomWords2: []string{"pass1", "pass2"},
		FuzzMode:     "clusterbomb",
		StatusInclude: "200",
		Concurrency:  4,
	}
	st.beginScan("cb1", "t", opt.Targets, opt)
	sc.run(context.Background(), opt)

	mu.Lock()
	total := len(hits)
	mu.Unlock()

	// 2 × 2 = 4 组合全部发送
	if total != 4 {
		t.Errorf("clusterbomb 应发出 4 次请求,实际 %d", total)
	}
	// 仅 admin:pass2 命中
	found := st.list()
	if len(found) != 1 {
		t.Errorf("应仅 admin:pass2 命中,得 %d 条", len(found))
	}
}

// 多关键字 pitchfork:user×pass 按下标配对,对标 ffuf -w u:FUZZ -w p:FUZ2Z -mode pitchfork。
func TestScanMultiKeywordPitchfork(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("u") == "admin" && r.PostFormValue("p") == "s3cr3t" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(401)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{
		Targets: []string{srv.URL + "/login"}, Method: "POST", RequestBody: "u=FUZZ&p=FUZ2Z",
		Wordlist: "custom", CustomWords: []string{"guest", "admin"},
		Wordlist2: "custom", CustomWords2: []string{"wrong", "s3cr3t"},
		FuzzMode: "pitchfork", StatusInclude: "200", Concurrency: 4,
	}
	st.beginScan("mk1", "t", opt.Targets, opt)
	sc.run(context.Background(), opt)

	hits := st.list()
	// pitchfork: (guest,wrong)→401, (admin,s3cr3t)→200。仅 1 命中。
	if len(hits) != 1 {
		t.Fatalf("pitchfork 应仅 admin/s3cr3t 命中,得 %d 条 %v", len(hits), hits)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"/.git/config":     "critical",
		"/.env":            "critical",
		"/backup.zip":      "critical",
		"/db_2024.sql":     "critical",
		"/admin":           "high",
		"/swagger-ui":      "high",
		"/config.php":      "high",
		"/robots.txt":      "medium",
		"/login":           "medium",
		"/notes.txt":       "low",
		"/home":            "info",
	}
	for path, want := range cases {
		if got, _ := classify(path); got != want {
			t.Errorf("classify(%q)=%q want %q", path, got, want)
		}
	}
	if sevRank("critical") <= sevRank("info") {
		t.Errorf("严重度权重排序错误")
	}
}

// TestScanHeadAutoSwitchMethod 验证：Method=HEAD 且设置了 FilterWords 时，
// 引擎自动切换为 GET（HEAD 响应体为空，词数过滤器永远命中 0，会产生静默漏报）。
func TestScanHeadAutoSwitchMethod(t *testing.T) {
	var gotMethods []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethods = append(gotMethods, r.Method)
		mu.Unlock()
		switch r.URL.Path {
		case "/secret":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("sensitive content here token"))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	opt := scanOptions{
		Targets:     []string{srv.URL},
		Wordlist:    "custom",
		CustomWords: []string{"secret", "notfound"},
		Concurrency: 2,
		Method:      http.MethodHead, // 用户设 HEAD，但同时开了 FilterWords
		FilterWords: "0",             // 触发自动切换
	}
	st.beginScan("head-switch", "test", opt.Targets, opt)
	sc.run(context.Background(), opt)

	mu.Lock()
	methods := append([]string(nil), gotMethods...)
	mu.Unlock()

	for _, m := range methods {
		if m == http.MethodHead {
			t.Errorf("设置 FilterWords 后不应发送 HEAD 请求（实际请求方法列表: %v）", methods)
			break
		}
	}
	if len(methods) == 0 {
		t.Error("应至少发出一个请求")
	}
}

func TestScanCancel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := newStore("")
	sc := newScanner(core.NewLogger(), st)
	words := make([]string, 200)
	for i := range words {
		words[i] = "w" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	opt := scanOptions{Targets: []string{srv.URL}, Wordlist: "custom", CustomWords: words, Concurrency: 4}
	st.beginScan("t3", "test", opt.Targets, opt)

	ctx, cancel := context.WithCancel(context.Background())
	st.setCancel(cancel)
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	sc.run(ctx, opt)

	if st.status().Err != "已取消" {
		t.Fatalf("取消后状态应为「已取消」,得 %q", st.status().Err)
	}
}
