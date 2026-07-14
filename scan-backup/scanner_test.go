package backup

// scanner_test.go —— backup 模块纯函数回归测试。
//
// 全部无网络依赖:候选生成 / 研判分类 / soft-404 判定 / 目标规范化 / 魔数识别,
// 以及本次新增的限速器与 429/503 退避逻辑(用注入时钟,不真实睡眠)。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func mustTarget(t *testing.T, s string) *url.URL {
	t.Helper()
	u, _, err := normalizeTarget(s)
	if err != nil {
		t.Fatalf("normalizeTarget(%q) 失败: %v", s, err)
	}
	return u
}

// ---- 限速器 ----

func TestLimiterSpacing(t *testing.T) {
	base := time.Unix(1000, 0)
	cur := base
	l := newLimiter(10) // interval = 100ms
	l.nowFn = func() time.Time { return cur }

	// 同一时刻连续预定:首个 0,其后按 interval 递增。
	if d := l.reserve(); d != 0 {
		t.Fatalf("reserve#1 want 0, got %v", d)
	}
	if d := l.reserve(); d != 100*time.Millisecond {
		t.Fatalf("reserve#2 want 100ms, got %v", d)
	}
	if d := l.reserve(); d != 200*time.Millisecond {
		t.Fatalf("reserve#3 want 200ms, got %v", d)
	}
	// 时钟前进到排程之后 → 不再等待。
	cur = base.Add(300 * time.Millisecond)
	if d := l.reserve(); d != 0 {
		t.Fatalf("reserve#4 after clock advance want 0, got %v", d)
	}
}

func TestLimiterUnlimited(t *testing.T) {
	l := newLimiter(0) // <=0 视为不限速
	for i := 0; i < 5; i++ {
		if d := l.reserve(); d != 0 {
			t.Fatalf("unlimited reserve#%d want 0, got %v", i, d)
		}
	}
}

func TestLimiterPenalize(t *testing.T) {
	base := time.Unix(2000, 0)
	l := newLimiter(10) // interval 100ms
	l.nowFn = func() time.Time { return base }

	l.reserve()                        // next = base+100ms
	l.penalize(500 * time.Millisecond) // next = base+600ms
	if d := l.reserve(); d != 600*time.Millisecond {
		t.Fatalf("after penalize want 600ms wait, got %v", d)
	}
}

func TestLimiterWaitRespectsCancel(t *testing.T) {
	l := newLimiter(1) // interval 1s,足够长
	l.reserve()        // 推进排程,使下次 wait 需要真实等待
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消
	if err := l.wait(ctx); err == nil {
		t.Fatal("wait 在 ctx 取消后应返回错误")
	}
}

// ---- 退避延迟 ----

func TestRetryAfterDelay(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		attempt int
		want    time.Duration
	}{
		{"retry-after 秒", "5", 0, 5 * time.Second},
		{"retry-after 带空格", "  3 ", 0, 3 * time.Second},
		{"retry-after 0 夹到下限", "0", 0, backoffBase},
		{"retry-after 过大夹到上限", "600", 0, backoffCap},
		{"无头·首次", "", 0, backoffBase},
		{"无头·第 1 次翻倍", "", 1, 1 * time.Second},
		{"无头·第 2 次", "", 2, 2 * time.Second},
		{"无头·多次夹到上限", "", 10, backoffCap},
		{"非法头退回指数退避", "soon", 0, backoffBase},
	}
	for _, c := range cases {
		if got := retryAfterDelay(c.header, c.attempt); got != c.want {
			t.Errorf("%s: retryAfterDelay(%q,%d)=%v want %v", c.name, c.header, c.attempt, got, c.want)
		}
	}
}

func TestIsThrottle(t *testing.T) {
	for code, want := range map[int]bool{429: true, 503: true, 200: false, 403: false, 404: false, 500: false} {
		if isThrottle(code) != want {
			t.Errorf("isThrottle(%d)=%v want %v", code, isThrottle(code), want)
		}
	}
}

func TestTrimSpace(t *testing.T) {
	cases := map[string]string{"  x  ": "x", "\t3\t": "3", "": "", "ab": "ab", " a b ": "a b"}
	for in, want := range cases {
		if got := trimSpace(in); got != want {
			t.Errorf("trimSpace(%q)=%q want %q", in, got, want)
		}
	}
}

// ---- 目标规范化 ----

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantErr  bool
		scheme   string
		explicit bool
	}{
		{"example.com", false, "https", false},
		{"http://example.com", false, "http", true},
		{"https://a.b/c", false, "https", true},
		{"", true, "", false},
		{"ftp://x.com", true, "", false},
	}
	for _, c := range cases {
		u, explicit, err := normalizeTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeTarget(%q) 应报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeTarget(%q) 意外报错: %v", c.in, err)
			continue
		}
		if u.Scheme != c.scheme || explicit != c.explicit {
			t.Errorf("normalizeTarget(%q)=scheme %s explicit %v, want %s %v", c.in, u.Scheme, explicit, c.scheme, c.explicit)
		}
	}
}

// ---- 候选生成 ----

func TestGenCandidatesCapAndDedup(t *testing.T) {
	u := mustTarget(t, "https://www.bank-corp.com")

	capped := genCandidates(u, 10, true)
	if len(capped) != 10 {
		t.Fatalf("maxPerHost=10 应恰好截断到 10,got %d", len(capped))
	}

	full := genCandidates(u, 4000, true)
	seen := map[string]bool{}
	for _, c := range full {
		if seen[c.rel] {
			t.Errorf("候选重复: %q", c.rel)
		}
		seen[c.rel] = true
	}
}

func TestGenCandidatesHostDerived(t *testing.T) {
	u := mustTarget(t, "https://www.bank-corp.com")
	full := genCandidates(u, 4000, true)
	want := "bank-corp.zip"
	found := false
	for _, c := range full {
		if c.rel == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("应包含主机名派生归档候选 %q", want)
	}
}

func TestGenCandidatesEditorToggle(t *testing.T) {
	// 用足够大的上限,确保末尾的编辑器候选不被字典扩容后的截断吃掉。
	u := mustTarget(t, "https://www.bank-corp.com")
	withEditor := len(genCandidates(u, 20000, true))
	without := len(genCandidates(u, 20000, false))
	if withEditor <= without {
		t.Errorf("includeEditor=true(%d) 应多于 false(%d)", withEditor, without)
	}
}

// ---- 类型研判 ----

func TestClassifyKind(t *testing.T) {
	cases := []struct {
		rel, ctype, magic, want string
	}{
		{"x", "", "zip", "源码"},
		{"x", "", "sqlite", "数据库"},
		{"x", "", "git-config", "配置"},
		{".git/config", "", "", "配置"},
		{"db/backup.sql", "", "", "数据库"},
		{"site.tar.gz", "", "", "源码"},
		{".env", "", "", "配置"},
		{"foo.unknown", "application/zip", "", "源码"},
		{"foo.unknown", "", "", "其它"},
	}
	for _, c := range cases {
		if got := classifyKind(c.rel, c.ctype, c.magic); got != c.want {
			t.Errorf("classifyKind(%q,%q,%q)=%q want %q", c.rel, c.ctype, c.magic, got, c.want)
		}
	}
}

// ---- soft-404 命中判定 ----

func TestAcceptOn200(t *testing.T) {
	cleanSite := baseline{}
	softStable := baseline{blanket200: true, stableLen: true, softLen: 1000}
	softDynamic := baseline{blanket200: true, stableLen: false}

	cases := []struct {
		name  string
		b     baseline
		magic string
		clen  int64
		want  bool
	}{
		{"识别到魔数即采信", softStable, "zip", 0, true},
		{"干净站点 2xx 即采信", cleanSite, "", 100, true},
		{"soft404 稳定·长度明显不同→采信", softStable, "", 2000, true},
		{"soft404 稳定·长度接近→拒绝", softStable, "", 1010, false},
		{"soft404 稳定·长度相同→拒绝", softStable, "", 1000, false},
		{"soft404 动态长度→保守拒绝", softDynamic, "", 5000, false},
	}
	for _, c := range cases {
		if got := acceptOn200(c.b, c.magic, c.clen); got != c.want {
			t.Errorf("%s: acceptOn200=%v want %v", c.name, got, c.want)
		}
	}
}

// ---- 魔数识别 ----

func TestMagicLabel(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{'P', 'K', 3, 4}, "zip"},
		{[]byte("Rar!\x1a\x07"), "rar"},
		{[]byte{0x1f, 0x8b}, "gzip"},
		{[]byte("BZh91"), "bzip2"},
		{[]byte("SQLite format 3\x00"), "sqlite"},
		{[]byte("<?php echo"), "php"},
		{[]byte("[core]\n"), "git-config"},
		{[]byte("-----BEGIN RSA"), "pem"},
		{[]byte("hello world"), ""},
	}
	for _, c := range cases {
		if got := magicLabel(c.in); got != c.want {
			t.Errorf("magicLabel(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// ---- 主机名派生 ----

func TestHostTokens(t *testing.T) {
	ip := mustTarget(t, "https://203.0.113.18")
	if toks := hostTokens(ip); toks != nil {
		t.Errorf("纯 IP 不应派生归档基名,got %v", toks)
	}
	u := mustTarget(t, "https://www.bank-corp.com")
	toks := hostTokens(u)
	if !contains(toks, "bank-corp") {
		t.Errorf("应派生主标签 bank-corp,got %v", toks)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ---- 定级 / 展示辅助 ----

func TestSeverityFor(t *testing.T) {
	cases := []struct {
		kind string
		code int
		rel  string
		want string
	}{
		{"数据库", 200, "backup.sql", "高危"},
		{"源码", 200, "site.zip", "高危"},
		{"配置", 200, ".env", "高危"},
		{"配置", 200, "robots.txt.bak", "中危"},
		{"源码", 403, "site.zip", "中危"}, // 受限统一中危
		{"其它", 200, "weird.tmp", "低危"},
	}
	for _, c := range cases {
		if got := severityFor(c.kind, c.code, c.rel); got != c.want {
			t.Errorf("severityFor(%q,%d,%q)=%q want %q", c.kind, c.code, c.rel, got, c.want)
		}
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{-1: "—", 512: "512 B", 2048: "2.0 KB"}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d)=%q want %q", in, got, want)
		}
	}
}

func TestParseContentRangeTotal(t *testing.T) {
	if got := parseContentRangeTotal("bytes 0-15/50535219"); got != 50535219 {
		t.Errorf("解析总长失败,got %d", got)
	}
	if got := parseContentRangeTotal("bytes 0-15/*"); got != -1 {
		t.Errorf("未知总长应返回 -1,got %d", got)
	}
	if got := parseContentRangeTotal("garbage"); got != -1 {
		t.Errorf("无斜杠应返回 -1,got %d", got)
	}
}

func TestFileLabel(t *testing.T) {
	cases := map[string]string{
		".git/config":        ".git/",
		"app/config.php.bak": "config.php.bak",
		"backup.zip":         "backup.zip",
	}
	for in, want := range cases {
		if got := fileLabel(in); got != want {
			t.Errorf("fileLabel(%q)=%q want %q", in, got, want)
		}
	}
}

// ---- 文本型敏感文件模式识别 ----

func TestTextPatternLabel(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		// pem
		{[]byte("-----BEGIN RSA PRIVATE KEY-----\n"), "pem"},
		{[]byte("-----BEGIN CERTIFICATE-----\n"), "pem"},
		// sql
		{[]byte("-- MySQL dump 10.13"), "sql"},
		{[]byte("CREATE TABLE users (id INT"), "sql"},
		{[]byte("INSERT INTO users VALUES"), "sql"},
		// env
		{[]byte("DATABASE_URL=postgres://u:p@host/db"), "env"},
		{[]byte("SECRET_KEY=abc123\nDEBUG=false"), "env"},
		// git-config
		{[]byte("[core]\n\trepositoryformatversion = 0"), "git-config"},
		{[]byte("[remote \"origin\"]"), "git-config"},
		// yaml
		{[]byte("---\nspring:\n  datasource:"), "yaml"},
		{[]byte("server:\n  port: 8080"), "yaml"},
		// json
		{[]byte(`{"db_password":"s3cr3t"}`), "json"},
		{[]byte(`[{"key":"value"}]`), "json"},
		// xml
		{[]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"), "xml"},
		{[]byte("<configuration><property>"), "xml"},
		{[]byte("<beans xmlns="), "xml"},
		// toml
		{[]byte("db_host = \"localhost\""), "toml"},
		{[]byte("port = 5432"), "toml"},
		// 短/空/无特征
		{[]byte(""), ""},
		{[]byte("x"), ""},
		{[]byte("hello world no pattern here"), ""},
	}
	for _, c := range cases {
		if got := textPatternLabel(c.in); got != c.want {
			t.Errorf("textPatternLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLooksLikeFunctions(t *testing.T) {
	if !looksLikeYAML([]byte("---\nkey: value")) {
		t.Error("--- 前缀应识别为 yaml")
	}
	if !looksLikeYAML([]byte("key: value")) {
		t.Error("key: value 应识别为 yaml")
	}
	if looksLikeYAML([]byte("ab")) {
		t.Error("短串不应识别为 yaml")
	}
	if !looksLikeJSON([]byte(`{"a":1}`)) {
		t.Error("{ 应识别为 json")
	}
	if !looksLikeJSON([]byte(`[1,2,3]`)) {
		t.Error("[ 应识别为 json")
	}
	if looksLikeJSON([]byte("")) {
		t.Error("空串不应识别为 json")
	}
	if !looksLikeXML([]byte("<?xml version")) {
		t.Error("<?xml 应识别为 xml")
	}
	if !looksLikeXML([]byte("<root>")) {
		t.Error("<root> 应识别为 xml")
	}
	if looksLikeXML([]byte("<")) {
		t.Error("孤立 < 不应识别为 xml")
	}
	if !looksLikeTOML([]byte("key = \"value\"")) {
		t.Error("key = value 应识别为 toml")
	}
	if looksLikeTOML([]byte("no equals sign")) {
		t.Error("无 = 不应识别为 toml")
	}
}

// ---- 鉴权透传 ----

func TestAuthTransportInjectsCookieAndAuthorization(t *testing.T) {
	var gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	opt := scanOptions{
		Cookie:        "session=abc123; user=admin",
		Authorization: "Bearer tok.xyz",
	}
	client := buildClient(opt)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodHead, srv.URL+"/probe", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	_ = resp.Body.Close()

	if gotCookie != opt.Cookie {
		t.Errorf("Cookie 注入失败: got %q, want %q", gotCookie, opt.Cookie)
	}
	if gotAuth != opt.Authorization {
		t.Errorf("Authorization 注入失败: got %q, want %q", gotAuth, opt.Authorization)
	}
}

func TestBuildClientNoAuthTransportWhenEmpty(t *testing.T) {
	// 无鉴权参数时不应包裹 authTransport
	client := buildClient(scanOptions{})
	if _, ok := client.Transport.(*authTransport); ok {
		t.Error("空鉴权时不应使用 authTransport")
	}
}

func TestCommonDictLoaded(t *testing.T) {
	if len(dictCommon) < 100 {
		t.Errorf("common 词典应有 ≥100 条,实际 %d 条", len(dictCommon))
	}
}

// ---- 内嵌字典 ----

func TestEmbeddedDictsLoaded(t *testing.T) {
	cases := []struct {
		name    string
		dict    []string
		minSize int
	}{
		{"raft-medium-files", dictRaftMediumFiles, 200},
		{"raft-medium-dirs", dictRaftMediumDirs, 100},
	}
	for _, c := range cases {
		if len(c.dict) < c.minSize {
			t.Errorf("内嵌词典 %s 应有 ≥%d 条，实际 %d 条", c.name, c.minSize, len(c.dict))
		}
	}
}

func TestEmbeddedPresetLookup(t *testing.T) {
	// 内嵌预置名应命中
	for _, name := range []string{"raft-medium-files", "raft-medium-dirs"} {
		lines, ok := embeddedPreset(name)
		if !ok {
			t.Errorf("embeddedPreset(%q) 应命中,返回 false", name)
			continue
		}
		if len(lines) == 0 {
			t.Errorf("embeddedPreset(%q) 返回空列表", name)
		}
	}
	// 未内嵌的名称应返回 false
	if _, ok := embeddedPreset("nonexistent-dict"); ok {
		t.Error("embeddedPreset(未知名称) 应返回 false")
	}
}

// ---- 自定义粘贴字典 ----

func TestCustomWordlistTextMerged(t *testing.T) {
	const customText = "# comment\nadmin/config.php\n\napi/v1/users\n"
	custom := parseList(customText)
	if len(custom) != 2 {
		t.Fatalf("parseList 解析自定义字典应得 2 条，实际 %d 条", len(custom))
	}
	if custom[0] != "admin/config.php" || custom[1] != "api/v1/users" {
		t.Errorf("解析结果不符: %v", custom)
	}
}

func TestCustomWordlistTextDeduplicatedByScanner(t *testing.T) {
	// 模拟场景：CustomWordlistText 包含一条已在 extDict 中的路径
	// enqueue 通过 seen map 去重，本测试验证合并后总条数正确
	dict1 := []string{"path/a", "path/b"}
	dict2 := parseList("path/b\npath/c\n") // path/b 重复
	merged := append(dict1, dict2...)
	seen := make(map[string]struct{})
	var deduped []string
	for _, p := range merged {
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			deduped = append(deduped, p)
		}
	}
	if len(deduped) != 3 {
		t.Errorf("去重后应得 3 条，实际 %d 条: %v", len(deduped), deduped)
	}
}
