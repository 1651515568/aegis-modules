package backup

// crawl_test.go —— 智能爬取 / 链接提取的纯函数与端到端(httptest)回归。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractLinks(t *testing.T) {
	body := []byte(`<a href="/inc/config.php">x</a><script src='/js/app.js'></script>
		<form action="/login.do"><link href="style.css"><div style="background:url('/img/bg.png')">`)
	links := extractLinks(body)
	want := []string{"/inc/config.php", "/js/app.js", "/login.do", "style.css", "/img/bg.png"}
	for _, w := range want {
		found := false
		for _, l := range links {
			if l == w {
				found = true
			}
		}
		if !found {
			t.Errorf("应提取到链接 %q,得到 %v", w, links)
		}
	}
}

func TestResolveSameHost(t *testing.T) {
	host := mustTarget(t, "https://site.com")
	page := "https://site.com/a/b/page.html"
	cases := []struct{ link, want string }{
		{"/inc/config.php", "inc/config.php"},
		{"../up.zip", "a/up.zip"},
		{"sub/x.sql", "a/b/sub/x.sql"},
		{"https://site.com/abs.bak", "abs.bak"},
		{"https://evil.com/x", ""}, // 跨域剔除
		{"mailto:a@b.com", ""},
		{"javascript:void(0)", ""},
		{"#frag", ""},
	}
	for _, c := range cases {
		if got := resolveSameHost(host, page, c.link); got != c.want {
			t.Errorf("resolveSameHost(%q)=%q want %q", c.link, got, c.want)
		}
	}
}

func TestParseRobotsAndSitemap(t *testing.T) {
	robots := []byte("User-agent: *\nDisallow: /private/\nDisallow: /admin/*\nSitemap: https://site.com/sitemap.xml\n")
	paths := parseRobots(robots)
	if !contains(paths, "private/") || !contains(paths, "admin/") {
		t.Errorf("robots 应解析出 Disallow 路径,got %v", paths)
	}
	sm := []byte(`<urlset><url><loc>https://site.com/page1</loc></url><url><loc>https://site.com/dump.sql</loc></url></urlset>`)
	locs := parseSitemap(sm)
	if len(locs) != 2 || !strings.Contains(locs[1], "dump.sql") {
		t.Errorf("sitemap 应解析出 2 个 loc,got %v", locs)
	}
}

func TestLooksSensitive(t *testing.T) {
	yes := []string{"download/db.sql", "backup.zip", "a/.env", "conf/app.yml", "id_rsa", "data.tar.gz"}
	no := []string{"inc/config.php", "index.html", "app.aspx", "page.jsp", "main.js", "style.css"}
	for _, f := range yes {
		if !looksSensitive(f) {
			t.Errorf("%q 应判为可疑泄露文件", f)
		}
	}
	for _, f := range no {
		if looksSensitive(f) {
			t.Errorf("%q 不应直接判为泄露(动态页面/普通资源)", f)
		}
	}
}

// TestCrawlDerivedHits 端到端:站点首页链接到真实文件,爬取后派生备份变体并直探敏感文件。
func TestCrawlDerivedHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>
				<a href="/inc/config.php">cfg</a>
				<a href="/download/db.sql">dump</a>
				<script src="/js/app.js"></script>
			</body></html>`))
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private/\n"))
		case "/inc/config.php": // 活动页面:不应被直接当命中
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>rendered config page</html>"))
		case "/inc/config.php.bak": // 真正的泄露:源码备份
			w.Header().Set("Content-Type", "text/plain")
			if r.Method == http.MethodHead {
				w.WriteHeader(200)
				return
			}
			_, _ = w.Write([]byte("<?php $db_password='secret'; ?>"))
		case "/download/db.sql": // 真实的可下载泄露文件
			w.Header().Set("Content-Type", "application/sql")
			if r.Method == http.MethodHead {
				w.WriteHeader(200)
				return
			}
			_, _ = w.Write([]byte("-- MySQL dump 10.13"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	st := newStore("")
	sc := newScannerForTest(st)
	// 关闭递归隔离爬取效果;关掉大字典(MaxPerHost 小)以加速,爬取派生候选不受其限。
	sc.run(context.Background(), scanOptions{
		Targets: []string{srv.URL}, MaxPerHost: 30, Concurrency: 8, RatePerSec: 100,
		MaxDepth: 0, Crawl: true, MaxCrawlPages: 25,
	})

	hits := map[string]bool{}
	for _, h := range st.list() {
		hits[h.URL] = true
	}
	if !anyHasSuffix(hits, "/inc/config.php.bak") {
		t.Errorf("应由爬取派生命中 config.php.bak;hits=%v", keys(hits))
	}
	if !anyHasSuffix(hits, "/download/db.sql") {
		t.Errorf("应直接命中爬取发现的 db.sql;hits=%v", keys(hits))
	}
	// 活动页面 config.php 本身不应被报为命中。
	if anyHasSuffix(hits, "/inc/config.php") && !anyHasSuffix(hits, "/inc/config.php.bak") {
		t.Errorf("活动页面 config.php 不应被直接报为命中")
	}
}

func anyHasSuffix(m map[string]bool, suf string) bool {
	for k := range m {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
