package backup

// jsmine_test.go —— 静态 JS 挖掘纯函数回归。

import (
	"strings"
	"testing"
)

func TestMineJS(t *testing.T) {
	body := []byte(`
		const api = "/api/v1/users";
		fetch('/data/export.sql');
		var r = {path: "config/db.js", icon: "logo.png", mime: "text/html"};
		import x from "../shared/util.js";
		const u = "https://cdn.other.com/lib.js"; // 跨域,后续被同源过滤
	`)
	got := mineJS(body)
	for _, w := range []string{"/api/v1/users", "/data/export.sql", "config/db.js", "../shared/util.js"} {
		if !contains(got, w) {
			t.Errorf("应挖掘出 %q,得到 %v", w, got)
		}
	}
	// 纯单词 / mime 类型不应被当路径。
	for _, bad := range []string{"text/html", "logo"} {
		if contains(got, bad) {
			t.Errorf("不应把 %q 当路径", bad)
		}
	}
}

func TestLooksLikePath(t *testing.T) {
	yes := []string{"/api/x", "config/db.js", "../a/b.sql", "static/js/main.js"}
	no := []string{"//cdn.com/a.js", "https://x.com/y", "text/html", "hello", "a b/c", "data:image/png"}
	for _, s := range yes {
		if !looksLikePath(s) {
			t.Errorf("%q 应判为路径", s)
		}
	}
	for _, s := range no {
		if looksLikePath(s) {
			t.Errorf("%q 不应判为路径", s)
		}
	}
}

func TestMineSourceMap(t *testing.T) {
	sm := []byte(`{"version":3,"sources":["webpack://app/./src/config/database.js","webpack://app/./node_modules/vue/dist/vue.js","./src/utils/helper.ts"],"names":[]}`)
	got := mineSourceMap(sm)
	if !contains(got, "src/config/database.js") {
		t.Errorf("应提取并归一化源码路径,得到 %v", got)
	}
	if !contains(got, "src/utils/helper.ts") {
		t.Errorf("应提取相对源码路径,得到 %v", got)
	}
	for _, g := range got {
		if strings.Contains(g, "node_modules") {
			t.Errorf("node_modules 应被跳过,得到 %q", g)
		}
	}
}
