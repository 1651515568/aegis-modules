package backup

// similarity_test.go —— 相似度校准 / 网络退避 / 带日期候选生成的纯函数回归。

import (
	"strings"
	"testing"
	"time"
)

func TestSimilarity(t *testing.T) {
	tmpl := []byte("<html><body>404 Not Found: the requested page does not exist</body></html>")
	// 同模板、仅回显路径不同(长度漂移)→ 仍高度相似。
	tmplB := []byte("<html><body>404 Not Found: the requested /abc.zip does not exist</body></html>")
	realFile := []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00 binary zip archive content totally different")

	if s := similarity(tmpl, tmpl); s < 0.99 {
		t.Errorf("自身相似度应≈1,got %.3f", s)
	}
	if s := similarity(tmpl, tmplB); s < calibrateThreshold {
		t.Errorf("同模板(回显差异)应判为相似(≥%.2f),got %.3f", calibrateThreshold, s)
	}
	if s := similarity(tmpl, realFile); s >= calibrateThreshold {
		t.Errorf("真实文件应判为不相似(<%.2f),got %.3f", calibrateThreshold, s)
	}
	// 边界:过短输入。
	if similarity([]byte("a"), []byte("a")) != 1 {
		t.Error("相同单字节应为 1")
	}
	if similarity([]byte("a"), []byte("b")) != 0 {
		t.Error("不同单字节应为 0")
	}
}

func TestNetRetryDelay(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, netRetryBase},
		{1, 500 * time.Millisecond},
		{2, netRetryCap}, // 250→500→1000? 实际 0.25*2^2=1s,未达 cap;见下
	}
	// attempt2: 0.25s*2*2 = 1s,< cap(2s) → 1s。修正期望。
	cases[2].want = 1 * time.Second
	for _, c := range cases {
		if got := netRetryDelay(c.attempt); got != c.want {
			t.Errorf("netRetryDelay(%d)=%v want %v", c.attempt, got, c.want)
		}
	}
	if got := netRetryDelay(10); got != netRetryCap {
		t.Errorf("大 attempt 应夹到上限 %v,got %v", netRetryCap, got)
	}
}

func TestGenDatedCandidates(t *testing.T) {
	u := mustTarget(t, "https://acme-corp.com")
	cands := genDatedCandidates(u)
	if len(cands) == 0 {
		t.Fatal("应生成带日期候选")
	}
	// 主机名派生的带日期归档应在最前(价值优先)。
	if !strings.Contains(cands[0].rel, "acme") {
		t.Errorf("首批带日期候选应为主机名派生,got %q", cands[0].rel)
	}
	// 应包含形如 backup-2024.sql 的组合。
	want := map[string]bool{"backup-2024.sql": false, "db_2025.zip": false, "www2023.tar.gz": false}
	for _, c := range cands {
		if _, ok := want[c.rel]; ok {
			want[c.rel] = true
		}
	}
	for rel, seen := range want {
		if !seen {
			t.Errorf("带日期候选应包含 %q", rel)
		}
	}
}

func TestGenCandidatesIncludesDated(t *testing.T) {
	u := mustTarget(t, "https://example.com")
	cands := genCandidates(u, 12000, true)
	has := false
	for _, c := range cands {
		if strings.Contains(c.rel, "2024") {
			has = true
			break
		}
	}
	if !has {
		t.Error("genCandidates 大上限下应包含带日期候选")
	}
}
