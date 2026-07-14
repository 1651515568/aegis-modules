package backup

// resume_test.go —— 断点续扫:跳过已完成目标 + 任务进度持久化。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// envServer 返回一个对 /.env 给命中、其它干净 404 的回环服务器。
func envServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			if r.Method == http.MethodHead {
				w.WriteHeader(200)
				return
			}
			_, _ = w.Write([]byte("DB_PASSWORD=secret"))
			return
		}
		http.NotFound(w, r)
	}))
}

func TestResumeSkipsCompletedTargets(t *testing.T) {
	srvA := envServer()
	srvB := envServer()
	defer srvA.Close()
	defer srvB.Close()
	hostA := mustTarget(t, srvA.URL).Host

	st := newStore("")
	sc := newScannerForTest(st)
	// 续扫:跳过 A,只扫 B。
	sc.runScan(context.Background(), scanOptions{
		Targets: []string{srvA.URL, srvB.URL}, MaxPerHost: 500, Concurrency: 8,
		RatePerSec: 100, MaxDepth: 0, Crawl: false,
	}, map[string]bool{hostA: true})

	for _, h := range st.list() {
		if strings.HasPrefix(h.URL, srvA.URL) {
			t.Errorf("已完成目标 A 不应被探测: %s", h.URL)
		}
	}
	foundB := false
	for _, h := range st.list() {
		if strings.HasPrefix(h.URL, srvB.URL) && strings.HasSuffix(h.URL, "/.env") {
			foundB = true
		}
	}
	if !foundB {
		t.Errorf("应命中目标 B 的 /.env;hits=%d", len(st.list()))
	}
}

func TestJobCheckpointAndResumable(t *testing.T) {
	srv := envServer()
	defer srv.Close()
	host := mustTarget(t, srv.URL).Host

	dir := t.TempDir()
	st := newStore(filepath.Join(dir, "hits.json"))
	sc := newScannerForTest(st)

	opt := scanOptions{Targets: []string{srv.URL}, MaxPerHost: 500, Concurrency: 8, RatePerSec: 100, MaxDepth: 0}
	st.setJob(&scanJob{Opts: opt, Status: "running"})
	sc.runScan(context.Background(), opt, nil)

	// 任务应落盘:目标完成、状态 done、不可续扫。
	j := st.loadJob()
	if j == nil || !contains(j.Completed, host) {
		t.Fatalf("job.Completed 应含已完成目标 %q,得到 %+v", host, j)
	}
	if j.Status != "done" {
		t.Errorf("完成后 status 应为 done,得到 %q", j.Status)
	}
	if st.status().Resumable {
		t.Error("全部完成后不应标记可续扫")
	}
}

func TestResumableAfterCancel(t *testing.T) {
	// 模拟「扫了一半被取消、仍有剩余目标」→ 应可续扫。
	st := newStore("")
	st.setJob(&scanJob{
		Opts:      scanOptions{Targets: []string{"a.com", "b.com", "c.com"}},
		Completed: []string{"a.com"},
		Status:    "canceled",
	})
	if !st.status().Resumable {
		t.Error("有剩余目标且未完成 → 应可续扫")
	}
	job, done := st.resumeInfo()
	if job == nil || !done["a.com"] || done["b.com"] {
		t.Errorf("resumeInfo 应返回任务且已完成集合含 a.com 不含 b.com,得到 %v", done)
	}
}
