package backup

// recurse_test.go —— 用回环 httptest 验证递归目录发现:
// 站点根没有命中,但 /uploads/ 目录存在、其下藏着 backup.sql —— 只有递归能挖出来。
// 同时验证递归受 soft-404 门控:对什么都回 200 的站点不递归(防爆炸)。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"redops/core"
)

// noopLogger 满足 core.Logger,测试中静默。
type noopLogger struct{}

func (noopLogger) Info(string, ...any)       {}
func (noopLogger) Warn(string, ...any)       {}
func (noopLogger) Error(string, ...any)      {}
func (n noopLogger) With(...any) core.Logger { return n }

func newScannerForTest(st *store) *scanner { return newScanner(noopLogger{}, st) }

func TestRecursiveDiscoveryFindsNestedBackup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/uploads/": // 目录存在
			w.WriteHeader(http.StatusOK)
		case "/uploads/backup.sql": // 藏在目录里的真实命中
			w.Header().Set("Content-Type", "application/sql")
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("-- MySQL dump 10.13 ..."))
		default:
			http.NotFound(w, r) // 干净 404
		}
	}))
	defer srv.Close()

	st := newStore("") // 不落盘
	sc := newScannerForTest(st)
	// MaxPerHost 故意调小:递归目录探测不受 MaxPerHost 限制,因此根候选小也能挖到 uploads/。
	sc.run(context.Background(), scanOptions{
		Targets: []string{srv.URL}, MaxPerHost: 50, Concurrency: 8, RatePerSec: 100, MaxDepth: 1,
	})

	found := false
	for _, h := range st.list() {
		if strings.Contains(h.URL, "/uploads/backup.sql") {
			found = true
		}
	}
	if !found {
		t.Fatalf("递归应在 /uploads/ 下挖出 backup.sql,但未命中;共 %d 条命中", len(st.list()))
	}
}

func TestRecursionDisabledOnSoftFour04(t *testing.T) {
	// 对「什么都回 200」的 soft-404 站点:即便 /uploads/backup.sql 真存在,
	// 也不应递归(base.clean404=false → 目录探测被门控关闭),避免误判爆炸。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>generic page padding padding padding</html>"))
	}))
	defer srv.Close()

	st := newStore("")
	sc := newScannerForTest(st)
	sc.run(context.Background(), scanOptions{
		Targets: []string{srv.URL}, MaxPerHost: 50, Concurrency: 8, RatePerSec: 100, MaxDepth: 2,
	})

	for _, h := range st.list() {
		if strings.Contains(h.URL, "/uploads/") {
			t.Fatalf("soft-404 站点不应递归进 uploads/,却命中 %s", h.URL)
		}
	}
}

// TestAcceptCalibratedBodySimilarity 直接验证相似度校准:soft-404 站点上,
// 与模板页相似的路径被拒绝、内容迥异的真实文件被采信。
func TestAcceptCalibratedBodySimilarity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/real") { // 真实文件:内容与模板迥异
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("PK\x03\x04 totally different binary archive bytes here padding padding"))
			return
		}
		// 其它一切回模板页(把路径回显进去,制造长度漂移的 soft-404)。
		_, _ = w.Write([]byte("<html><body>404 Not Found: " + r.URL.Path + " does not exist on this server</body></html>"))
	}))
	defer srv.Close()

	sc := newScannerForTest(newStore(""))
	sc.lim = newLimiter(0)
	client := buildClient(scanOptions{TimeoutMs: 5000})
	base := baseline{
		blanket200: true,
		sample:     []byte("<html><body>404 Not Found: /rdx404-xxxx does not exist on this server</body></html>"),
	}

	// 真实文件 → 与模板不相似 → 采信。
	if !sc.acceptCalibrated(context.Background(), client, srv.URL+"/real-backup.zip", base, "", 64) {
		t.Error("内容迥异的真实文件应被相似度校准采信")
	}
	// 模板页路径 → 与模板高度相似 → 拒绝。
	if sc.acceptCalibrated(context.Background(), client, srv.URL+"/whatever.zip", base, "", 64) {
		t.Error("与 soft-404 模板相似的响应应被拒绝(否则误报)")
	}
}
