package backup

// probe_test.go —— 用回环 httptest 验证「绝不下载文件体」这一核心安全承诺:
// 即便服务器忽略 Range、对一个超大文件直接回 200,doMagic 也只能从网络拉取 ≤16 字节。
// 这是模块对标业内工具的关键差异点(多数扫描器会下载整个响应体),必须有测试钉死。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDoMagicDoesNotDrainBodyOn200 起一个「无视 Range、回 200 并尝试吐出 8MB」的服务器,
// 分块 flush 并在每块前检查请求 ctx 是否已被客户端关闭。断言:服务器实际写出的字节数
// 远小于总量(说明客户端读到 16 字节即断开),且 doMagic 仍正确识别出 ZIP 魔数。
func TestDoMagicDoesNotDrainBodyOn200(t *testing.T) {
	const total = 8 << 20 // 8MB:远大于任何内核 socket 缓冲,能清晰区分「早断」与「拉完」
	const chunk = 4 << 10

	wrote := make(chan int64, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 故意无视 Range:不回 206、不带 Content-Range,直接 200 全量。
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("ResponseWriter 不支持 Flush")
			wrote <- -1
			return
		}
		buf := make([]byte, chunk)
		copy(buf, []byte{'P', 'K', 3, 4}) // 首块带 ZIP 魔数
		var sent int64
		for sent < total {
			if r.Context().Err() != nil { // 客户端已断开 → 立即停写
				break
			}
			n, err := w.Write(buf)
			sent += int64(n)
			if err != nil {
				break
			}
			fl.Flush()
		}
		wrote <- sent
	}))
	defer srv.Close()

	sc := &scanner{lim: newLimiter(0)} // 不限速
	client := buildClient(scanOptions{TimeoutMs: 5000})

	code, _, ctype, head := sc.doMagic(context.Background(), client, srv.URL)
	if code != http.StatusOK {
		t.Fatalf("期望 200,得到 %d", code)
	}
	if ctype != "application/zip" {
		t.Errorf("Content-Type 期望 application/zip,得到 %q", ctype)
	}
	if magicLabel(head) != "zip" {
		t.Errorf("应识别出 zip 魔数,head=%v", head)
	}

	select {
	case sent := <-wrote:
		// 核心断言:即使服务器想吐 8MB,客户端读到 16 字节即断,服务器实际写出远小于总量。
		if sent >= total {
			t.Fatalf("安全回归:doMagic 把整个 body 拉了下来(写出 %d / 共 %d 字节)——违背「绝不下载文件体」承诺", sent, total)
		}
		if sent > 1<<20 { // 给 socket 缓冲留足余量(<1MB),但仍 ≪ 8MB
			t.Errorf("doMagic 读取过多:服务器写出 %d 字节(应远小于 1MB)", sent)
		}
		t.Logf("✓ 服务器仅写出 %d 字节(总量 %d)——确认仅探头部,未下载文件体", sent, total)
	case <-time.After(8 * time.Second):
		t.Fatal("服务器未在预期时间内停写,可能仍在被拉取整个 body")
	}
}
