package backup

// limiter.go —— 全局请求限速 + 429/503 自适应退避。
//
// 为什么需要:scanner 的并发信号量只限制「同时在飞的请求数」,不限制「每秒请求数」。
// 对真实目标高速打点会:① 触发 WAF / IP 封禁;② 更隐蔽的——真实存在的文件若被目标
// 的限流网关挡下会回 429/503,旧逻辑直接当「不存在」丢弃,造成漏报。本文件提供:
//   * limiter:进程内令牌间隔限速器,所有探测请求(含基线)统一过闸,平滑到 ~N req/s。
//   * penalize:命中 429/503 时把全局排程整体后推,让所有并发 goroutine 一起降速。
//   * retryAfterDelay:解析 Retry-After,否则指数退避——纯函数,便于回归。

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// limiter 是「最小间隔」限速器:相邻两次放行至少间隔 interval,等效平滑的 1/interval req/s。
// 相比令牌桶不允许突发,对目标更克制;并发再高也被限速收敛到设定速率。
type limiter struct {
	mu       sync.Mutex
	interval time.Duration    // 相邻请求最小间隔 = 1/rate
	next     time.Time        // 下一次可放行的最早时刻
	nowFn    func() time.Time // 时钟(测试可注入)
}

// newLimiter 按 ratePerSec 构造限速器。ratePerSec<=0 视为不限速(interval=0,reserve 恒返回 0)。
func newLimiter(ratePerSec float64) *limiter {
	var iv time.Duration
	if ratePerSec > 0 {
		iv = time.Duration(float64(time.Second) / ratePerSec)
	}
	return &limiter{interval: iv, nowFn: time.Now}
}

// reserve 预定一个放行槽位,返回调用方需等待的时长,并把排程推进一个 interval。
// 不睡眠、仅依赖 nowFn —— 便于单测验证间隔与退避叠加。
func (l *limiter) reserve() time.Duration {
	if l.interval <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFn()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	return wait
}

// wait 阻塞到预定槽位;ctx 取消则立即返回其错误(扫描可被随时取消)。
func (l *limiter) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d := l.reserve()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// penalize 把全局排程整体后推 d —— 收到 429/503 时调用,使所有并发 goroutine 一起降速。
// 为避免单个慢主机冻结整轮多目标扫描,调用方应对 d 取一个温和上限(见 globalPenaltyCap)。
func (l *limiter) penalize(d time.Duration) {
	if d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	base := l.next
	now := l.nowFn()
	if base.Before(now) {
		base = now
	}
	l.next = base.Add(d)
}

// 退避参数。
const (
	maxRetries       = 3                      // 429/503 最多重试次数
	backoffBase      = 500 * time.Millisecond // 指数退避基数:0.5s,1s,2s…
	backoffCap       = 20 * time.Second       // 单次重试等待上限(含 Retry-After)
	globalPenaltyCap = 3 * time.Second        // 全局降速单次后推上限,避免冻结多目标扫描

	maxNetRetries = 2                      // 瞬时网络错误(连接重置/超时)最多重试次数
	netRetryBase  = 250 * time.Millisecond // 网络错误退避基数:0.25s,0.5s…
	netRetryCap   = 2 * time.Second        // 网络错误单次退避上限
)

// netRetryDelay 计算第 attempt 次网络错误重试前的退避时长(指数,夹在 [base, cap])。纯函数。
func netRetryDelay(attempt int) time.Duration {
	d := netRetryBase
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= netRetryCap {
			return netRetryCap
		}
	}
	if d > netRetryCap {
		return netRetryCap
	}
	return d
}

// retryAfterDelay 计算第 attempt 次重试(从 0 计)前应等待的时长。
// 优先采信整数秒形式的 Retry-After 头;否则指数退避。结果夹在 [backoffBase, backoffCap]。
// 纯函数,不读时钟 —— HTTP-date 形式的 Retry-After(少见于 429)不解析,退回指数退避。
func retryAfterDelay(retryAfter string, attempt int) time.Duration {
	if secs, err := strconv.Atoi(trimSpace(retryAfter)); err == nil && secs >= 0 {
		d := time.Duration(secs) * time.Second
		return clampDelay(d)
	}
	// 指数退避:base * 2^attempt。
	d := backoffBase
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= backoffCap {
			break
		}
	}
	return clampDelay(d)
}

func clampDelay(d time.Duration) time.Duration {
	if d < backoffBase {
		return backoffBase
	}
	if d > backoffCap {
		return backoffCap
	}
	return d
}

// isThrottle 判定状态码是否为「被限流/暂时不可用」——需退避重试,绝不当作「不存在」。
func isThrottle(code int) bool {
	return code == 429 || code == 503
}

// trimSpace 避免为单行解析引入 strings 包级耦合(Retry-After 可能带前后空格)。
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
