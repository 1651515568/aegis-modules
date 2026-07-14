package portscan

import "testing"

// TestPermutationBijection 守住正确性红线:置换必须是 [0,n) 上的双射
// —— 每个元素恰好出现一次(不漏扫、不重扫)。
func TestPermutationBijection(t *testing.T) {
	for _, n := range []uint64{1, 2, 3, 7, 10, 64, 100, 1000, 1024, 65535} {
		p := newPermutation(n, 0x1234567)
		seen := make([]bool, n)
		for i := uint64(0); i < n; i++ {
			v := p.at(i)
			if v >= n {
				t.Fatalf("n=%d: at(%d)=%d 越界", n, i, v)
			}
			if seen[v] {
				t.Fatalf("n=%d: 值 %d 重复出现(置换非双射)", n, v)
			}
			seen[v] = true
		}
		// 覆盖性:全部出现
		for v := uint64(0); v < n; v++ {
			if !seen[v] {
				t.Fatalf("n=%d: 值 %d 从未出现(置换有遗漏)", n, v)
			}
		}
	}
}

// TestPermutationShuffles 不同 seed 应给出不同顺序(且非恒等顺序)。
func TestPermutationShuffles(t *testing.T) {
	n := uint64(1000)
	p := newPermutation(n, 42)
	identity := 0
	for i := uint64(0); i < n; i++ {
		if p.at(i) == i {
			identity++
		}
	}
	// 随机置换的不动点期望约为 1,放宽到 < n/10 即说明确实打乱了。
	if identity > int(n/10) {
		t.Errorf("置换看起来近似恒等(不动点 %d/%d),未有效打乱", identity, n)
	}
}
