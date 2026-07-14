package portscan

// blackrock.go —— 借鉴 masscan 的随机化扫描顺序。
//
// masscan 不按 host→port 顺序扫(那样会连续锤同一台主机),而是在整个
// 「主机 × 端口」索引空间 [0, N) 上做一个无状态的伪随机置换,按置换顺序遍历,
// 从而把压力均匀打散到所有目标上、更隐蔽、对多目标更均衡。
//
// 这里用一个「平衡 Feistel 网络 + 循环游走(cycle-walking)」实现 [0,N) 上的
// 双射置换:无需存下整张乱序表(O(1) 空间),给定下标 i 即可算出第 i 个元素。
// 平衡 Feistel 配模加法对任意轮函数都可逆,故一定是双射(不漏扫、不重扫)——
// 这一点由 blackrock_test.go 的覆盖性测试守住。

import "math"

type permutation struct {
	n      uint64 // 真实元素数
	s      uint64 // 边长:ceil(sqrt(n)),Feistel 域为 s*s
	seed   uint64
	rounds int
}

func newPermutation(n, seed uint64) *permutation {
	s := uint64(math.Ceil(math.Sqrt(float64(n))))
	if s == 0 {
		s = 1
	}
	return &permutation{n: n, s: s, seed: seed, rounds: 4}
}

// at 返回置换的第 i 个元素(i、返回值均在 [0,n))。
func (p *permutation) at(i uint64) uint64 {
	x := p.feistel(i)
	for x >= p.n { // 循环游走:落在 [n, s*s) 的结果继续置换,直到回到 [0,n)
		x = p.feistel(x)
	}
	return x
}

// feistel 是 [0, s*s) 上的双射置换。
func (p *permutation) feistel(x uint64) uint64 {
	l := x % p.s
	r := x / p.s
	for i := 0; i < p.rounds; i++ {
		l, r = r, (l+p.round(r, i))%p.s
	}
	return r*p.s + l
}

func (p *permutation) round(r uint64, i int) uint64 {
	return mix(r^p.seed^(uint64(i)*0x100000001b3)) % p.s
}

// mix 是 splitmix64 风格的整数雪崩散列(轮函数用,非密码学强度)。
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}
