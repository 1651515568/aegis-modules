package scandir

// similarity.go —— 动态软 404 的「响应体相似度」判定。
//
// 仅靠 Content-Length 挡不住「动态软 404」:站点对任意路径回 200 且把请求路径/时间戳/CSRF
// 回显进模板,长度每次漂移。业内工具(ffuf -ac / dirsearch DynamicContentParser / feroxbuster)
// 用响应体相似度区分「真实内容」与「模板页」。这里用轻量、可单测的 Sørensen–Dice 字节二元组
// 系数:与软 404 模板样本相似度 ≥ 阈值 → 判为同质模板页,抑制。只取头部样本,绝不下载整页。

const (
	simSampleCap  = 2048 // 相似度校准的头部采样上限(字节)
	simThreshold  = 0.92 // 与软 404 模板相似度 ≥ 此值 → 判为同质模板页(偏保守,避免误抑真实命中)
)

// headSample 取字节切片头部 ≤ simSampleCap 的拷贝(用于相似度比对,避免持有大 body)。
func headSample(b []byte) []byte {
	if len(b) <= simSampleCap {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	out := make([]byte, simSampleCap)
	copy(out, b[:simSampleCap])
	return out
}

// similarity 返回两段字节的 Sørensen–Dice 二元组相似度,范围 [0,1]。
// 1=几乎相同,0=毫无共同二元组。对长度漂移/少量回显鲁棒。
func similarity(a, b []byte) float64 {
	if len(a) < 2 || len(b) < 2 {
		if string(a) == string(b) {
			return 1
		}
		return 0
	}
	ca := bigramCounts(a)
	cb := bigramCounts(b)
	inter := 0
	for g, na := range ca {
		if nb, ok := cb[g]; ok {
			inter += min2(na, nb)
		}
	}
	total := (len(a) - 1) + (len(b) - 1)
	if total == 0 {
		return 1
	}
	return float64(2*inter) / float64(total)
}

// bigramCounts 统计字节二元组出现次数(uint16 键 = 两个相邻字节)。
func bigramCounts(s []byte) map[uint16]int {
	m := make(map[uint16]int, len(s))
	for i := 0; i+1 < len(s); i++ {
		g := uint16(s[i])<<8 | uint16(s[i+1])
		m[g]++
	}
	return m
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
