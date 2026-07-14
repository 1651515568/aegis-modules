package backup

// similarity.go —— soft-404 站点的「响应体相似度校准」。
//
// 背景:对「什么都回 200」的 soft-404 站点,仅靠 Content-Length 容易误判 —— 动态模板页会
// 因把请求路径回显进页面而长度漂移。业内工具(ffuf -ac / dirsearch)用响应体相似度来区分
// 「真实文件」与「模板页」。这里实现一个轻量、可单测的相似度判定:
//   * 仅在 soft-404(blanket200)且无法靠魔数判定时启用;
//   * 仅读取 ≤calibrateSampleCap 字节头部(远小于文件体,绝不下载完整文件);
//   * 用 Sørensen–Dice 字节二元组系数:与模板样本相似度 < 阈值 → 判为真实文件。

const (
	// 采样上限从 512 提升至 2048：更长的样本使二元组比较更准确，
	// 尤其对把请求路径回显进模板的动态 soft-404 页面效果更好。
	calibrateSampleCap = 2048
	// 相似度阈值从 0.7 提升至 0.85：只有与 soft-404 模板 ≥85% 相似才判为模板页并过滤。
	// 备份文件（.zip/.sql/.env 等）与 HTML 404 模板相似度通常 <0.2，提高阈值不增加误报，
	// 但能显著减少 0.7~0.85 灰色地带的漏报。
	calibrateThreshold = 0.85
)

// similarity 返回两段字节的 Sørensen–Dice 二元组相似度,范围 [0,1]。
// 1=几乎相同,0=毫无共同二元组。对长度漂移/少量回显鲁棒。
func similarity(a, b []byte) float64 {
	if len(a) < 2 || len(b) < 2 {
		// 太短无法构成二元组:退化为「完全相等?」判断。
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
