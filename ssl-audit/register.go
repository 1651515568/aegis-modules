package sslaudit

import "redops/core"

// 模块自注册 —— 被 main.go 的 blank import 触发（go generate 自动生成）。
func init() {
	core.MustRegister(New())
}
