package osintfofa

import "redops/core"

// 模块自注册 —— 被 main.go 的 `import _ "redops/modules/osint-fofa"` 触发。
func init() {
	core.MustRegister(New())
}
