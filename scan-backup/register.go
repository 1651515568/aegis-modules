package backup

import "redops/core"

// 模块自注册 —— 被 main.go 的 `import _ "redops/modules/backup"` 触发。
func init() {
	core.MustRegister(New())
}
