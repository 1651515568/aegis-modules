package scandir

import "redops/core"

// 模块自注册 —— 被自动生成的 modules_gen.go 中的
// `import _ "redops/modules/scan-dir"` 触发(由 `cd engine && go generate ./...` 维护)。
// 重复 id 会在启动时 panic,保证全局唯一。
func init() {
	core.MustRegister(New())
}
