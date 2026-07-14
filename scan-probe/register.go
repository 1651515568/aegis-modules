package probe

import "redops/core"

func init() {
	core.MustRegister(New())
}
