package jsextract

import "redops/core"

func init() {
	core.MustRegister(New())
}
