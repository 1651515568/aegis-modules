package webshell

import "redops/core"

func init() {
	core.MustRegister(New())
}
