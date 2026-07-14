package vulnscan

import "redops/core"

func init() {
	core.MustRegister(New())
}
