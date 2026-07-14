package assetcollect

import "redops/core"

func init() {
	core.MustRegister(New())
}
