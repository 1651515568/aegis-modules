package subdomain

import "redops/core"

func init() {
	core.MustRegister(New())
}
