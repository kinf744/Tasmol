//go:build tools

// Package tools pins tool dependencies so `go mod tidy` keeps them.
// gomobile's gobind must resolve golang.org/x/mobile/bind from this
// module when binding golib/vpnlib.
package tools

import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
)
