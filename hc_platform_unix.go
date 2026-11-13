//go:build !windows

package main

import (
	"context"
	"net"
	"path/filepath"
	"strings"
)

func validHcSocket(s string) bool { return filepath.IsAbs(s) && !strings.ContainsAny(s, "\x00\r\n\t") }
func dialHc(ctx context.Context, s string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", s)
}
