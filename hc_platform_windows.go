//go:build windows

package main

import (
	"context"
	"github.com/Microsoft/go-winio"
	"net"
	"strings"
)

func validHcSocket(s string) bool {
	return strings.HasPrefix(s, `\\.\pipe\`) && len(s) > 9 && !strings.ContainsAny(s, "\x00\r\n\t")
}
func dialHc(ctx context.Context, s string) (net.Conn, error) { return winio.DialPipeContext(ctx, s) }
