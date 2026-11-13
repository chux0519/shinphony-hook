//go:build windows

package main

import "context"

// Named pipes are not files in a temp directory; nothing to guard.
func watchSocket(context.Context, string) <-chan error { return make(chan error) }
