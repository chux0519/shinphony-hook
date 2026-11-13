//go:build windows

package main

import (
	"errors"
	"io"
)

func keysCLI(_ []string, _ io.Reader, _ io.Writer) error {
	return errors.New("keys_platform_not_supported")
}
