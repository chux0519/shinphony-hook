//go:build linux || darwin

package main

import "errors"

func supervise(dir, creds string) error { return errors.New("use_native_service_manager") }
