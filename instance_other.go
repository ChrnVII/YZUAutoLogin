//go:build !windows

package main

import "errors"

// The application targets Windows. Keeping a no-op implementation lets the
// protocol and configuration tests compile on other operating systems.
var errAlreadyRunning = errors.New("YZU Auto Login 已在运行")

func acquireInstanceLock() (func(), error) {
	return func() {}, nil
}

func acquireInstanceLockNamed(string) (func(), error) {
	return func() {}, nil
}
