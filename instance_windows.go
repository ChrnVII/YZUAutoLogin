//go:build windows

package main

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

const instanceMutexName = `Local\YZUAutoLogin-2B6FA46C-045B-4825-8B5F-8606F32DA56`

var errAlreadyRunning = errors.New("YZU Auto Login 已在运行")

// acquireInstanceLock ensures there is only one tray/monitor instance in the
// current Windows session. The handle is deliberately retained for the
// process lifetime; closing it releases the named mutex.
func acquireInstanceLock() (func(), error) {
	return acquireInstanceLockNamed(instanceMutexName)
}

func acquireInstanceLockNamed(name string) (func(), error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("创建单实例锁名称失败: %w", err)
	}
	handle, err := windows.CreateMutex(nil, false, name16)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(handle)
		return nil, errAlreadyRunning
	}
	if err != nil {
		return nil, fmt.Errorf("创建单实例锁失败: %w", err)
	}

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() { _ = windows.CloseHandle(handle) })
	}, nil
}
