//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// networkRecoveryAvailable reports whether this build can inspect the routing
// table and restart the DHCP lease. Both rely on Windows tooling.
const networkRecoveryAvailable = true

// createNoWindow keeps helper processes from flashing a console: the application
// is linked with -H=windowsgui and owns no console of its own.
const createNoWindow = 0x08000000

func runHidden(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// defaultGateway reads the IPv4 default gateway of the machine from the routing
// table. Parsing lives in parseDefaultGateway so it can be tested on any
// platform; this wrapper only supplies the command output.
func defaultGateway(ctx context.Context) (string, bool) {
	output, err := runHidden(ctx, "route", "print", "-4")
	if err != nil {
		return "", false
	}
	return parseDefaultGateway(output)
}

// flushDNS clears the resolver cache. It has no side effects, which is why it is
// attempted before anything that interrupts connectivity.
func flushDNS(ctx context.Context) bool {
	_, err := runHidden(ctx, "ipconfig", "/flushdns")
	return err == nil
}

// restartDHCP releases and renews every DHCP lease on the machine.
//
// This is the one destructive step in the recovery path: the host loses its
// address and every open connection the moment /release runs, and stays
// unreachable until /renew completes. It is only reached after the routing table
// has been confirmed empty, and the caller additionally throttles it with a gate,
// so it can never be triggered by a merely unhealthy internet connection.
func restartDHCP(ctx context.Context) error {
	if output, err := runHidden(ctx, "ipconfig", "/release"); err != nil {
		return fmt.Errorf("ipconfig /release 失败: %w（%s）", err, firstLine(output))
	}
	if output, err := runHidden(ctx, "ipconfig", "/renew"); err != nil {
		return fmt.Errorf("ipconfig /renew 失败: %w（%s）", err, firstLine(output))
	}
	return nil
}
