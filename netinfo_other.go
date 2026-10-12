//go:build !windows

package main

import (
	"context"
	"errors"
)

// networkRecoveryAvailable is false here. Reading the routing table and
// restarting the DHCP lease both depend on Windows tooling, so other operating
// systems keep the probe-only behaviour the protocol tests were written against.
const networkRecoveryAvailable = false

// errNetworkRecoveryUnsupported is reported when a recovery step is attempted on
// a platform that cannot perform it.
var errNetworkRecoveryUnsupported = errors.New("当前系统不支持自动恢复网络")

func defaultGateway(context.Context) (string, bool) { return "", false }

func flushDNS(context.Context) bool { return false }

func restartDHCP(context.Context) error { return errNetworkRecoveryUnsupported }
