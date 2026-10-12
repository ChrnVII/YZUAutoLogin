package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultProbeTimeout bounds the connectivity probe configured in the WebUI.
	defaultProbeTimeout = 12 * time.Second
	// gatewayProbeTimeout is shorter than the configured probe: the default
	// gateway is on the local link, so a slow reply already means "not a portal".
	gatewayProbeTimeout = 5 * time.Second
	// ipProbeTimeout is shorter still: a portal that intercepts HTTP answers an
	// IP literal immediately.
	ipProbeTimeout = 4 * time.Second
	// gatewayQueryTimeout bounds one routing-table read.
	gatewayQueryTimeout = 5 * time.Second
	// gatewayPollInterval is the polling step used while waiting for the route
	// table to converge after a DHCP restart.
	gatewayPollInterval = time.Second
	// gatewayWaitTimeout is how long a DHCP restart is given to produce a route.
	gatewayWaitTimeout = 20 * time.Second
	// dhcpRestartTimeout bounds ipconfig /release followed by ipconfig /renew.
	dhcpRestartTimeout = 120 * time.Second
	// dhcpRestartCooldown throttles DHCP restarts. Without it a short probe
	// interval could drop the adapter again while the previous restart is still
	// converging, turning one outage into a flapping link.
	dhcpRestartCooldown = 5 * time.Minute
)

// parseDefaultGateway extracts the IPv4 default gateway from `route print -4`
// output and returns the lowest-metric one.
//
// Only the data columns are inspected, never the headers, so a localized Windows
// installation is parsed exactly like an English one: the destination and netmask
// columns of a default route are always the literal 0.0.0.0, and a row whose
// gateway column is not an IPv4 literal — the localized "on-link" marker of an
// interface route, for instance — is skipped. The interface column must also be
// an IPv4 literal, which excludes the Interface List section at the top of the
// output.
func parseDefaultGateway(output string) (string, bool) {
	gateway := ""
	gatewayMetric := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		gatewayIP := net.ParseIP(fields[2]).To4()
		if gatewayIP == nil || net.ParseIP(fields[3]).To4() == nil {
			continue
		}
		metric := 0
		if len(fields) >= 5 {
			if parsed, err := strconv.Atoi(fields[4]); err == nil {
				metric = parsed
			}
		}
		if gateway == "" || metric < gatewayMetric {
			gateway, gatewayMetric = gatewayIP.String(), metric
		}
	}
	return gateway, gateway != ""
}

// waitForGateway polls the routing table until a default gateway appears or the
// context expires.
//
// Polling is required rather than a single read: ipconfig /renew can return
// before the adapter, the ARP cache and the route table have converged, and one
// immediate lookup would report a false failure that costs another DHCP restart.
func waitForGateway(ctx context.Context) (string, bool) {
	ticker := time.NewTicker(gatewayPollInterval)
	defer ticker.Stop()
	for {
		if gateway, ok := defaultGateway(ctx); ok {
			return gateway, true
		}
		select {
		case <-ctx.Done():
			return "", false
		case <-ticker.C:
		}
	}
}

// firstLine condenses command output so a multi-line ipconfig report cannot
// flood a single log entry.
func firstLine(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
