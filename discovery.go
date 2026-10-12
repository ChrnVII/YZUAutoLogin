package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipDirectProbes are connectivity probes addressed by a literal IP.
//
// They exist because the configured probe normally uses a host name, so a broken
// resolver hides the portal completely: the request dies during the lookup and
// never reaches the HTTP exchange the portal would intercept. On the campus
// network behind a relay router this is exactly what happened — the log filled up
// with "no such host" and the redirect never had a chance to occur.
//
// Each entry carries the status a healthy answer has. A bare GET to a resolver
// has a fixed, well-known reply — AliDNS and DNSPod both answer 404 with a tiny
// body — and that reply is the only thing separating "the internet answered"
// from "the portal answered in its place"; without it any 200 page counts as
// proof of connectivity. Cloudflare's 1.1.1.1 answers 301 and is frequently
// throttled from mainland campus networks, and 114DNS does not answer HTTP on
// port 80 at all (measured: connection never completes), so both were dropped.
//
// The list is a variable rather than a constant so tests can point it at a local
// server and keep the suite offline.
var ipDirectProbes = []probeTarget{
	{url: "http://223.5.5.5/", expectedStatus: http.StatusNotFound, timeout: ipProbeTimeout, onlineWhenNormal: true},
	{url: "http://119.29.29.29/", expectedStatus: http.StatusNotFound, timeout: ipProbeTimeout, onlineWhenNormal: true},
}

// probeTarget is one candidate address for a connectivity probe.
type probeTarget struct {
	url          string
	expectedText string
	// expectedStatus, when non-zero, is the status code a healthy response must
	// carry. Zero means "do not check".
	//
	// It matters most for IP-literal probes, which cannot ship a fixed body to
	// compare against. Without it there is nothing to compare a reply with, so
	// any 200 counted as proof of connectivity — which is exactly how a portal
	// that answers the probe with its own interstitial page, instead of an HTTP
	// redirect, stayed invisible and the machine never signed in.
	expectedStatus int
	timeout        time.Duration
	// onlineWhenNormal marks a target whose ordinary response proves the machine
	// really has internet access. It is false for the default gateway: a router
	// keeps serving its own web interface while the uplink is dead, so a normal
	// reply from it is not evidence of connectivity.
	onlineWhenNormal bool
}

type probeFailure struct {
	kind string
	err  error
}

// discovery is the outcome of one probe pass.
type discovery struct {
	online     bool
	captive    bool
	portalURL  string
	gateway    string
	hasGateway bool
	failures   []probeFailure
	// primaryFailureKind records why the configured probe failed even when a
	// later target succeeded, because that still means the resolver is broken
	// rather than the link being down.
	primaryFailureKind string
}

// configuredProbeTarget is the candidate described by the WebUI settings. The
// expected status and body both travel with the target, because they are what
// tells a healthy reply apart from a portal answering in its place.
func configuredProbeTarget(cfg Config) probeTarget {
	return probeTarget{
		url:              cfg.ProbeURL,
		expectedText:     cfg.ProbeExpectedText,
		expectedStatus:   cfg.ProbeExpectedStatus,
		timeout:          defaultProbeTimeout,
		onlineWhenNormal: true,
	}
}

// buildProbeTargets orders the candidates from most to least authoritative: the
// configured probe, then the default gateway, then the IP literals. The gateway
// comes before the generic IP probes because a portal hosted on the gateway
// answers with the full /eportal/index.jsp session query that login needs.
func buildProbeTargets(cfg Config, gateway string, hasGateway bool) []probeTarget {
	targets := []probeTarget{configuredProbeTarget(cfg)}
	seen := map[string]bool{strings.ToLower(cfg.ProbeURL): true}
	add := func(target probeTarget) {
		key := strings.ToLower(target.url)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, target)
	}
	if hasGateway {
		add(probeTarget{url: "http://" + gateway + "/", timeout: gatewayProbeTimeout})
	}
	for _, candidate := range ipDirectProbes {
		add(candidate)
	}
	return targets
}

// discoverPortal probes every candidate in order and stops at the first
// definitive answer. A target that cannot be reached no longer aborts the pass:
// its failure is recorded and the next candidate is tried, which is what lets an
// IP literal carry the check when the configured host name cannot be resolved.
func discoverPortal(ctx context.Context, cfg Config) discovery {
	gatewayCtx, cancel := context.WithTimeout(ctx, gatewayQueryTimeout)
	gateway, ok := defaultGateway(gatewayCtx)
	cancel()
	return discoverWithGateway(ctx, cfg, gateway, ok)
}

// discoverWithGateway is discoverPortal with the routing table supplied by the
// caller, so tests can describe a network without touching the host.
func discoverWithGateway(ctx context.Context, cfg Config, gateway string, hasGateway bool) discovery {
	found := discovery{gateway: gateway, hasGateway: hasGateway}

	for index, target := range buildProbeTargets(cfg, gateway, hasGateway) {
		result, err := probeTargetURL(ctx, cfg, target)
		if err != nil {
			failure := probeFailure{kind: classifyNetworkError(err), err: err}
			found.failures = append(found.failures, failure)
			if index == 0 {
				found.primaryFailureKind = failure.kind
			}
			continue
		}
		if result.captive {
			found.captive = true
			if result.portalURL != "" {
				found.portalURL = result.portalURL
				return found
			}
			// The portal was detected but the redirect carried no address to sign
			// in to. A later candidate may still name it.
			continue
		}
		if target.onlineWhenNormal {
			found.online = true
			return found
		}
	}
	return found
}

// classifyNetworkError reduces a probe failure to a short, stable reason. Every
// failure used to be logged as a bare "探测失败", which made a DNS outage
// indistinguishable from a link outage and hid the fact that the resolver, not
// the network, was the broken part.
func classifyNetworkError(err error) string {
	if err == nil {
		return "未知错误"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "DNS 解析超时"
		}
		return "DNS 解析失败"
	}
	if errors.Is(err, context.Canceled) {
		return "探测已取消"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "连接超时"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "连接超时"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "无法建立连接"
	}
	return "请求失败"
}

// hasDNSFailure reports whether any candidate died during name resolution, which
// is the one class of failure a flushdns can plausibly fix.
func (d discovery) hasDNSFailure() bool {
	for _, failure := range d.failures {
		if strings.HasPrefix(failure.kind, "DNS") {
			return true
		}
	}
	return false
}

const maxFailureSummaryRunes = 400

// failureSummary lists every failed candidate with its reason, keeping the raw
// error text for the log where it is valuable for diagnosis.
func (d discovery) failureSummary() string {
	if len(d.failures) == 0 {
		return "未发现可用网络"
	}
	parts := make([]string, 0, len(d.failures))
	for _, failure := range d.failures {
		parts = append(parts, fmt.Sprintf("%s（%v）", failure.kind, failure.err))
	}
	summary := strings.Join(parts, "；")
	runes := []rune(summary)
	if len(runes) > maxFailureSummaryRunes {
		return string(runes[:maxFailureSummaryRunes]) + "…"
	}
	return summary
}

// failureKinds condenses the same information into the short form shown on the
// WebUI status line, where a list of raw errors would not fit.
func (d discovery) failureKinds() string {
	if len(d.failures) == 0 {
		return "未发现可用网络"
	}
	counts := make(map[string]int, len(d.failures))
	order := make([]string, 0, len(d.failures))
	for _, failure := range d.failures {
		if counts[failure.kind] == 0 {
			order = append(order, failure.kind)
		}
		counts[failure.kind]++
	}
	parts := make([]string, 0, len(order))
	for _, kind := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", kind, counts[kind]))
	}
	return strings.Join(parts, "，")
}

// dhcpGate throttles the one destructive recovery step. Losing the lease drops
// every connection the machine holds, so the restart is rate limited instead of
// being repeated on every probe cycle.
type dhcpGate struct {
	mu   sync.Mutex
	last time.Time
}

func (g *dhcpGate) allow(now time.Time, cooldown time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.last.IsZero() && now.Sub(g.last) < cooldown {
		return false
	}
	g.last = now
	return true
}

// recoveryStep is the remedy a failed probe pass earns, ordered by how much
// disruption it causes.
type recoveryStep int

const (
	// recoveryNone leaves the network alone: a reachable gateway that merely
	// fails to resolve names is not something a lease restart can fix, and the
	// restart would cut every open connection for nothing.
	recoveryNone recoveryStep = iota
	// recoveryFlushDNS clears the resolver cache and probes again.
	recoveryFlushDNS
	// recoveryRestartDHCP drops and reacquires the lease. It is the only step
	// that interrupts connectivity.
	recoveryRestartDHCP
)

// recoveryFor maps a failed pass to the least disruptive remedy that can
// plausibly explain it.
//
// The ordering is the safety property of the whole recovery path: a present
// default route proves the link works, so the adapter must be left alone and only
// the resolver cache may be cleared. Dropping the lease is reserved for the case
// where the routing table is genuinely empty.
func recoveryFor(failed discovery) recoveryStep {
	if failed.hasGateway {
		if failed.hasDNSFailure() {
			return recoveryFlushDNS
		}
		return recoveryNone
	}
	return recoveryRestartDHCP
}
