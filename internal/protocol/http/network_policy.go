package http

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/GopeedLab/gopeed/pkg/protocol/http"
)

// outboundPolicy keeps request-scoped URL checks beside the transport which
// makes the check effective for redirects and for every DNS resolution.
type outboundPolicy struct {
	allowedHosts map[string]struct{}
	allowedCIDRs []netip.Prefix
	lookup       func(context.Context, string) ([]netip.Addr, error)
}

var (
	cgnatPrefix   = netip.MustParsePrefix("100.64.0.0/10")
	cloudMetadata = netip.MustParseAddr("169.254.169.254")
)

func newOutboundPolicy(policy *fhttp.NetworkPolicy) (*outboundPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	p := &outboundPolicy{allowedHosts: make(map[string]struct{}), lookup: lookupNetIP}
	for _, host := range policy.AllowedHosts {
		if normalized := normalizeHost(host); normalized != "" {
			p.allowedHosts[normalized] = struct{}{}
		}
	}
	for _, raw := range policy.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		p.allowedCIDRs = append(p.allowedCIDRs, prefix.Masked())
	}
	return p, nil
}

func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func (p *outboundPolicy) validateURL(ctx context.Context, u *url.URL) error {
	if u == nil || u.Hostname() == "" {
		return fmt.Errorf("outbound URL has no host")
	}
	_, err := p.resolve(ctx, u.Hostname())
	return err
}

func (p *outboundPolicy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, fmt.Errorf("outbound host is empty")
	}
	if _, ok := p.allowedHosts[normalized]; ok {
		return p.lookup(ctx, normalized)
	}
	if ip, err := netip.ParseAddr(normalized); err == nil {
		if err := p.validateAddr(ip); err != nil {
			return nil, err
		}
		return []netip.Addr{ip}, nil
	}
	if normalized == "localhost" || strings.HasSuffix(normalized, ".localhost") {
		return nil, fmt.Errorf("outbound host %q is local", host)
	}
	addrs, err := p.lookup(ctx, normalized)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("outbound host %q has no addresses", host)
	}
	for _, addr := range addrs {
		if err := p.validateAddr(addr); err != nil {
			return nil, err
		}
	}
	return addrs, nil
}

func (p *outboundPolicy) validateAddr(addr netip.Addr) error {
	addr = effectiveAddr(addr)
	for _, prefix := range p.allowedCIDRs {
		if prefix.Contains(addr) {
			return nil
		}
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() || addr.IsMulticast() {
		return fmt.Errorf("outbound address %s is not allowed", addr)
	}
	if addr.Is4() && (cgnatPrefix.Contains(addr) || cloudMetadata == addr) {
		return fmt.Errorf("outbound address %s is not allowed", addr)
	}
	return nil
}

// effectiveAddr unwraps IPv4 transition mechanisms before classification so a
// globally-looking IPv6 wrapper cannot route a task to a private IPv4 target.
func effectiveAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is4() {
		return addr
	}
	bytes := addr.As16()
	if bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b {
		return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
	}
	if bytes[0] == 0x20 && bytes[1] == 0x02 {
		return netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]})
	}
	if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0 {
		return netip.AddrFrom4([4]byte{bytes[12] ^ 0xff, bytes[13] ^ 0xff, bytes[14] ^ 0xff, bytes[15] ^ 0xff})
	}
	allZero := true
	for _, value := range bytes[:12] {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero && (bytes[12] != 0 || bytes[13] != 0 || bytes[14] != 0 || bytes[15] > 1) {
		return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
	}
	return addr
}

func (p *outboundPolicy) dialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split outbound address %q: %w", address, err)
		}
		addrs, err := p.resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, addr := range addrs {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("dial outbound host %q: %w", host, lastErr)
	}
}
