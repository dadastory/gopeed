package bt

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/GopeedLab/gopeed/pkg/base"
	model "github.com/GopeedLab/gopeed/pkg/protocol/bt"
	"github.com/anacrolix/torrent/iplist"
)

type outboundPolicy struct {
	allowedHosts map[string]struct{}
	allowedCIDRs []netip.Prefix
}

var (
	cgnatPrefix   = netip.MustParsePrefix("100.64.0.0/10")
	cloudMetadata = netip.MustParseAddr("169.254.169.254")
)

func bitTorrentOutboundPolicy(opts *base.Options) *outboundPolicy {
	if opts == nil {
		return nil
	}
	extra, ok := opts.Extra.(*model.OptsExtra)
	if !ok || extra.NetworkPolicy == nil {
		return nil
	}
	p := &outboundPolicy{allowedHosts: make(map[string]struct{})}
	for _, host := range extra.NetworkPolicy.AllowedHosts {
		if normalized := normalizeHost(host); normalized != "" {
			p.allowedHosts[normalized] = struct{}{}
		}
	}
	for _, raw := range extra.NetworkPolicy.AllowedCIDRs {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			p.allowedCIDRs = append(p.allowedCIDRs, prefix.Masked())
		}
	}
	return p
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
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

func (p *outboundPolicy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, fmt.Errorf("outbound host is empty")
	}
	if _, ok := p.allowedHosts[normalized]; ok {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", normalized)
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
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", normalized)
	if err != nil {
		return nil, err
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
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() || addr.IsMulticast() || (addr.Is4() && (cgnatPrefix.Contains(addr) || cloudMetadata == addr)) {
		return fmt.Errorf("outbound address %s is not allowed", addr)
	}
	return nil
}

// effectiveAddr unwraps IPv4 transition mechanisms before classification so a
// globally-looking IPv6 wrapper cannot route a BitTorrent peer to a private
// IPv4 target. Keep this in parity with the HTTP protocol policy.
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

// Lookup implements anacrolix's IP blocklist interface. BitTorrent peer
// discovery yields addresses rather than hostnames, so CIDR policy is applied
// again immediately before a peer is admitted.
func (p *outboundPolicy) Lookup(ip net.IP) (iplist.Range, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || p.validateAddr(addr) != nil {
		return iplist.Range{Description: "blocked by task outbound policy"}, true
	}
	return iplist.Range{}, false
}

func (p *outboundPolicy) NumRanges() int { return 0 }
