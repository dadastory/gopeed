package http

import (
	"context"
	"net/netip"
	"net/url"
	"testing"

	fhttp "github.com/GopeedLab/gopeed/pkg/protocol/http"
)

func TestOutboundPolicyRejectsRedirectAndDNSRebinding(t *testing.T) {
	p, err := newOutboundPolicy(&fhttp.NetworkPolicy{})
	if err != nil {
		t.Fatalf("newOutboundPolicy() error = %v", err)
	}
	lookups := 0
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	source, _ := url.Parse("https://downloads.example.test/file")
	if err := p.validateURL(context.Background(), source); err != nil {
		t.Fatalf("validate initial public URL: %v", err)
	}
	redirect, _ := url.Parse("https://downloads.example.test/redirected")
	if err := p.validateURL(context.Background(), redirect); err == nil {
		t.Fatal("redirect after DNS rebinding was accepted")
	}
}

func TestOutboundPolicyAllowsExplicitCIDRButNotUnrelatedPrivateAddress(t *testing.T) {
	p, err := newOutboundPolicy(&fhttp.NetworkPolicy{AllowedCIDRs: []string{"192.168.10.0/24"}})
	if err != nil {
		t.Fatalf("newOutboundPolicy() error = %v", err)
	}
	if err := p.validateAddr(netip.MustParseAddr("192.168.10.8")); err != nil {
		t.Fatalf("explicitly allowed private CIDR was rejected: %v", err)
	}
	if err := p.validateAddr(netip.MustParseAddr("192.168.11.8")); err == nil {
		t.Fatal("unrelated private address was accepted")
	}
}

func TestOutboundPolicyRejectsPrivateAddressInNAT64Wrapper(t *testing.T) {
	p, err := newOutboundPolicy(&fhttp.NetworkPolicy{})
	if err != nil {
		t.Fatalf("newOutboundPolicy() error = %v", err)
	}
	if err := p.validateAddr(netip.MustParseAddr("64:ff9b::a9fe:a9fe")); err == nil {
		t.Fatal("NAT64-wrapped link-local address was accepted")
	}
}

func TestOutboundPolicyAllowsExactTrustedHost(t *testing.T) {
	p, err := newOutboundPolicy(&fhttp.NetworkPolicy{AllowedHosts: []string{"files.internal.example"}})
	if err != nil {
		t.Fatalf("newOutboundPolicy() error = %v", err)
	}
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.9")}, nil
	}
	u, _ := url.Parse("https://files.internal.example/archive")
	if err := p.validateURL(context.Background(), u); err != nil {
		t.Fatalf("explicitly trusted host was rejected: %v", err)
	}
}
