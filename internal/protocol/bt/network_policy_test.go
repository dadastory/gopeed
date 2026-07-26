package bt

import (
	"net"
	"testing"

	"github.com/GopeedLab/gopeed/pkg/base"
	model "github.com/GopeedLab/gopeed/pkg/protocol/bt"
)

func TestBitTorrentOutboundPolicyBlocksPrivatePeers(t *testing.T) {
	policy := bitTorrentOutboundPolicy(&base.Options{Extra: &model.OptsExtra{NetworkPolicy: &model.NetworkPolicy{}}})
	if policy == nil {
		t.Fatal("expected a task outbound policy")
	}
	if _, blocked := policy.Lookup(net.ParseIP("172.28.0.4")); !blocked {
		t.Fatal("private Compose peer was not blocked")
	}
}

func TestBitTorrentOutboundPolicyAllowsExplicitCIDR(t *testing.T) {
	policy := bitTorrentOutboundPolicy(&base.Options{Extra: &model.OptsExtra{NetworkPolicy: &model.NetworkPolicy{
		AllowedCIDRs: []string{"172.28.0.0/16"},
	}}})
	if _, blocked := policy.Lookup(net.ParseIP("172.28.0.4")); blocked {
		t.Fatal("explicitly allowed peer CIDR was blocked")
	}
}

func TestBitTorrentOutboundPolicyBlocksTransitionedPrivatePeer(t *testing.T) {
	policy := bitTorrentOutboundPolicy(&base.Options{Extra: &model.OptsExtra{NetworkPolicy: &model.NetworkPolicy{}}})
	// 6to4 wraps 172.28.0.4 as 2002:ac1c:0004::.
	if _, blocked := policy.Lookup(net.ParseIP("2002:ac1c:0004::")); !blocked {
		t.Fatal("transitioned private peer was not blocked")
	}
}
