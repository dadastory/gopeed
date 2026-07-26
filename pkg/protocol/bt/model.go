package bt

type ReqExtra struct {
	Trackers []string `json:"trackers"`
}

type OptsExtra struct {
	NetworkPolicy *NetworkPolicy `json:"networkPolicy,omitempty"`
}

type NetworkPolicy struct {
	AllowedHosts []string `json:"allowedHosts,omitempty"`
	AllowedCIDRs []string `json:"allowedCIDRs,omitempty"`
}

// Stats for torrent
type Stats struct {
	// health indicators of torrents, from large to small, ConnectedSeeders are also the key to the health of seed resources
	TotalPeers       int `json:"totalPeers"`
	ActivePeers      int `json:"activePeers"`
	ConnectedSeeders int `json:"connectedSeeders"`
	// Total seed bytes
	SeedBytes int64 `json:"seedBytes"`
	// Seed ratio
	SeedRatio float64 `json:"seedRatio"`
	// Total seed time
	SeedTime int64 `json:"seedTime"`
}
