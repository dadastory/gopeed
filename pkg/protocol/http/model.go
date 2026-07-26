package http

type ReqExtra struct {
	Method string            `json:"method"`
	Header map[string]string `json:"header"`
	Body   string            `json:"body"`
}

type OptsExtra struct {
	Connections int `json:"connections"`
	// NetworkPolicy is an optional, task-scoped outbound policy supplied by an
	// embedding application. When present, the HTTP fetcher validates every
	// redirect and resolves-and-dials only approved addresses, preventing DNS
	// rebinding after the application has accepted the original source URL.
	NetworkPolicy *NetworkPolicy `json:"networkPolicy,omitempty"`
	// AutoTorrent when task download complete, and it is a .torrent file, it will be auto create a new task for the torrent file
	// nil means use global config, true/false means explicit setting
	AutoTorrent *bool `json:"autoTorrent"`
	// DeleteTorrentAfterDownload when true, deletes the .torrent file after creating BT task
	// nil means use global config, true/false means explicit setting
	DeleteTorrentAfterDownload *bool `json:"deleteTorrentAfterDownload"`
	// AutoExtract when task download complete, and it is an archive file, it will be auto extracted
	// nil means use global config, true/false means explicit setting
	AutoExtract *bool `json:"autoExtract"`
	// ArchivePassword is the password for extracting password-protected archives
	ArchivePassword string `json:"archivePassword"`
	// DeleteAfterExtract when true, deletes the archive file after successful extraction
	DeleteAfterExtract bool `json:"deleteAfterExtract"`
}

// NetworkPolicy is deliberately narrow: it is not a global Gopeed setting and
// does not change standalone Gopeed behaviour. Exact allowed hosts and CIDRs
// can opt trusted internal endpoints back in; all other private and special
// purpose addresses are rejected while a task using the policy is running.
type NetworkPolicy struct {
	AllowedHosts []string `json:"allowedHosts,omitempty"`
	AllowedCIDRs []string `json:"allowedCIDRs,omitempty"`
}

// Stats for download
type Stats struct {
	Connections []*StatsConnection `json:"connections"`
}

type StatsConnection struct {
	Downloaded int64 `json:"downloaded"`
	Completed  bool  `json:"completed"`
	Failed     bool  `json:"failed"`
	RetryTimes int   `json:"retryTimes"`
}
