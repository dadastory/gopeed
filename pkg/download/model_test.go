package download

import (
	"encoding/json"
	"testing"

	"github.com/GopeedLab/gopeed/internal/controller"
	"github.com/GopeedLab/gopeed/internal/fetcher"
	"github.com/GopeedLab/gopeed/pkg/base"
)

type telemetryFetcher struct {
	progress fetcher.Progress
}

func (f *telemetryFetcher) Setup(*controller.Controller)               {}
func (f *telemetryFetcher) Resolve(*base.Request, *base.Options) error { return nil }
func (f *telemetryFetcher) Start() error                               { return nil }
func (f *telemetryFetcher) Patch(*base.Request, *base.Options) error   { return nil }
func (f *telemetryFetcher) Pause() error                               { return nil }
func (f *telemetryFetcher) Close() error                               { return nil }
func (f *telemetryFetcher) Stats() any                                 { return nil }
func (f *telemetryFetcher) Meta() *fetcher.FetcherMeta                 { return nil }
func (f *telemetryFetcher) Progress() fetcher.Progress                 { return f.progress }
func (f *telemetryFetcher) Wait() error                                { return nil }

func TestCalcSpeedResetOnRollback(t *testing.T) {
	speedArr := []int64{1024, 2048, 4096}

	if got := calcSpeed(&speedArr, -512, 1); got != 0 {
		t.Fatalf("calcSpeed() = %d, want 0 after rollback", got)
	}
	if len(speedArr) != 0 {
		t.Fatalf("speed window len = %d, want 0 after rollback", len(speedArr))
	}

	if got := calcSpeed(&speedArr, 1024, 1); got != 1024 {
		t.Fatalf("calcSpeed() = %d, want 1024 after reset", got)
	}
}

func TestTaskMarshalJSONIncludesOnlyBitTorrentFileProgress(t *testing.T) {
	makeTask := func(protocol string) Task {
		return Task{
			Protocol: protocol,
			Meta: &fetcher.FetcherMeta{
				Req:  &base.Request{URL: "https://example.test/archive"},
				Opts: &base.Options{},
				Res: &base.Resource{Hash: "info-hash", Files: []*base.FileInfo{
					{Name: "one.bin", Size: 100},
					{Name: "two.bin", Size: 200},
				}},
			},
			fetcher: &telemetryFetcher{progress: fetcher.Progress{25, 50}},
		}
	}

	torrentTask := makeTask("bt")
	encoded, err := json.Marshal(&torrentTask)
	if err != nil {
		t.Fatalf("marshal BitTorrent task: %v", err)
	}
	var torrent map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &torrent); err != nil {
		t.Fatalf("unmarshal BitTorrent task: %v", err)
	}
	var progress map[int]int64
	if err := json.Unmarshal(torrent["fileProgress"], &progress); err != nil || len(progress) != 2 || progress[0] != 25 || progress[1] != 50 {
		t.Fatalf("fileProgress = %s, want {0:25,1:50}", torrent["fileProgress"])
	}

	httpSourceTask := makeTask("http")
	encoded, err = json.Marshal(&httpSourceTask)
	if err != nil {
		t.Fatalf("marshal HTTP task: %v", err)
	}
	var httpTask map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &httpTask); err != nil {
		t.Fatalf("unmarshal HTTP task: %v", err)
	}
	if _, exists := httpTask["fileProgress"]; exists {
		t.Fatalf("HTTP task unexpectedly exposed fileProgress: %s", encoded)
	}
}
