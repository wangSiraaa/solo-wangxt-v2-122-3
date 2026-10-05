package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// TestExportRoundTripsEveryVersion publishes the two shipped example zone
// versions, then for every stored version renders the master file and
// re-parses it through the production parser, asserting the result is an
// equivalent record set carrying the same SOA serial.
func TestExportRoundTripsEveryVersion(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}

	read := func(p string) []dns.RR {
		t.Helper()
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rrs, err := zone.Parse(strings.NewReader(string(raw)), origin, lim)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		return rrs
	}
	if _, err := s.Publish(ctx, read("../../testdata/zone-v1.db"), "v1", lim); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if _, err := s.Publish(ctx, read("../../testdata/zone-v2.db"), "v2", lim); err != nil {
		t.Fatalf("publish v2: %v", err)
	}

	for _, serial := range []uint32{1, 2} {
		v, err := s.LoadVersion(ctx, serial)
		if err != nil {
			t.Fatalf("LoadVersion %d: %v", serial, err)
		}
		if v.Note != "v"+string(rune('0'+serial)) {
			t.Fatalf("version %d note = %q", serial, v.Note)
		}
		text := zone.RenderMaster(v.Snapshot.RRs, zone.ExportMeta{
			Origin:      v.Snapshot.Origin,
			Serial:      v.Serial,
			Note:        v.Note,
			PublishedAt: v.PublishedAt,
		})
		reparsed, err := zone.Parse(strings.NewReader(text), origin,
			zone.Limits{MinTTL: 0, MaxTTL: ^uint32(0)})
		if err != nil {
			t.Fatalf("version %d export does not reparse: %v\n%s", serial, err, text)
		}
		if !zone.EqualRRSet(reparsed, v.Snapshot.RRs) {
			t.Fatalf("version %d export changed the record set", serial)
		}
		var gotSerial uint32
		for _, rr := range reparsed {
			if soa, ok := rr.(*dns.SOA); ok {
				gotSerial = soa.Serial
			}
		}
		if gotSerial != serial {
			t.Fatalf("version %d export serial = %d", serial, gotSerial)
		}
	}
}

// TestLoadVersionMissing returns the sentinel error for unknown versions.
func TestLoadVersionMissing(t *testing.T) {
	s := freshStore(t)
	if _, err := s.LoadVersion(context.Background(), 999); err == nil {
		t.Fatal("expected error loading missing version")
	} else if !errors.Is(err, ErrNoVersion) {
		t.Fatalf("want ErrNoVersion, got %v", err)
	}
	if _, err := s.LoadSnapshot(context.Background(), 999); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("LoadSnapshot missing: want ErrNoVersion, got %v", err)
	}
}
