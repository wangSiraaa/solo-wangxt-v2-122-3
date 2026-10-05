package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// exportVersion renders one stored version exactly the way the CLI export
// command does: version metadata + snapshot -> master file text.
func exportVersion(t *testing.T, s *Store, serial uint32) string {
	t.Helper()
	ctx := context.Background()
	info, err := s.VersionInfo(ctx, serial)
	if err != nil {
		t.Fatalf("VersionInfo(%d): %v", serial, err)
	}
	snap, err := s.LoadSnapshot(ctx, serial)
	if err != nil {
		t.Fatalf("LoadSnapshot(%d): %v", serial, err)
	}
	var buf bytes.Buffer
	if err := zone.WriteMasterFile(&buf, snap, info.Note, info.PublishedAt); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestExportRoundTripMatchesSnapshot(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}

	v1 := `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN TXT "quoted \"inside\" and \\ slash"
mx1 IN MX 10 mail.lab.test.
mail IN A 127.0.0.25
_sip._tcp IN SRV 10 60 5060 sip.lab.test.
sip IN A 127.0.0.26
`
	v2 := strings.Replace(v1, "www IN A 127.0.0.20\n",
		"www IN A 127.0.0.20\nwww IN A 127.0.0.21\nhost2 IN A 127.0.0.30\n", 1)

	if _, err := s.Publish(ctx, parse(t, v1), "v1", lim); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, parse(t, v2), "v2", lim); err != nil {
		t.Fatal(err)
	}

	// The current version (2) and the earlier version (1) both export and
	// re-parse to exactly the records of their respective snapshots.
	for serial := uint32(1); serial <= 2; serial++ {
		text := exportVersion(t, s, serial)
		if !strings.Contains(text, "source version: ") {
			t.Fatalf("serial %d: export lacks provenance header:\n%s", serial, text)
		}
		got, err := zone.Parse(strings.NewReader(text), origin, lim)
		if err != nil {
			t.Fatalf("serial %d: export does not re-parse: %v\n%s", serial, err, text)
		}
		snap, err := s.LoadSnapshot(ctx, serial)
		if err != nil {
			t.Fatal(err)
		}
		if diff := canonicalDiff(snap.RRs, got); diff != "" {
			t.Fatalf("serial %d: %s\nexport was:\n%s", serial, diff, text)
		}
		// The exported SOA carries the version's serial.
		var soa *dns.SOA
		for _, rr := range got {
			if s, ok := rr.(*dns.SOA); ok {
				soa = s
			}
		}
		if soa == nil || soa.Serial != serial {
			t.Fatalf("serial %d: re-parsed SOA = %v", serial, soa)
		}
	}
}

func TestVersionInfoUnknownSerial(t *testing.T) {
	s := freshStore(t)
	if _, err := s.VersionInfo(context.Background(), 4242); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("VersionInfo(4242) = %v, want wrapped ErrNoVersion", err)
	}
}

// canonicalDiff compares two record sets as multisets of their canonical
// text form and returns a human-readable diff, empty when equivalent.
func canonicalDiff(want, got []dns.RR) string {
	count := map[string]int{}
	for _, rr := range want {
		count[zone.CanonicalText(rr)]++
	}
	for _, rr := range got {
		count[zone.CanonicalText(rr)]--
	}
	var parts []string
	for text, n := range count {
		switch {
		case n > 0:
			parts = append(parts, "missing: "+text)
		case n < 0:
			parts = append(parts, "extra: "+text)
		}
	}
	return strings.Join(parts, "; ")
}
