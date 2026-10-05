package zone

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// exportZone exercises every supported record type and the rdata forms
// most likely to break a textual round-trip: quoted text with special
// characters, multi-string TXT, MX preference/target and SRV fields.
const exportZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (7 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
@ IN NS ns2.lab.test.
ns1 3600 IN A 127.0.0.10
host1 600 IN AAAA 2001:db8::10
@ 1800 IN A 127.0.0.5
www IN A 127.0.0.20
www IN A 127.0.0.21
www IN TXT "hello; world"
www IN TXT "quote \"here\" and \\ backslash"
www IN TXT "two" "strings"
mx1 IN MX 10 mail.lab.test.
mx2 IN MX 20 mail2.lab.test.
_sip._tcp IN SRV 10 60 5060 sip.lab.test.
alias IN CNAME www.lab.test.
rev 300 IN PTR host1.lab.test.
cafile IN CAA 0 issue "ca.lab.test"
cafile IN CAA 0 iodef "mailto:admin@lab.test"
*.wild IN A 127.0.0.99
`

func parseForExport(t *testing.T, text string) []dns.RR {
	t.Helper()
	rrs, err := Parse(strings.NewReader(text), "lab.test.",
		Limits{MinTTL: 0, MaxTTL: ^uint32(0)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rrs
}

func TestRenderMasterRoundTrip(t *testing.T) {
	rrs := parseForExport(t, exportZone)
	snap, err := NewSnapshot("lab.test.", 7, rrs)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	text := RenderMaster(snap.RRs, ExportMeta{
		Origin:      snap.Origin,
		Serial:      snap.Serial,
		Note:        "v1\nline 2; with semicolon",
		PublishedAt: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
	})

	// Header must identify the source version and serial.
	for _, want := range []string{
		"; origin: lab.test.",
		"; source version serial: 7",
		"; published at: 2026-10-05 12:00:00 UTC",
		"; note: v1",
		"; note: line 2. with semicolon",
		"$ORIGIN lab.test.",
	} {
		if !strings.Contains(text, want+"\n") {
			t.Fatalf("export header missing %q in:\n%s", want, text)
		}
	}

	// Re-parsing through the production parser must give an equivalent set.
	reparsed, err := Parse(strings.NewReader(text), "lab.test.",
		Limits{MinTTL: 0, MaxTTL: ^uint32(0)})
	if err != nil {
		t.Fatalf("reparse exported file: %v\nexport:\n%s", err, text)
	}
	if !EqualRRSet(reparsed, snap.RRs) {
		t.Fatalf("round-trip mismatch\n--- exported ---\n%s", text)
	}

	// SOA serial must survive verbatim.
	var serial uint32
	for _, rr := range reparsed {
		if soa, ok := rr.(*dns.SOA); ok {
			serial = soa.Serial
		}
	}
	if serial != 7 {
		t.Fatalf("reparsed SOA serial = %d, want 7", serial)
	}
}

func TestRenderMasterKeepsTXTMXSRV(t *testing.T) {
	snap, _ := NewSnapshot("lab.test.", 3, parseForExport(t, exportZone))
	text := RenderMaster(snap.RRs, ExportMeta{Origin: "lab.test.", Serial: 3})

	wantLines := []string{
		`www.lab.test. 3600 IN TXT "hello; world"`,
		`www.lab.test. 3600 IN TXT "quote \"here\" and \\ backslash"`,
		`www.lab.test. 3600 IN TXT "two" "strings"`,
		`mx1.lab.test. 3600 IN MX 10 mail.lab.test.`,
		`mx2.lab.test. 3600 IN MX 20 mail2.lab.test.`,
		`_sip._tcp.lab.test. 3600 IN SRV 10 60 5060 sip.lab.test.`,
	}
	got := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		got[line] = true
	}
	for _, w := range wantLines {
		if !got[w] {
			t.Errorf("export missing exact line %q", w)
		}
	}
}

func TestRenderMasterTTLsPreserved(t *testing.T) {
	snap, _ := NewSnapshot("lab.test.", 1, parseForExport(t, exportZone))
	text := RenderMaster(snap.RRs, ExportMeta{Origin: "lab.test.", Serial: 1})
	for _, want := range []string{
		"ns1.lab.test. 3600 IN A 127.0.0.10",
		"host1.lab.test. 600 IN AAAA 2001:db8::10",
		"lab.test. 1800 IN A 127.0.0.5",
		"rev.lab.test. 300 IN PTR host1.lab.test.",
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("TTL not preserved: missing %q", want)
		}
	}
}

func TestRenderMasterStableOrder(t *testing.T) {
	snap, _ := NewSnapshot("lab.test.", 1, parseForExport(t, exportZone))
	meta := ExportMeta{Origin: "lab.test.", Serial: 1}
	a := RenderMaster(snap.RRs, meta)
	// A snapshot rebuilt from the same data must render byte-identically.
	snap2, _ := NewSnapshot("lab.test.", 1, parseForExport(t, exportZone))
	b := RenderMaster(snap2.RRs, meta)
	if a != b {
		t.Fatal("export is not deterministic for identical versions")
	}

	// Body order: SOA first, apex NS next (AXFR-stable order), and names
	// ascending afterwards.
	var body []string
	for _, line := range strings.Split(a, "\n") {
		if line == "" || strings.HasPrefix(line, ";") ||
			strings.HasPrefix(line, "$") {
			continue
		}
		body = append(body, line)
	}
	if !strings.Contains(body[0], " IN SOA ") {
		t.Fatalf("first body record must be SOA, got %q", body[0])
	}
	if !strings.Contains(body[1], " IN NS ") ||
		!strings.HasPrefix(body[1], "lab.test. ") {
		t.Fatalf("second body record must be apex NS, got %q", body[1])
	}
}

func TestEqualRRSet(t *testing.T) {
	a := parseForExport(t, exportZone)
	b := parseForExport(t, exportZone)
	if !EqualRRSet(a, b) {
		t.Fatal("identical sets compare unequal")
	}

	// Reordered input is still the same set.
	b[5], b[6] = b[6], b[5]
	if !EqualRRSet(a, b) {
		t.Fatal("reordered sets compare unequal")
	}

	// Uppercase owner names are equivalent in DNS.
	upper := strings.Replace(exportZone, "ns1 3600 IN A 127.0.0.10",
		"NS1 3600 IN A 127.0.0.10", 1)
	if !EqualRRSet(a, parseForExport(t, upper)) {
		t.Fatal("case-folded owner names should compare equal")
	}

	// A changed TTL must be detected.
	ttl := strings.Replace(exportZone, "host1 600 IN AAAA",
		"host1 601 IN AAAA", 1)
	if EqualRRSet(a, parseForExport(t, ttl)) {
		t.Fatal("TTL change must make sets unequal")
	}

	// TXT text is case-sensitive: changed rdata must be detected.
	txt := strings.Replace(exportZone, `"hello; world"`,
		`"HELLO; world"`, 1)
	if EqualRRSet(a, parseForExport(t, txt)) {
		t.Fatal("TXT rdata case change must make sets unequal")
	}
}
