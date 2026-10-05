package zone

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// exportZone exercises every supported record type, with TXT content
// that needs quoting and escaping preserved byte-for-byte.
const exportZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
@ IN NS ns2.lab.test.
ns1 IN A 127.0.0.10
ns2 IN A 127.0.0.11
@ IN A 127.0.0.5
www IN A 127.0.0.20
www IN TXT "Mixed Case \"quoted\" \\ backslash"
www IN TXT "multi" "string" "record"
mx1 IN MX 10 mail.lab.test.
mail IN A 127.0.0.25
_sip._tcp IN SRV 10 60 5060 sip.lab.test.
sip IN A 127.0.0.26
alias IN CNAME www.lab.test.
ptr1 IN PTR target.lab.test.
cafile IN CAA 0 issue "ca.lab.test"
host1 IN AAAA 2001:db8::10
*.wild IN A 127.0.0.99
`

func TestWriteMasterFileRoundTrip(t *testing.T) {
	lim := Limits{MinTTL: 30, MaxTTL: 86400}
	snap, err := NewSnapshot("lab.test.", 7, mustParse(t, exportZone, lim))
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 10, 5, 1, 2, 3, 0, time.FixedZone("LAB", 3600))

	var buf bytes.Buffer
	if err := WriteMasterFile(&buf, snap, `review "v7" please`, stamp); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// The header names the source version and serial (UTC timestamp).
	for _, want := range []string{
		"source version: 7", "SOA serial: 7", "zone: lab.test.",
		`note: review "v7" please`, "published at: 2026-10-05T00:02:03Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("export header missing %q:\n%s", want, out)
		}
	}

	// Re-parsing with the existing parser yields the same record set,
	// compared case-sensitively on the full presentation form.
	got, err := Parse(strings.NewReader(out), "lab.test.", lim)
	if err != nil {
		t.Fatalf("exported file does not re-parse: %v\n%s", err, out)
	}
	if diff := rrSetDiff(snap.RRs, got); diff != "" {
		t.Fatalf("round-trip mismatch: %s\nexport was:\n%s", diff, out)
	}

	// Deterministic: rendering the same snapshot twice is byte-identical.
	var again bytes.Buffer
	if err := WriteMasterFile(&again, snap, `review "v7" please`, stamp); err != nil {
		t.Fatal(err)
	}
	if again.String() != out {
		t.Fatal("export output is not stable across runs")
	}
}

func TestWriteMasterFilePreservesRdataFields(t *testing.T) {
	lim := Limits{MinTTL: 30, MaxTTL: 86400}
	snap, err := NewSnapshot("lab.test.", 3, mustParse(t, exportZone, lim))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteMasterFile(&buf, snap, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(strings.NewReader(buf.String()), "lab.test.", lim)
	if err != nil {
		t.Fatal(err)
	}

	var txts []*dns.TXT
	var mx *dns.MX
	var srv *dns.SRV
	for _, rr := range got {
		switch r := rr.(type) {
		case *dns.TXT:
			txts = append(txts, r)
		case *dns.MX:
			mx = r
		case *dns.SRV:
			srv = r
		}
	}
	// TXT: miekg keeps master-file escapes in the in-memory string and
	// interprets them at wire-pack time, so the re-parsed records must
	// hold the exact same escaped strings as the snapshot — case,
	// embedded quotes and backslashes intact, multi-string split kept.
	if len(txts) != 2 {
		t.Fatalf("expected 2 TXT records, got %d", len(txts))
	}
	var single, multi *dns.TXT
	for _, r := range txts {
		if len(r.Txt) == 1 {
			single = r
		} else {
			multi = r
		}
	}
	if single == nil || single.Txt[0] != `Mixed Case \"quoted\" \\ backslash` {
		t.Fatalf("TXT escaping/case not preserved: %#v", single)
	}
	if multi == nil || strings.Join(multi.Txt, "|") != "multi|string|record" {
		t.Fatalf("multi-string TXT not preserved: %#v", multi)
	}
	// MX and SRV numeric fields and targets survive.
	if mx == nil || mx.Preference != 10 || mx.Mx != "mail.lab.test." {
		t.Fatalf("MX fields not preserved: %v", mx)
	}
	if srv == nil || srv.Priority != 10 || srv.Weight != 60 ||
		srv.Port != 5060 || srv.Target != "sip.lab.test." {
		t.Fatalf("SRV fields not preserved: %v", srv)
	}
}

func TestWriteMasterFileNoteCannotInjectRecords(t *testing.T) {
	lim := Limits{MinTTL: 30, MaxTTL: 86400}
	snap, err := NewSnapshot("lab.test.", 1, mustParse(t, validZone, lim))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	note := "ok\nevil.lab.test. 60 IN A 6.6.6.6\n; done"
	if err := WriteMasterFile(&buf, snap, note, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "evil") && !strings.HasPrefix(line, ";") {
			t.Fatalf("note escaped its comment line: %q", line)
		}
	}
	got, err := Parse(strings.NewReader(buf.String()), "lab.test.", lim)
	if err != nil {
		t.Fatal(err)
	}
	if diff := rrSetDiff(snap.RRs, got); diff != "" {
		t.Fatalf("hostile note changed the record set: %s", diff)
	}
}

// rrSetDiff compares two record sets as multisets of their full
// presentation form (owner, TTL, class, type, rdata; case-sensitive) and
// returns a human-readable diff, empty when they are equivalent.
func rrSetDiff(want, got []dns.RR) string {
	count := map[string]int{}
	for _, rr := range want {
		count[rr.String()]++
	}
	for _, rr := range got {
		count[rr.String()]--
	}
	var missing, extra []string
	for text, n := range count {
		for ; n > 0; n-- {
			missing = append(missing, text)
		}
		for ; n < 0; n++ {
			extra = append(extra, text)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return "missing: [" + strings.Join(missing, "; ") +
		"] extra: [" + strings.Join(extra, "; ") + "]"
}
