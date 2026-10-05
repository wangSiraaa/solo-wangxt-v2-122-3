package zone

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ExportMeta names the database version a master-file export was rendered
// from. Every field is informational: it is written into the file header
// so an offline reviewer can tell which version (and SOA serial) the text
// in front of them came from.
type ExportMeta struct {
	Origin      string
	Serial      uint32
	Note        string
	PublishedAt time.Time
}

// masterLine renders one RR as a single RFC 1035 master-file line:
//
//	name ttl CLASS TYPE rdata
//
// using miekg/dns's own String() encoder, which quotes and escapes TXT
// character-strings (embedded quotes, backslashes, non-printable bytes),
// CAA values and domain names exactly the way NewZoneParser understands.
// Its fields are tab-separated; master-file whitespace is interchangeable,
// and no supported rdata form contains a literal tab (tabs inside TXT data
// are escaped as \DDD), so collapsing tabs to single spaces keeps the
// output stable and round-trippable.
func masterLine(rr dns.RR) string {
	return strings.Join(strings.Split(rr.String(), "\t"), " ")
}

// RenderMaster serializes rrs into a standard RFC 1035 zone master file
// for offline review.
//
// The records are emitted in the snapshot's stable order (SOA first, apex
// NS next, then name/type/rdata), every RR keeps its own TTL, and the SOA
// carries the version serial verbatim. A comment header identifies the
// source zone, version serial, publication time and note; comments are
// skipped by Parse, so the file is self-describing yet parses back to the
// same record set.
//
// RenderMaster does not consult any configuration and performs no I/O.
func RenderMaster(rrs []dns.RR, meta ExportMeta) string {
	var b strings.Builder
	b.WriteString("; dnszone master file export\n")
	if meta.Origin != "" {
		fmt.Fprintf(&b, "; origin: %s\n", dns.Fqdn(strings.ToLower(meta.Origin)))
	}
	fmt.Fprintf(&b, "; source version serial: %d\n", meta.Serial)
	if !meta.PublishedAt.IsZero() {
		fmt.Fprintf(&b, "; published at: %s\n",
			meta.PublishedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if note := sanitizeNote(meta.Note); note != "" {
		for _, line := range strings.Split(note, "\n") {
			fmt.Fprintf(&b, "; note: %s\n", line)
		}
	}
	fmt.Fprintf(&b, "$ORIGIN %s\n", dns.Fqdn(strings.ToLower(meta.Origin)))
	b.WriteString("\n")
	for _, rr := range rrs {
		b.WriteString(masterLine(rr))
		b.WriteByte('\n')
	}
	return b.String()
}

// sanitizeNote keeps free-form note text safe inside comment lines: no
// carriage returns and no embedded comment markers that could make the
// provenance header ambiguous to a human reader.
func sanitizeNote(note string) string {
	note = strings.ReplaceAll(note, "\r\n", "\n")
	note = strings.ReplaceAll(note, "\r", "\n")
	note = strings.ReplaceAll(note, ";", ".")
	return strings.TrimRight(note, "\n")
}

// EqualRRSet reports whether two record sets contain the same records
// (name, type, class, TTL and rdata) regardless of order or capitalization
// of owner names. It is used to verify that an exported master file parses
// back to an equivalent record set.
func EqualRRSet(a, b []dns.RR) bool {
	counts := map[string]int{}
	for _, rr := range a {
		counts[rrIdentity(rr)]++
	}
	for _, rr := range b {
		k := rrIdentity(rr)
		if counts[k] == 0 {
			return false
		}
		counts[k]--
	}
	for _, n := range counts {
		if n != 0 {
			return false
		}
	}
	return true
}

// rrIdentity is a full-record key, unlike the diff key: it includes the
// TTL and keeps rdata case (TXT text is case-sensitive) but folds the
// owner name the way zone comparisons do.
func rrIdentity(rr dns.RR) string {
	h := rr.Header()
	return strings.ToLower(h.Name) + "|" + dns.TypeToString[h.Rrtype] + "|" +
		classString(h.Class) + "|" + fmt.Sprint(h.Ttl) + "|" + exactRdata(rr)
}

// exactRdata renders rdata without the owner/TTL/class/type prefix,
// preserving the original text case (miekg's encoder only lowercases
// domain-name fields, as DNS semantics require).
func exactRdata(rr dns.RR) string {
	parts := strings.Split(rr.String(), "\t")
	if len(parts) >= 5 {
		return strings.Join(parts[4:], " ")
	}
	return rr.String()
}

// classString renders a DNS class; everything in this zone is IN but the
// identity key records it rather than assuming it.
func classString(c uint16) string {
	if s, ok := dns.ClassToString[c]; ok {
		return s
	}
	return fmt.Sprintf("%d", c)
}
