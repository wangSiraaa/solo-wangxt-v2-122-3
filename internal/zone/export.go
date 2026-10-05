package zone

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

// WriteMasterFile serializes a snapshot as an RFC 1035 master file: a
// comment header recording the source version and SOA serial, the $ORIGIN
// directive, then every record of the version in the snapshot's canonical
// order (SOA first, apex NS next, then by owner/type/rdata) with explicit
// TTLs. The output is deterministic for a given snapshot, and re-parsing
// it with Parse yields the same record set, so an exported version can be
// reviewed offline or diffed against another export.
func WriteMasterFile(w io.Writer, snap *Snapshot, note string, publishedAt time.Time) error {
	b := bufio.NewWriter(w)
	fmt.Fprintln(b, "; dnszone master file export")
	fmt.Fprintf(b, "; zone: %s\n", snap.Origin)
	fmt.Fprintf(b, "; source version: %d (SOA serial: %d)\n", snap.Serial, snap.Serial)
	fmt.Fprintf(b, "; published at: %s\n", publishedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(b, "; note: %s\n", commentText(note))
	fmt.Fprintln(b)
	fmt.Fprintf(b, "$ORIGIN %s\n", snap.Origin)
	for _, rr := range snap.RRs {
		// RR.String() is RFC 1035 presentation format and keeps all
		// rdata escaping (quoted TXT, backslashes, \DDD octets) and
		// fields (MX preference, SRV priority/weight/port) intact, so
		// every line re-parses to an identical record.
		fmt.Fprintln(b, rr.String())
	}
	return b.Flush()
}

// commentText flattens control characters to spaces so a stored note can
// never break out of its comment line and inject extra master-file lines.
func commentText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
