// Command dnszone runs the local-only authoritative DNS zone service and
// publishes zone versions atomically into PostgreSQL.
//
// Usage:
//
//	dnszone serve    --config config.json
//	dnszone publish  --config config.json --file zone.db [--note "..."]
//	dnszone versions --config config.json
//	dnszone export   --config config.json [--serial N] [--out file.db]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/server"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "publish":
		err = runPublish(args)
	case "versions":
		err = runVersions(args)
	case "export":
		err = runExport(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dnszone - local test-domain authoritative DNS service

Commands:
  serve     run the authoritative UDP/TCP server
  publish   atomically publish a zone file as a new version
  versions  list published zone versions
  export    write a published version as a standard master file

Run "<command> -h" for command flags.
`)
}

func loadConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "dnszone ", log.LstdFlags|log.Lmicroseconds)
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	srv, err := server.New(ctx, cfg, st, logger)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	file := fs.String("file", "zone.db", "RFC 1035 zone master file")
	note := fs.String("note", "", "change note stored with the version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()

	lim := zone.Limits{MinTTL: cfg.TTLMin, MaxTTL: cfg.TTLMax}
	rrs, err := zone.Parse(f, cfg.ZoneOrigin(), lim)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	res, err := st.Publish(ctx, rrs, *note, lim)
	if err != nil {
		return err
	}
	fmt.Printf("published serial %d (%d record changes)\n", res.Serial, len(res.Changes))
	for _, c := range res.Changes {
		fmt.Printf("  %s %s\n", c.Action, zone.CanonicalText(c.RR))
	}
	return nil
}

func runVersions(args []string) error {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()
	vs, err := st.ListVersions(ctx, 100)
	if err != nil {
		return err
	}
	fmt.Printf("current zone: %s\n", cfg.ZoneOrigin())
	for _, v := range vs {
		fmt.Printf("  serial %d  %s  %q\n", v.Serial,
			v.PublishedAt.Format("2006-01-02 15:04:05 MST"), v.Note)
	}
	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	serial := fs.Uint("serial", 0, "version serial to export (0 = current published version)")
	out := fs.String("out", "", "output master file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if uint64(*serial) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid serial %d: must fit in a 32-bit unsigned integer", *serial)
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	want := uint32(*serial)
	if want == 0 {
		cur, err := st.CurrentSerial(ctx)
		if err != nil {
			return err
		}
		if cur == 0 {
			return errors.New("no zone version has been published yet")
		}
		want = cur
	}
	v, err := st.LoadVersion(ctx, want)
	if err != nil {
		return err
	}
	snap := v.Snapshot

	// Build the whole export in memory and verify it round-trips through
	// the same parser publishers use before touching the output path, so a
	// bad export can never leave a half-written file. TTL bounds are left
	// open: an archived version is data to verify, not a new publish.
	text := zone.RenderMaster(snap.RRs, zone.ExportMeta{
		Origin:      snap.Origin,
		Serial:      snap.Serial,
		Note:        v.Note,
		PublishedAt: v.PublishedAt,
	})
	reparsed, err := zone.Parse(strings.NewReader(text), snap.Origin,
		zone.Limits{MinTTL: 0, MaxTTL: ^uint32(0)})
	if err != nil {
		return fmt.Errorf("internal error: exported file does not parse: %w", err)
	}
	if got := reparsedSOASerial(reparsed); got != snap.Serial {
		return fmt.Errorf("internal error: exported SOA serial %d != version serial %d",
			got, snap.Serial)
	}
	if !zone.EqualRRSet(reparsed, snap.RRs) {
		return errors.New("internal error: exported file parses to a different record set")
	}

	if *out == "" {
		_, err = io.WriteString(os.Stdout, text)
		return err
	}
	if err := writeFileAtomic(*out, []byte(text)); err != nil {
		return err
	}
	fmt.Printf("exported %s version serial %d (%d records) to %s\n",
		snap.Origin, snap.Serial, len(snap.RRs), *out)
	return nil
}

func reparsedSOASerial(rrs []dns.RR) uint32 {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial
		}
	}
	return 0
}

// writeFileAtomic writes data only after it is fully rendered and
// verified: a temp file in the destination directory is fsynced, then
// renamed over the target in one operation. A failed export leaves no
// file at all and never truncates a previously good export.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dnszone-export-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
