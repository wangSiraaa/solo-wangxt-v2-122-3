// Command dnszone runs the local-only authoritative DNS zone service and
// publishes zone versions atomically into PostgreSQL.
//
// Usage:
//
//	dnszone serve    --config config.json
//	dnszone publish  --config config.json --file zone.db [--note "..."]
//	dnszone versions --config config.json
//	dnszone export   --config config.json [--serial N] [--out zone.db]
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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
  export    export a zone version as an RFC 1035 master file

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

// runExport writes one stored version as an RFC 1035 master file for
// offline review. It is read-only: only SELECT queries run, nothing in
// the database or the serving snapshot is modified.
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	serialFlag := fs.Uint64("serial", 0, "version serial to export (0 = current version)")
	out := fs.String("out", "-", `output file ("-" writes to stdout)`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serialFlag > math.MaxUint32 {
		return fmt.Errorf("serial %d out of range", *serialFlag)
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

	serial := uint32(*serialFlag)
	if serial == 0 {
		serial, err = st.CurrentSerial(ctx)
		if err != nil {
			return err
		}
		if serial == 0 {
			return errors.New("no version published yet")
		}
	}
	// Existence is checked before the output path is touched, so an
	// invalid version can never leave a half-written file behind.
	info, err := st.VersionInfo(ctx, serial)
	if err != nil {
		return err
	}
	snap, err := st.LoadSnapshot(ctx, serial)
	if err != nil {
		return err
	}

	// Render fully in memory first; only a complete file is written out.
	var buf bytes.Buffer
	if err := zone.WriteMasterFile(&buf, snap, info.Note, info.PublishedAt); err != nil {
		return err
	}
	if *out == "" || *out == "-" {
		if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "exported serial %d (%d records) to stdout\n", serial, len(snap.RRs))
		return nil
	}
	if err := writeFileAtomic(*out, buf.Bytes()); err != nil {
		return err
	}
	fmt.Printf("exported serial %d (%d records) to %s\n", serial, len(snap.RRs), *out)
	return nil
}

// writeFileAtomic writes data to path via a temp file in the same
// directory plus rename, so the target never holds partial content and
// no temp file is left behind on failure.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dnszone-export-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
