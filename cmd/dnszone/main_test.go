package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

// testDatabaseURL follows the same convention as internal/store: the
// integration database comes from DNSZONE_TEST_DATABASE and tests skip
// when it is unreachable.
func testDatabaseURL() string {
	if u := os.Getenv("DNSZONE_TEST_DATABASE"); u != "" {
		return u
	}
	return "postgres://dnsadmin@127.0.0.1:55432/dnszone_test?sslmode=disable&connect_timeout=2"
}

// isolatedTestDB returns a database dedicated to the CLI tests, creating
// it on first use. The store package tests truncate the shared test
// database while running in parallel with this package; a separate
// database keeps the exported versions stable for the whole test run.
func isolatedTestDB(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(testDatabaseURL())
	if err != nil {
		t.Fatalf("bad test database URL: %v", err)
	}
	const dbName = "dnszone_cmdtest"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	maint := *u
	maint.Path = "/postgres"
	pool, err := pgxpool.New(ctx, maint.String())
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	defer pool.Close()
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`,
		dbName).Scan(&exists); err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	if !exists {
		if _, err := pool.Exec(ctx, `CREATE DATABASE `+dbName); err != nil {
			t.Fatalf("create %s: %v", dbName, err)
		}
	}
	out := *u
	out.Path = "/" + dbName
	return out.String()
}

func writeTestConfig(t *testing.T, dbURL string) string {
	t.Helper()
	cfg := `{
  "zone": "lab.test.",
  "listen_udp": "127.0.0.1:0",
  "listen_tcp": "127.0.0.1:0",
  "database_url": "` + dbURL + `",
  "ttl_min": 30,
  "ttl_max": 86400
}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const cliZoneV1 = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN TXT "export \"quoted\" txt"
mx1 IN MX 10 mail.lab.test.
mail IN A 127.0.0.25
_sip._tcp IN SRV 10 60 5060 sip.lab.test.
sip IN A 127.0.0.26
`

func publishFile(t *testing.T, cfgPath, text, note string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "zone.db")
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPublish([]string{"-config", cfgPath, "-file", f, "-note", note}); err != nil {
		t.Fatalf("publish %q: %v", note, err)
	}
}

func TestExportCommandRoundTrip(t *testing.T) {
	dbURL := isolatedTestDB(t)
	cfgPath := writeTestConfig(t, dbURL)
	dir := t.TempDir()

	// Publish two versions through the real CLI path. The database is
	// dedicated to this package but persists across runs, so serials are
	// discovered, not assumed.
	publishFile(t, cfgPath, cliZoneV1, "v1")
	v2 := strings.Replace(cliZoneV1, "www IN A 127.0.0.20\n",
		"www IN A 127.0.0.20\nhost2 IN A 127.0.0.30\n", 1)
	publishFile(t, cfgPath, v2, "v2")

	ctx := context.Background()
	st, err := store.New(ctx, dbURL, "lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	current, err := st.CurrentSerial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current < 2 {
		t.Fatalf("expected at least 2 published versions, current serial is %d", current)
	}

	// Export the current version (default) and an earlier one explicitly.
	files := map[uint32]string{}
	currentFile := filepath.Join(dir, "export-current.db")
	if err := runExport([]string{"-config", cfgPath, "-out", currentFile}); err != nil {
		t.Fatalf("export current: %v", err)
	}
	files[current] = currentFile
	olderFile := filepath.Join(dir, "export-older.db")
	older := current - 1
	if err := runExport([]string{"-config", cfgPath, "-serial",
		fmt.Sprint(older), "-out", olderFile}); err != nil {
		t.Fatalf("export serial %d: %v", older, err)
	}
	files[older] = olderFile

	lim := zone.Limits{MinTTL: 30, MaxTTL: 86400}
	for serial, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		// Provenance: source version and serial are named in the file.
		if !strings.Contains(text, fmt.Sprintf("source version: %d", serial)) ||
			!strings.Contains(text, fmt.Sprintf("SOA serial: %d", serial)) {
			t.Errorf("serial %d: export lacks provenance header:\n%s", serial, text)
		}
		// Re-parsing with the existing parser yields the snapshot's set.
		got, err := zone.Parse(strings.NewReader(text), "lab.test.", lim)
		if err != nil {
			t.Fatalf("serial %d: export does not re-parse: %v", serial, err)
		}
		snap, err := st.LoadSnapshot(ctx, serial)
		if err != nil {
			t.Fatal(err)
		}
		if !sameRecordSet(snap.RRs, got) {
			t.Fatalf("serial %d: exported records differ from snapshot:\n%s", serial, text)
		}
	}
}

func TestExportInvalidVersionWritesNothing(t *testing.T) {
	dbURL := isolatedTestDB(t)
	cfgPath := writeTestConfig(t, dbURL)
	dir := t.TempDir()
	out := filepath.Join(dir, "should-not-exist.db")

	err := runExport([]string{"-config", cfgPath, "-serial", "9999", "-out", out})
	if err == nil {
		t.Fatal("export of unknown serial must fail")
	}
	if !errors.Is(err, store.ErrNoVersion) {
		t.Fatalf("error = %v, want wrapped ErrNoVersion", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("output file exists after failed export: %v", statErr)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".dnszone-export-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

// sameRecordSet reports whether a and b hold the same records, comparing
// canonical text as a multiset.
func sameRecordSet(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, rr := range a {
		count[zone.CanonicalText(rr)]++
	}
	for _, rr := range b {
		count[zone.CanonicalText(rr)]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}
