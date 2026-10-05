package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

// testDB is the integration-test database. It is separate from the
// store package's dnszone_test so `go test ./...` never lets one package
// truncate tables while another is mid-publish. Tests skip when it is
// unreachable so `go test` stays usable without PostgreSQL.
func testDBURL() string {
	if u := os.Getenv("DNSZONE_CLI_TEST_DATABASE"); u != "" {
		return u
	}
	return "postgres://dnsadmin@127.0.0.1:55432/dnszone_cli_test?sslmode=disable&connect_timeout=2"
}

// writeTestConfig emits a config pointed at the test database. Listeners
// are never bound by publish/export, their values are placeholders.
func writeTestConfig(t *testing.T, dbURL string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
  "zone": "lab.test.",
  "listen_udp": "127.0.0.1:0",
  "listen_tcp": "127.0.0.1:0",
  "database_url": "` + dbURL + `",
  "ttl_min": 30,
  "ttl_max": 86400
}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func resetExportDB(t *testing.T, dbURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// store.New connects and ensures the schema exists, so this also works
	// against an empty freshly created database.
	st, err := store.New(ctx, dbURL, "lab.test.")
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	defer st.Close()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	defer pool.Close()
	for _, stmt := range []string{
		`TRUNCATE zone_changes, zone_records, zone_versions`,
		`UPDATE zone_meta SET current_serial=0, origin='lab.test.' WHERE id=1`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCLIExportCurrentAndOldVersions is the acceptance path: publish two
// versions, export each, and confirm the files reparse to record sets
// equivalent to the database snapshots with matching SOA serials.
func TestCLIExportCurrentAndOldVersions(t *testing.T) {
	dbURL := testDBURL()
	resetExportDB(t, dbURL)
	cfg := writeTestConfig(t, dbURL)
	dir := filepath.Dir(cfg)

	pub := func(file string) {
		t.Helper()
		if err := runPublish([]string{
			"-config", cfg, "-file", file, "-note", filepath.Base(file),
		}); err != nil {
			t.Fatalf("publish %s: %v", file, err)
		}
	}
	pub("../../testdata/zone-v1.db")
	pub("../../testdata/zone-v2.db")

	export := func(serial uint, name string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		args := []string{"-config", cfg, "-out", path}
		if serial != 0 {
			args = append(args, "-serial", strconv.FormatUint(uint64(serial), 10))
		}
		if err := runExport(args); err != nil {
			t.Fatalf("export serial %d: %v", serial, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	v1Text := export(1, "v1.db")
	currentText := export(0, "current.db") // 0 resolves to the latest version
	v2Text := export(2, "v2.db")

	if v2Text != currentText {
		t.Fatal("export of serial 0 must equal export of current serial 2")
	}
	if v1Text == v2Text {
		t.Fatal("versions 1 and 2 must export different content")
	}

	check := func(text string, serial uint32) {
		t.Helper()
		want := []string{
			"; source version serial: " + strconv.Itoa(int(serial)),
			"; origin: lab.test.",
			"$ORIGIN lab.test.",
		}
		for _, w := range want {
			if !strings.Contains(text, w+"\n") {
				t.Fatalf("export serial %d missing header %q", serial, w)
			}
		}
		rrs, err := zone.Parse(strings.NewReader(text), "lab.test.",
			zone.Limits{MinTTL: 0, MaxTTL: ^uint32(0)})
		if err != nil {
			t.Fatalf("export serial %d does not reparse: %v", serial, err)
		}
		var nSOA int
		for _, rr := range rrs {
			if soa, ok := rr.(*dns.SOA); ok {
				if soa.Serial != serial {
					t.Fatalf("export serial %d carries SOA serial %d", serial, soa.Serial)
				}
				nSOA++
			}
		}
		if nSOA != 1 {
			t.Fatalf("export serial %d has %d SOA records, want 1", serial, nSOA)
		}
	}
	check(v1Text, 1)
	check(v2Text, 2)

	// The older export must preserve its v1 TXT text and v1-only record
	// set (host2 exists only in v2); MX/SRV fields must survive intact.
	for _, want := range []string{
		`www.lab.test. 3600 IN TXT "multi-record same name v1"`,
		`mx1.lab.test. 3600 IN MX 10 mail.lab.test.`,
		`_sip._tcp.lab.test. 3600 IN SRV 10 60 5060 sip.lab.test.`,
	} {
		if !strings.Contains(v1Text, want+"\n") {
			t.Fatalf("v1 export missing %q", want)
		}
	}
	if strings.Contains(v1Text, "host2.lab.test.") {
		t.Fatal("v1 export must not contain v2-only host2")
	}
	if !strings.Contains(v2Text, `www.lab.test. 3600 IN TXT "multi-record same name v2"`) {
		t.Fatal("v2 export must carry the v2 TXT text")
	}
	if !strings.Contains(v2Text, "host2.lab.test. 3600 IN A 127.0.0.30") {
		t.Fatal("v2 export must carry host2")
	}
}

// TestCLIExportInvalidVersionLeavesNoFile: an unknown serial must fail
// clearly and must not create an output file or clobber an existing one.
func TestCLIExportInvalidVersionLeavesNoFile(t *testing.T) {
	dbURL := testDBURL()
	resetExportDB(t, dbURL)
	cfg := writeTestConfig(t, dbURL)
	dir := filepath.Dir(cfg)

	path := filepath.Join(dir, "should-not-exist.db")
	err := runExport([]string{"-config", cfg, "-serial", "4242", "-out", path})
	if err == nil {
		t.Fatal("export of nonexistent serial must fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error must state the version was not found, got: %v", err)
	}
	if _, stat := os.Stat(path); !os.IsNotExist(stat) {
		t.Fatalf("invalid export created a file: %v", stat)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".dnszone-export-*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}

	// A pre-existing good file at the path is untouched.
	good := filepath.Join(dir, "previous-good.db")
	const marker = "previous good export\n"
	if err := os.WriteFile(good, []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runExport([]string{"-config", cfg, "-serial", "4242", "-out", good}); err == nil {
		t.Fatal("export of nonexistent serial must fail")
	}
	raw, err := os.ReadFile(good)
	if err != nil || string(raw) != marker {
		t.Fatalf("failed export overwrote existing file: %q err=%v", raw, err)
	}
}

// TestCLIExportNoVersions is the empty-database path for serial 0.
func TestCLIExportNoVersions(t *testing.T) {
	dbURL := testDBURL()
	resetExportDB(t, dbURL)
	cfg := writeTestConfig(t, dbURL)
	dir := filepath.Dir(cfg)
	path := filepath.Join(dir, "none.db")
	err := runExport([]string{"-config", cfg, "-out", path})
	if err == nil || !strings.Contains(err.Error(), "no zone version") {
		t.Fatalf("want clear no-version error, got %v", err)
	}
	if _, stat := os.Stat(path); !os.IsNotExist(stat) {
		t.Fatal("no file should be created when nothing is published")
	}
}

// TestCLIExportSerialOutOfRange checks the flag-level validation.
func TestCLIExportSerialOutOfRange(t *testing.T) {
	dbURL := testDBURL()
	resetExportDB(t, dbURL)
	cfg := writeTestConfig(t, dbURL)
	err := runExport([]string{"-config", cfg, "-serial", "4294967296", "-out", filepath.Join(t.TempDir(), "x.db")})
	if err == nil || !strings.Contains(err.Error(), "invalid serial") {
		t.Fatalf("want invalid-serial error, got %v", err)
	}
}
