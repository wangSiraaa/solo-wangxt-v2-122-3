# dnszone — local-only authoritative DNS zone service

An authoritative-only DNS server for a single internal test zone
(`lab.test.` by default), backed by PostgreSQL for immutable zone
versions and a change log. It is built for a test lab, not the public
internet:

- **Authoritative only.** Answers come solely from the current zone
  snapshot. There is no recursion, no forwarding, no resolver library
  calls, and the process never opens an outbound connection except to
  its configured PostgreSQL. Out-of-zone names get `REFUSED` with `RA=0`.
- **Explicit record-type allow list.** `SOA, NS, A, AAAA, CNAME, MX,
  TXT, SRV, PTR, CAA` only; any other type in a zone file (e.g.
  `DNSKEY`, `RRSIG`) is rejected at publish time.
- **Atomic publication.** Publishing inserts the full RR set, the change
  log and the current-version pointer in one PostgreSQL transaction
  while holding a row lock on the version counter. The serving layer
  holds an immutable snapshot behind an `atomic.Pointer`; publication is
  one pointer swap, so a query can never observe half a version.
- **Controlled zone transfers.** AXFR and IXFR are TCP-only, restricted
  to configured source CIDRs **and** require a valid
  [TSIG](https://datatracker.ietf.org/doc/html/rfc8945) signature
  using the HMAC algorithms provided by `miekg/dns`
  (hmac-sha1/224/256/384/512). No home-grown signing.
- **Correct negative answers.** NXDOMAIN and NODATA are authoritative
  (`AA`) and carry the zone SOA in the authority section with TTL
  `min(SOA TTL, SOA MINIMUM)` per RFC 2308.
- **Validation at the edge.** TTLs outside the configured bounds,
  CNAME/other-record coexistence, duplicate CNAMEs, apex CNAMEs, and
  records whose owner is outside the zone are all rejected and the
  publish rolls back.

## Layout

```
cmd/dnszone/         CLI: serve / publish / versions / export
internal/config/     JSON config (listeners, TTL bounds, ACL, TSIG keys)
internal/zone/       master-file parsing, validation, immutable snapshots,
                     lookup (CNAME chase + wildcards), version diffing,
                     stable master-file rendering
internal/store/      PostgreSQL: versions, records, change log, LISTEN notify
internal/server/     DNS handler: queries + AXFR/IXFR, TSIG/ACL gating
scripts/             postgres bootstrap and dig verification
testdata/            example zones and a TSIG key file
```

## Requirements

- Go 1.25+
- PostgreSQL 14+ (any reachable instance; tested on 15)
- BIND `dig` for the verification script

## Quick start

1. Prepare the database (example uses a local user-space cluster):

   ```sh
   PG_HOME=$HOME/tools/local ./scripts/start-postgres.sh
   ```

   Any PostgreSQL works; point `database_url` in `config.json` at it.
   The schema is created automatically on first start.

2. Build and publish the first version:

   ```sh
   go build -o bin/dnszone ./cmd/dnszone
   ./bin/dnszone publish -config config.json -file testdata/zone-v1.db --note v1
   ```

3. Serve:

   ```sh
   ./bin/dnszone serve -config config.json
   ```

   The server watches PostgreSQL `LISTEN zone_published` and hot-reloads
   new versions; publish a new file with the same command and queries
   move to the new version atomically.

4. Query and transfer with standard `dig`:

   ```sh
   dig @127.0.0.1 -p 5354 www.lab.test A
   dig @127.0.0.1 -p 5354 -k testdata/tsig.key lab.test. AXFR +tcp
   dig @127.0.0.1 -p 5354 -k testdata/tsig.key lab.test. IXFR=1 +tcp
   ```

5. Hand a version to a colleague for offline review:

   ```sh
   ./bin/dnszone export -config config.json -serial 2 -out zone-serial2.db
   ./bin/dnszone export -config config.json | less   # serial 0 = current
   ```

   `export` is strictly read-only: it never changes the current-version
   pointer or any row, so the running service keeps serving unchanged.

## Exporting versions (offline review)

`dnszone export` writes a stored version back out as a standard RFC 1035
master file:

- **Complete record set.** Every supported record type is emitted
  (`SOA, NS, A, AAAA, CNAME, MX, TXT, SRV, PTR, CAA`), each RR with its
  own TTL and the SOA carrying the version serial (refresh/retry/expire/
  minimum included).
- **Stable order.** SOA first, apex NS next, then records sorted by name,
  type and rdata — the same order used for AXFR, so identical versions
  produce byte-identical files.
- **Provenance in the file.** Comment lines record the zone origin,
  source version serial, UTC publication time and stored note. Comments
  are ignored by the parser.
- **Round-trip guaranteed.** Before the file is written it is rendered
  in memory and re-parsed through the same parser used by `publish`; the
  CLI refuses to write if the result is not an equivalent record set with
  the same serial. TXT quoting/escaping (quotes, backslashes, tabs,
  non-ASCII), MX preferences and SRV fields are preserved.
- **No half files.** The output is written to a temp file and renamed
  into place only after the full render and round-trip check, so an
  invalid version (or any other failure) creates nothing and never
  truncates an existing file. An unknown serial fails with
  `zone version not found: serial N`.


## Configuration (`config.json`)

| Key | Meaning |
| --- | --- |
| `zone` | single zone origin to serve (FQDN) |
| `listen_udp` / `listen_tcp` | bind addresses; bind to loopback for a lab-only service |
| `database_url` | PostgreSQL connection string |
| `ttl_min` / `ttl_max` | inclusive TTL window enforced at publish (e.g. 30–86400) |
| `transfer_allow_cidrs` | source networks allowed to AXFR/IXFR (TSIG still required) |
| `tsig_keys` | map of key name (FQDN) → `{algorithm, secret_b64}` |

`secret_b64` is standard base64, the same encoding used in a BIND key
file (`dig -k`).

## Atomicity and transfers

- Each successful publish gets a monotonically increasing serial (the
  SOA serial is rewritten to it) and a stored change log (`ADD`/`DEL`
  rows) derived from the previous version, excluding the SOA itself.
- **AXFR** emits the complete version bracketed by identical SOA RRs.
  Because the handler captures the snapshot pointer once per request, a
  transfer that starts before a publish finishes keeps streaming the
  old version; new transfers get the new one. No mixed stream.
- **IXFR** streams RFC 1995 deltas when the client's serial is a version
  still held in PostgreSQL; an up-to-date client receives a single SOA,
  an ahead-of-server client receives the current SOA, and a missing
  serial falls back to a full AXFR.

## Tests

```sh
go test -race ./...
```

- `internal/zone`: TTL boundaries, same-name multi-records, CNAME
  conflicts, out-of-zone/unsupported-type rejection, CNAME chains,
  wildcards, negative TTL, diff and AXFR ordering, and master-file
  export (stable order, TTL/SOA/TXT/MX/SRV preservation, round-trip).
- `internal/server`: AA/no-recursion answers, NXDOMAIN/NODATA
  authority, out-of-zone REFUSED, atomic snapshot swap, and TSIG+ACL
  transfer gating over real DNS sockets.
- `internal/store` (runs against PostgreSQL; creates/uses
  `dnszone_test`): publish/load, rollback of invalid publishes,
  concurrent publishing with no serial gaps, change-log contents, and
  per-version export round-trips.
- `cmd/dnszone` (runs against PostgreSQL; uses `dnszone_cli_test`):
  CLI export of current and old versions with reparse equivalence, and
  the no-half-written-file / clear-error guarantees for bad versions.

An end-to-end `dig` checklist (flags, negatives, AXFR/IXFR content and
TSIG bookends) lives at `scripts/verify-dig.sh`.

## Security notes

- Malformed/truncated/random packets were fuzzed (thousands of probes):
  the server keeps serving and every reply is a well-formed response.
- Hostile inputs (out-of-zone names, external CNAME targets) do not
  cause any outbound connection: the only established outbound sockets
  are the pool connections to PostgreSQL. There is no HTTP client, no
  dialer, no `net.Resolver` use.
- DNS UPDATE (opcode 5) is answered NOTIMP; only standard queries are
  processed.
- TSIG secrets are configuration data; protect `config.json` like a
  BIND key file.
