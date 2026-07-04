# Batman Rust Port Design

This document is the implementation reference for the Rust-first Batman
implementation. It started as the Dart-to-Rust port plan, and now records the
current feature surface, architecture, baseline storage format, and verification
gates needed before publishing the Rust crate.

## Goals

- Implement the current Batman feature set in Rust, with the previous Dart
  implementation retained under `dart/` as legacy/reference material.
- Keep the runtime memory target below 50 MB RSS for large filesystem baseline,
  scan, and review paths.
- Keep `unsafe` isolated to small platform FFI boundaries for Unix ownership,
  Windows file identity, Windows ACL, registry, and xattr support.
- Prefer streaming I/O and bounded in-memory state over loading full file lists,
  log files, or baseline records into memory.
- Keep source files reviewable; split modules when doing so reduces real
  complexity or risk.
- Use clear structs and `impl` blocks for service-style components.
- Preserve CLI behavior where it remains operationally sound; deliberate
  security changes such as non-zero scan exits must be tested and documented.
- Store file baseline data in a purpose-built binary database if a crate cannot
  meet the memory and speed requirements.
- Preserve FIM-relevant platform metadata without growing per-record memory:
  Unix device/inode identity, non-directory hard-link counts, Unix xattrs,
  Linux inode flags, and Windows owner/group/DACL state are folded into the
  existing fixed-width security metadata hash.

## Existing Feature Surface

### Global CLI

Current global flags:

- `--verbose`, `-v`: enable verbose logging.
- `--colour`, `-c`: enable or disable colored output. Default is enabled.
- `--logfile`, `-l`: append output to a logfile instead of stdout/stderr.
- `--insecure`: allow scans without elevated privileges.
- `--quiet`, `-q`: suppress per-file progress output.
- `--progress`: show count-style progress instead of the current path.
- `--version`: print version and exit.

Current commands:

- `install`
- `baseline`
- `scan`
- `accept`
- `review`
- `logs`
- `cron`
- `doctor`
- `keygen`
- `harden`
- `unharden`
- `checkpoint`

### Configuration Resolution

Batman resolves configuration from an explicit `--config`, then the
`BATMAN_CONFIG` environment variable, then platform defaults. Privileged Unix
runs prefer `/etc/batman/batman.yaml` with data under `/var/lib/batman`; user
runs use the platform user config/data directories.

Important `batman.yaml` fields:

- `file_integrity.scan_byte_limit`, default `0`. A value of `0` means hash the
  whole file; a positive value caps reads at that many bytes.
- `file_integrity.scan_threads`, default `available CPU cores - 2`, with a
  minimum of one.
- `file_integrity.baseline_public_key`, optional Ed25519 public key used to
  verify signed baseline manifests. `BATMAN_BASELINE_PUBLIC_KEY` overrides this
  config value when both are present.
- `file_integrity.scan_paths`, a list of files or directories to scan.
- `file_integrity.exclusions`, a list of path prefixes to skip.
- `db_path`, used for the binary baseline store, scan spool, review sessions,
  and audit log.
- `send_email_on_fail`, `send_email_on_success`.
- `email_server_host`, default `localhost`.
- `email_server_port`, default `25`.
- `email_from_address`.
- `email_fail_to_address`.
- `email_success_to_address`.
- `log_audits.log_sources`.
- `log_audits.rules`.

The Rust port should accept the current documented shape and should also support
the existing observed `file_integrity.db_path` form in bundled examples. The
effective database path must be documented and exposed by `doctor`.

### File Integrity Features

`baseline`:

- Requires root unless `--insecure` is passed.
- Refuses to run when no file integrity scan paths are configured.
- Atomically replaces the previous baseline and preserves recoverable backups
  during replacement.
- Recursively scans configured scan paths.
- Skips configured exclusions, excluded filesystems, and Batman's own database
  directory.
- Adds records for files, symlinks, selected special entries, included
  directories, Windows registry entries, and metadata-only paths.
- Captures content hashes plus metadata such as permissions, owner, group,
  timestamps, and ACL/xattr hashes where the platform supports them.
- Logs permission failures and continues in insecure mode.

`scan`:

- Requires root unless `--insecure` is passed.
- Requires an installed config file.
- Spools the current scan to bounded sorted chunks.
- Streams current entries against the baseline records to report modified,
  added, deleted, and moved paths.
- Writes a portable review session under `db_path/reviews` with finding
  reasons and before/after hash and metadata snapshots.
- Exits `0` only when the scan is clean; exits non-zero when findings, scan
  errors, trust failures, or strict policy drift are present.

`accept`:

- Accepts a file or directory path and updates the baseline for known-good
  changes without a full review session.

`review`:

- Opens scan findings in a terminal UI.
- Supports approve, exclude, flag, undo, state filtering, export, and apply.
- Applies exclusions to `batman.yaml` using secure atomic writes and updates
  approved baseline records where requested.

Current checksum behavior:

- File content uses a 32-byte BLAKE3 digest.
- Empty files hash to BLAKE3's digest of an empty byte stream.
- Non-empty files are read completely when `scan_byte_limit` is `0`; otherwise
  the configured byte limit is hashed and policy lint warns that the scan is
  weaker.

### Log Scanning Features

`logs`:

- Scans all configured log sources that currently exist.
- Requires root unless `--insecure` is passed.

`logs [selector] [path]`:

- With no selector, scan every configured file log source that exists.
- With a source name and optional path, scan that configured source or the
  supplied override path.
- With a rule name and path, scan the path using that configured rule.

Log source types:

- `file`: streams a text file.
  `--since`.
- `journalctl`: streams `journalctl <args>`.

Domain-specific source types are intentionally not part of the Rust port. A
service-specific scanner must be represented as generic source configuration,
`group_by`, and referenced rules.

Log source fields:

- `type`
- `name`, no spaces.
- `description`, default `not supplied`.
- `top`, default `1000`.
- `trim_prefix`, a regex that trims through the end of the match before
  reporting a selected line.
- `reset`, a marker string that clears retained matches and counters when seen.
- `group_by`, a regex used to aggregate matched lines into grouped reports.
- `report_to`, an optional log-source recipient used for log scan email
  notifications when the relevant global email switch is enabled.
- `rules`, a list of rule references.
- Type-specific fields such as `path`, `container`, `since`, and `args`.

Selectors:

- `contains`: line must contain all `match` strings, then must not contain any
  `exclude` strings. Supports `insensitive`.
- `one_of`: line must contain at least one `match` string, then must not contain
  any `exclude` strings. Supports `insensitive`.
- `regex`: line must match all regexes in `match`, then must not match regexes
  in `exclude`.
- `creditcard`: detects 16-digit strings that pass Luhn validation and
  sanitises matched output to `XXXX XXXX XXXX XXXX`.

Selector fields:

- `type`
- `description`
- `match` and `exclude`, accepted as inline YAML lists or indented block lists.
- `risk`: `none`, `low`, `medium`, `high`, `critical`.
- `continue`: when false, stop checking later selectors in the same rule after a
  match. Current default behavior terminates after a match.

Analyser behavior:

- The simple analyser reports matched lines grouped by rule.
- The grouped analyser aggregates by group key, tracks count, first example,
  last example, and highest risk, then reports top entries by risk and count.
- Grouped reporting is selected by adding `group_by` to any log source.
- For compatibility with existing bundled examples, `group_by` on a referenced
  rule is also accepted when the source does not define `group_by`.
- Reset/discard behavior is selected by adding `reset` to any log source.
- Log email notifications are selected by global email settings. A source-level
  `report_to` overrides the global success/failure recipient for that log
  source.

### Operational Commands

`install`:

- Can set `--config`, which must end in `batman.yaml`.
- Can set `--db-path`.
- Supports `--overwrite`.
- Supports `--systemd-dir` to write `batman-scan.service` and
  `batman-scan.timer` for daily scheduled scans on systemd hosts.
- Supports `--launchd-dir` to write a macOS launchd plist.
- Supports `--windows-task-dir` to write a Windows Task Scheduler XML file.
- Creates the config directory.
- Writes default `batman.yaml`.
- Creates the database directory.
- Uses platform-specific default include/exclude/metadata rules.

`cron`:

- Supports `--baseline`, `--scan`, and `--logs`.
- Refuses to run if both scans are disabled.
- Uses default schedule `0 30 22 * * *`.
- Runs optional baseline at startup.
- Runs file-integrity and/or log scans on the schedule using the host's local
  time.

`doctor`:

- Prints local settings, config/database trust, database files, baseline count,
  audit-chain status, scan worker settings, policy lint, self-monitoring
  coverage, and log rule status.
- Warns when production hardening such as signed baseline verification or
  strict config-drift handling is not enabled.
- `doctor --production` exits non-zero when hardening checks fail, so
  deployment scripts can enforce production posture. `--strict` is accepted as
  the legacy spelling.
- Checks external config pinning through `BATMAN_EXPECTED_CONFIG_HASH`, signed
  baseline policy, rollback generation, scheduler policy, audit forwarding,
  self-monitoring, and platform file hardening advisories.

`keygen`:

- Generates a 32-byte Ed25519 seed from the OS random source.
- Prints `BATMAN_BASELINE_PRIVATE_KEY` and `BATMAN_BASELINE_PUBLIC_KEY` values
  for signed baseline setup.
- Tells the operator to store the private key somewhere safe. Manual baseline
  writes prompt for this private key with terminal echo disabled; the environment
  variable form remains available for unattended automation but is not the
  preferred manual workflow because environment variables are easy to leak into
  shell history, service files, process metadata, or diagnostics.
- The public key can be stored as `file_integrity.baseline_public_key` for
  scan-time verification.
- Does not read the scan database or allocate scan-scale buffers.

Unsigned baselines:

- `baseline --unsigned` is an explicit operator opt-out.
- Scans configured with `file_integrity.baseline_public_key`,
  `BATMAN_BASELINE_PUBLIC_KEY`, or `BATMAN_REQUIRE_SIGNED_BASELINE=1` reject the
  unsigned result.
- `baseline --unsigned` is rejected when `BATMAN_REQUIRE_SIGNED_BASELINE=1` is
  enabled.
- `install` initializes config/resources. `keygen` initializes signing keys so
  private key material is created only when the operator explicitly asks for it.

`harden` / `unharden`:

- Lock or unlock Batman config, executable, baseline, and audit artifacts
  around approved maintenance.
- On Linux, use immutable flags for config/baseline artifacts and append-only
  for the audit log where supported.
- On Windows, reapply restrictive ACLs where native tooling is available.

`checkpoint`:

- Verifies the baseline before printing a portable generation/config/baseline
  checkpoint for off-host storage.
- Supports JSON output for deployment tooling.

### Compatibility Traps To Verify

Some observed Dart behavior appears accidental. The Rust port should make these
cases explicit in tests before deciding whether to preserve or correct them:

- `logs` iterates configured sources but currently calls the single-source scan
  path with the command name rather than the source name. Intended behavior is
  to scan every configured source.
- `JournalCtlSource` exists in the Dart tree, but the log-source factory does
  not currently wire the `journalctl` type. Treat support for `journalctl` as an
  intended feature and add a fixture test before relying on it.
- Log source duplicate-name validation only adds names after the first element
  when the set is already non-empty. The Rust parser should reject duplicate
  names deterministically.
- The byte-sum checksum from the Dart prototype was deliberately replaced by
  BLAKE3. This breaks old baselines and requires a fresh baseline.
- Integrity findings deliberately return a non-zero process exit. This is the
  Rust CLI contract for scheduled jobs and is covered by workflow tests.

## Rust Workspace Layout

The Rust crate now lives at the repository root. The previous Dart
implementation lives under `dart/` as reference material:

```text
Cargo.toml
src/
  app.rs
  cli.rs
  commands/
  config/
  integrity/
  logscan/
  output/
  security.rs
  system/
tests/
resource/
docs/
dart/
```

The Rust crate should expose a library layer so command tests can call behavior
without shelling out:

- `batman::config`
- `batman::integrity`
- `batman::logscan`
- `batman::commands`

`main.rs` should only parse process arguments, call `App::run`, and translate
errors to exit codes.

## Recommended Crates

Use well-maintained crates only where they improve correctness without blowing
the memory target:

- CLI: `clap` with derive support.
- Errors: `thiserror` for typed errors, `anyhow` only at command boundaries.
- YAML: `serde`, `serde_yaml`.
- Paths and home directory: `home` or `dirs`.
- Directory traversal: evaluate `ignore` or `walkdir`. Use streaming traversal
  and disable gitignore semantics unless explicitly wanted.
- Hashing for path keys: `md-5` or `blake3`. Path key stability with Dart only
  matters for diagnostics; binary store can use sorted raw paths.
- Regex: `regex`.
- Cron: `cron` crate if it supports required 5-field syntax cleanly, otherwise
  use `croner`.
- SMTP: evaluate `lettre`. If it adds too much baseline memory, isolate email
  behind a feature flag or send only when configured.
- Terminal colors: `anstyle`, `owo-colors`, or clap color support.
- Temporary files: `tempfile`.

Do not add a general embedded database until a prototype proves it is faster and
lower memory than the purpose-built store below.

## Binary Baseline Store Design

The store must support:

- Full rewrite on `baseline`.
- Streaming compare during `scan` plus targeted lookup for review/accept.
- Deleted-file detection.
- Low memory use with roughly 10 million paths.
- Crash-safe replacement.

Use two files in the configured database directory:

```text
baseline.bfi
baseline.idx
baseline.manifest
audit.log
```

`baseline.bfi` is the append-only record file for a completed baseline.
`baseline.idx` is a compact sorted index.
`baseline.manifest` stores the record/index file hashes, config hash, creation
time, generation, and optional keyed BLAKE3 or Ed25519 signature. Ed25519 is
preferred for production because scan hosts only need the public key.
`audit.log` is a hash-chained local audit trail and can be forwarded to syslog
or a TCP JSON-line sink.

### Record File

Header:

```text
magic:      8 bytes  "BATBFI\0\1"
version:    u16      1
flags:      u16      reserved
created:    i64      unix timestamp seconds
limit:      u64      scan byte limit used by the baseline
records:    u64      number of records
```

Record:

```text
path_hash:   u128
checksum:    32 bytes  BLAKE3 content digest or synthetic metadata digest
metadata:    fixed-width FileMetadata
path_len:    u32
path:        [u8; path_len] UTF-8 path bytes
```

`FileMetadata` stores kind flags, size, permissions, owner, group, modified,
created, metadata-change time, and an ACL/xattr hash where available. Directory
records ignore volatile directory size and timestamp churn during compare, while
still detecting kind, permission, owner, group, and ACL changes.
When Unix xattr enumeration fails, Batman stores a deterministic error hash so
loss of ACL/xattr visibility is itself detectable.
On Linux, inode flags from `FS_IOC_GETFLAGS`, such as immutable and append-only,
are included in the same metadata hash when supported by the filesystem.

### Index File

Header:

```text
magic:      8 bytes "BATIDX\0\1"
version:    u16
fanout:     u16
records:    u64
```

Index entry:

```text
path_hash:  u128
offset:     u64
path_len:   u32
```

Index entries are sorted by `path_hash`. Collision ranges are resolved by
seeking into `baseline.bfi` and comparing the full stored path. A 128-bit hash
keeps collision ranges small while still verifying the full path before a lookup
is accepted.

### Scan Strategy

The scan command uses a sequential merge strategy for large filesystems:

1. Traverse the configured filesystem scan paths.
2. Checksum each current file once.
3. Write `(path_hash, checksum, size, mtime_ns, path)` into a current-scan
   spool.
4. Sort current-scan entries in bounded chunks and merge them in hash order.
5. Stream `baseline.idx` in hash order and compare hash groups against the
   current-scan stream.
6. Verify equal hashes by comparing full paths from `baseline.bfi`.
7. Report modified, added, deleted, and moved paths during the merge. Findings
   include reason labels and review snapshots for the relevant baseline and/or
   current record.

For memory below 50 MB:

- No map of all baseline or current paths is loaded.
- Current-scan sorting uses chunk files under the configured database path. The
  current-scan default chunk size is 16,384 entries, which keeps path-heavy scan
  chunks below the memory target.
- Deleted paths are reported through a streaming visitor instead of collecting
  every deleted path in memory.
- Email detail bodies are capped so a mass add/delete/change event cannot retain
  millions of strings before sending a notification.

`BaselineReader::lookup` still exists for point lookups such as `accept` and
targeted inspection. Whole-filesystem scans use the merge path, because per-file
binary search over `baseline.idx` would cause too many random seeks at 10
million files.

Large filesystem changes are represented path-by-path:

- New files are paths present in the current scan but missing from the index.
- Deleted files are baseline records missing from the current-scan stream.
- Moved files are detected as moved findings when content and metadata provide a
  strong candidate match; otherwise they fall back to added/deleted findings.

The current store is optimized for full baseline rebuilds, read-only scans, and
review/accept rewrites. It does not try to mutate `baseline.idx` incrementally.

A B-tree is only warranted if the product needs incremental baseline updates
with many in-place inserts/deletes. For full rebuilds, the flat sorted index is
more compact and cheaper to bulk-build. For very large production scans, the
merge scan trades extra sequential disk writes for far fewer random index seeks.

### Baseline Write Strategy

During `baseline`:

1. Stream discovered files.
2. Write discovered records into bounded sorted spool chunks under `db_path`.
3. Merge spool chunks in path-hash order.
4. Write `baseline.bfi.tmp` and `baseline.idx.tmp` sequentially from the merged
   stream.
5. Write and verify `baseline.manifest.tmp` with record/index hashes, config
   hash, generation, and optional signature.
6. `fsync` files and directory where supported.
7. Rename temp files over existing files atomically with recoverable backups.

This is an external chunked sort path rather than a full in-memory sort, so
baseline memory remains bounded for multi-million-file systems.

## File Scanning Design

`FileIntegrityScanner` owns traversal and statistics:

```rust
pub struct FileIntegrityScanner {
    config: IntegrityConfig,
    output: Output,
}
```

Responsibilities:

- Normalize configured paths.
- Reject missing configured scan paths with an error log and continue.
- Skip excluded path prefixes.
- Skip the Batman settings/database directory.
- Count directories, files, bytes, and failures.
- Checksum files through a bounded parallel worker pipeline. The default worker
  count is configured by `file_integrity.scan_threads`, defaulting to the
  lower of available CPU count minus two or four. `BATMAN_SCAN_THREADS` remains
  available as an environment override for one-off tuning. Workers use small
  stacks and bounded result buffering so memory stays controlled; DB writes
  remain single-threaded.
- Emit progress according to `quiet`, TTY detection, and `progress`. Terminal
  progress is updated in place on one line; logfile output remains line-based.
  The default terminal form is `Calculating Hashes: (101K 12.3MB 6.15MB/s avg
  4.00MB/s now 2.00Kf/s) ...path`, with the path clipped to the current
  terminal width. Scan uses the same format with a `Scanning` prefix. Verbose
  progress also includes DB chunk/byte counters such as `db 12c/2.80MB`.
  `--progress` keeps the path out of the line and reports directories, files,
  processed bytes, average byte rate, rolling five-second byte rate, and
  rolling five-second file rate.
- Measure terminal width with the `terminal_size` crate against stdout, falling
  back to `COLUMNS` and then 80 columns when stdout is not a terminal. The
  progress renderer leaves a one-column margin to avoid terminal auto-wrap.

`ChecksumCalculator`:

- Reads regular files with `BufReader`.
- Reads whole files when `scan_byte_limit` is `0`; otherwise caps reads at
  `scan_byte_limit`.
- Computes a 32-byte BLAKE3 digest.
- Uses a reusable per-worker buffer to avoid per-file allocation churn.

Future checksum algorithm changes should be a new baseline version, not a
silent behavior change.

## Log Scanning Design

Represent log sources with an enum rather than trait objects at first:

```rust
pub enum SourceKind {
    File,
    JournalCtl,
}
```

`LogSource` stores generic source behavior such as reset markers, grouping, and
trim settings as configuration fields rather than hardcoded source subclasses.
It implements methods through `impl LogSource`:

- `name()`
- `description()`
- `exists()`
- `source_label()`
- `open_lines()`
- `preprocess_line()`
- `tidy_line()`
- `analyser_kind()`

Use `BufRead::read_line` for files. Use `std::process::Command` with piped
stdout for `journalctl` sources, then stream stdout through `BufReader`. Do not
capture full command output.

Represent selectors as an enum:

```rust
pub enum Selector {
    Contains(ContainsSelector),
    OneOf(OneOfSelector),
    Regex(RegexSelector),
    CreditCard(CreditCardSelector),
}
```

The scanner flow:

1. Open source stream.
2. For each line, increment the line counter.
3. Run source pre-processing.
4. Run analyser pre-processing.
5. Evaluate referenced rules and selectors in order.
6. Respect selector terminate/continue.
7. Tidy and sanitise matched output.
8. Feed matches to the analyser.
9. Print summary and analyser report.

Simple analyser memory risk:

- Current behavior stores selected lines until report generation.
- Respect `top` by retaining only lines that may be reported where possible.
- For parity, keep grouping by rule and risk sorting, but cap retained details to
  `top` per source to avoid unbounded memory use.

Grouped analyser:

- Store one stats record per group key.
- If group cardinality grows too high, retain top candidates with a bounded heap
  after verifying parity requirements.

## Command Design

Each command module exposes one `run` function that accepts shared context:

```rust
pub struct CommandContext {
    pub global: GlobalOptions,
    pub local_settings: LocalSettings,
}
```

Command functions return `Result<ExitCode, BatmanError>`.

Suggested exit behavior:

- `0`: command completed successfully and a file-integrity scan found no
  findings or scan errors.
- `1`: invalid arguments, missing installation, permission errors, or internal
  command failure.
- `1`: file-integrity scan findings, scan errors, trust failures, or strict
  config-drift failures.

## Error Handling

Use typed errors for recoverable categories:

- `ConfigError`
- `StoreError`
- `ScanError`
- `LogRuleError`
- `ProcessError`
- `EmailError`

At command boundaries:

- Print user-readable messages.
- Include path context.
- Continue scanning on per-file permission errors in insecure mode.
- Fail fast on malformed configuration.

## Privilege Handling

The Dart implementation releases and reacquires privileges through `dcli`.
Rust should start with a simpler model:

- Detect effective UID on Unix.
- Detect Administrator token membership on Windows.
- Require UID 0 on Unix or an elevated Administrator session on Windows unless
  `--insecure`.
- Do not attempt privilege escalation.
- Keep wrapper commands as external process calls.

If setuid behavior is required later, design it explicitly and keep it isolated
in `system::privileges`.

## Install Resources

The Rust binary must embed or package:

- Default local `batman.yaml`.
- Default `batman.yaml`.
- 

Use `include_str!` for small text resources. Keep generated resource code out of
the first port unless packaging requires it.

## Testing Plan

Unit tests:

- Config path resolution with `BATMAN_CONFIG` and default
  home path.
- YAML parsing for file integrity settings.
- YAML parsing for log sources and rules.
- YAML parsing for selector `match`/`exclude` values in inline and block-list
  forms.
- Selector matching for `contains`, `one_of`, `regex`, and `creditcard`.
- Luhn validation and credit-card sanitisation.
- BLAKE3 checksum behavior for whole-file and byte-limited hashing.
- Binary store read/write/lookup/sweep behavior.
- Exclusion prefix behavior.

Integration tests:

- `install` into a temporary home/settings directory.
- first-run install check that creates the default container
  `batman.yaml`, plus the outside-container missing-install error path.
- `baseline` and `scan` over a fixture tree.
- Detection of modified, added, deleted, and moved files.
- targeted scan path diagnostics for missing, unbaselined, matching, and
  mismatching files.
- `logs RULE PATH` over fixture logs.
- `logs SOURCE PATH` over fixture logs.
- `logs SOURCE` when the configured source path is missing, and override-path
  scanning when the configured source path is missing.
- `logs` over configured file sources.
- Cron schedule parsing.
- Cron local-clock parsing for scheduled runtime checks.

Compatibility tests:

- Reuse existing Dart fixture YAML and sample logs.
- Create golden reports only where output stability matters.
- Keep intentional Rust security differences documented rather than forcing
  Dart-compatible behavior.

Performance and memory tests:

- Baseline a generated tree with many small files.
- Scan the same tree with warm and cold cache notes.
- Record peak RSS with `/usr/bin/time -v` or platform equivalent.
- Confirm large baseline, scan, and review workflows stay under 50 MB RSS.
- Benchmark binary store lookup rate.
- Benchmark checksum throughput for large files with different buffer sizes.

## Performance Tuning Checklist

- Use one reusable read buffer per scanner worker.
- Start single-threaded, then add bounded parallelism only if memory remains
  below target.
- Avoid collecting directory traversal results.
- Avoid storing all log matches.
- Avoid allocating lowercase copies per selector when case-insensitive matching
  can be handled with pre-normalized selector values and bounded line buffers.
- Keep binary store lookup path allocation-free except for path normalization.
- Profile before changing storage format.

### Current Measurement Notes

The current Rust implementation has release-mode synthetic scale samples:

- 2M-record baseline writer: about 17 MB maximum RSS.
- 2M-record identical scan compare: about 27 MB maximum RSS.
- 2M-record move-heavy scan compare: about 32 MB maximum RSS.

These samples are below the 50 MB target and exercise the memory-sensitive
baseline/compare paths. Representative whole-disk runs are still useful for I/O
throughput tuning, filesystem-specific stalls, and exclusion policy quality.

The baseline index writer now spills sorted index chunks and merges them into
`baseline.idx`, so baseline creation no longer requires holding every index
entry in memory. The baseline index default in-memory chunk size is 100,000
entries because each entry is fixed-width and small. The current-scan spool uses
a smaller chunk because each current entry owns a path.

### Current Runtime Validation Notes

The Rust binary has been exercised against isolated temporary fixtures for:

- `install --config --db_path --overwrite`, verifying `batman.yaml` and the db
  directory are created.
- first-run install check, verifying the default container
  `batman.yaml` is created when the config file is missing, and the non-container
  missing-install path returns a controlled error.
- `baseline`, verifying baseline records are written for a configured fixture
  tree.
- `scan`, verifying a clean scan succeeds against that baseline and findings
  produce a non-zero exit.
- targeted scan path diagnostics, verifying stored and current diagnostics are
  reported.
- `logs`, verifying configured file log sources and rules scan a fixture log.
- direct rule/source path scans, verifying virtual rule scans work over a
  fixture log.
- Dart-style rule YAML using block-list selector `match` and `exclude` values.
- Generic grouped log scanning using `group_by`, `reset`, and regex
  `trim_prefix` source configuration.

Live external integrations still need environment-backed validation where
available: long-running cron/system scheduler behavior and real SMTP delivery.

## Implementation Phases

### Phase 1: Skeleton and Configuration

- Create Rust crate and root workspace layout.
- Implement CLI shape and global options.
- Implement output routing, color toggle, and logfile append.
- Implement local settings and `batman.yaml` parsing.
- Add configuration validation tests.

### Phase 2: Binary Store and File Integrity

- Implement BLAKE3 content hashing.
- Implement binary store writer and reader.
- Implement baseline scan.
- Implement scan compare with added, modified, deleted, and moved findings.
- Implement `accept`, `review`, and `doctor` baseline count support.
- Add fixture-based file-integrity tests.

### Phase 3: Log Scanning

- Implement rule and selector parsing.
- Implement file source scanning.
- Implement simple analyser.
- Implement direct rule/source path scans and `logs`.
- Implement generic grouped analyser and reset behavior driven by source
  configuration.

### Phase 4: Operations

- Implement `install`.
- Implement `cron`.
- Implement email notifications.
- Package embedded resources.

### Phase 5: Compatibility, Tuning, and Cutover

- Keep Dart fixtures/reference material where useful, but let Rust security
  requirements supersede Dart compatibility.
- Tune buffer sizes and store lookup.
- Add memory regression checks.
- Review source file lengths and split modules over 500 lines.
- Build release binary.
- Document migration from Hive to `baseline.bfi`/`baseline.idx`.
- Follow `docs/cargo_release_checklist.md` before publishing to crates.io.

## Open Decisions

- Whether Rust should read existing Hive baselines. Preferred answer: no; require
  a fresh baseline because the store format changes.
- Whether to add a migration utility from older Dart/Hive baselines. Preferred
  answer: no; require a fresh Rust baseline.
- Whether email support is mandatory in the default binary or feature-gated.
  Preferred answer: default-on if RSS remains below target when idle and during
  scans.

## Definition of Done

The Rust port is complete when:

- All Rust-first commands listed in this document exist in the Rust binary.
- Existing file integrity behavior is implemented and tested.
- Existing log source, rule, selector, and analyser behavior is implemented and
  tested.
- Default install resources are available from the Rust binary.
- The binary baseline store supports baseline, lookup, and deleted-file sweep.
- Normal baseline, scan, and review workflows stay below 50 MB RSS on
  representative workloads, or any exception is measured and documented.
- Any `unsafe` remains isolated to platform FFI code with tests or compile
  coverage.
- Rust source files remain reviewable and are split when doing so reduces risk.
- The Dart source tree remains under `dart/` as legacy/reference material.
