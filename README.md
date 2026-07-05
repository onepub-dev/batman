# Batman

Batman is a low-memory file integrity monitoring (FIM) tool with optional log
scanning. It builds a baseline of files, checks the current filesystem against
that baseline, and reports altered, new, deleted, and moved files.

FIM is a key concept in PCI compliance for credit card processing, and Batman
is designed specifically to address PCI DSS section 11.5. It is also useful
for any organisation looking to implement defence in depth.

The Rust implementation is the primary implementation in this repository.

## Speed
Batman is designed to be fast and memory efficient. It can baseline or scan 5M files (1.5TB) in about 10 minutes using less than 50MB of memory (on 6yo hardware).  Batman is multi-threaded and will use up to 4 worker threads by default. You can configure Batman to use less cores via the config settings `file_integrity.scan_threads`.

## Getting Started

Before you install Batman, you should first ensure that the target server has the least surface area possible. To do this, remove any packages that are not actively used by the system, this will speed up the baseline/scan process and reduce the attack surface for hackers to go after.

Install from the repository:

```bash
cargo install --path .
```

Create the initial config:

```bash
sudo batman install
```

Initialize signing keys only when you are ready to operate signed baselines:

```bash
batman keygen
```

`install` writes configuration and scheduler resources. `keygen` is separate so
Batman does not silently create private signing material on a monitored host as
a side effect of config initialization.

On systemd hosts, optionally generate a daily scan service and timer:

```bash
sudo batman install --systemd-dir /etc/systemd/system
sudo systemctl enable --now batman-scan.timer
```

For production scheduler artifacts, include the strict runtime environment in
the generated job definition:

```bash
sudo batman install \
  --systemd-dir /etc/systemd/system \
  --production-scheduler \
  --scheduler-env BATMAN_BASELINE_PUBLIC_KEY=<public-key> \
  --scheduler-env BATMAN_BASELINE_MIN_GENERATION=<generation> \
  --scheduler-env BATMAN_AUDIT_TCP=<host:port>
```

On macOS or Windows, generate scheduler artifacts and register them with the
platform scheduler:

```bash
sudo batman install --launchd-dir /Library/LaunchDaemons
sudo launchctl bootstrap system /Library/LaunchDaemons/com.noojee.batman.scan.plist

batman install --windows-task-dir C:\\Batman
schtasks /Create /TN BatmanScan /XML C:\\Batman\\batman-scan.xml
```

Create the baseline:

```bash
sudo batman baseline
sudo batman checkpoint
```

Run a file scan:

```bash
sudo batman scan
```

`batman scan` exits with `0` when the scan is clean and exits non-zero when it
finds integrity issues, scan errors, or trust failures. This makes it suitable
for cron, systemd timers, and other job runners.

Review the results of the scan in the terminal UI:

```bash
sudo batman review
```
The review command lets you triage findings from the latest scan. You can then
exclude noisy paths, approve known-good changes, or flag suspicious files.

When you first install Batman you are likely to have to go through multiple review cycles as you discover what files are mutated during normal system operations.

Accept a known-good file or directory change into the baseline:

```bash
sudo batman accept /path/to/file-or-directory
```

Each scan writes a portable review session under `db_path/reviews`. The review
file contains the problems found by the scan, the change reason, review state,
and before/after evidence. Modified and moved findings include both baseline
and current snapshots; added findings include the current snapshot; deleted
findings include the baseline snapshot. Snapshots record hashes and metadata
such as kind, size, permissions, owner, group, timestamps, and security metadata
hashes where available. Excluding noisy paths is one possible review result;
approving legitimate changes and flagging suspicious findings are also
supported by the TUI.

Apply reviewed actions on the scanned host:

```bash
sudo batman review --apply --operator "$USER" --comment "ticket-123"
sudo batman baseline
```

`--operator` and `--comment` are optional, but recommended for production
reviews. When omitted, Batman records the current OS user where it can.

For off-host review, export the latest session and apply the reviewed file when
it comes back:

```bash
sudo batman review --export latest --output /tmp/batman-review.yaml
sudo batman review --apply --operator "$USER" --comment "ticket-123" /tmp/batman-review.yaml
sudo batman baseline
```

Use `sudo batman review --list` to show saved sessions. Use
`sudo batman review --dry-run --apply` to preview apply counts.

Use `--quiet` for cron/jobs and `--progress` for count-oriented progress
output. Add `--verbose` when you want profiling details such as byte rates and
baseline spool counters:

```bash
sudo batman --quiet scan
sudo batman --progress baseline
sudo batman --verbose baseline
```

For deeper performance investigations, set `BATMAN_PERF_TRACE=1`. Batman then
writes slow internal events to stderr, such as slow file hashes, scan result
backpressure, current-scan spool flushes, and baseline finalisation phases.
Slow stat/hash events include filesystem type, file kind or processed byte
count, and path. Slow directory reads include filesystem type, entry count,
enqueued child count, and path. Use `BATMAN_PERF_TRACE_MS` to change the
reporting threshold in milliseconds.

## Configuration

`batman install` writes `batman.yaml` and creates the baseline database
directory. The default config is platform-specific and intentionally minimal;
log scanner examples are not installed by default.
On Windows, install expands `file_integrity.scan_paths` to every visible fixed
local drive and skips removable, optical, and network drives.

On Unix, installed config and database paths are made private. When Batman is
run as root, `batman.yaml`, its parent directory, and the database directory are
also made root-owned. Privileged baseline and scan commands refuse group/world
writable config or database paths, symlinks in trusted paths, and non-root-owned
trusted paths unless `--insecure` is used.
On Windows, install uses the native ACL tooling to restrict config and data
paths to Administrators and SYSTEM where possible; doctor warns if broad write
access remains. Run production `install`, `baseline`, `scan`, `accept`, and
`logs` commands from an elevated Administrator shell.

| Entry | Purpose |
| --- | --- |
| `logPath` | Optional log file used by Batman output. |
| `email_server_host` | SMTP server host for scan notifications. |
| `email_server_port` | SMTP server port. |
| `email_from_address` | From address for notification email. |
| `report_on_success` | Send success notifications when `true`. |
| `report_to` | Default failure notification recipient. |
| `email_success_to_address` | Optional success notification recipient. |
| `db_path` | Data directory containing `baseline.bfi`, `baseline.idx`, `baseline.manifest`, scan spool files, and review sessions under `reviews/`. May be top-level or under `file_integrity`. Batman always excludes this directory during scans; do not configure it as a scan root. |
| `file_integrity.scan_byte_limit` | `0` scans whole files. A positive byte count scans only that many bytes per file. |
| `file_integrity.scan_threads` | Optional worker count. Defaults to min(available CPUs minus two, 4), minimum one. |
| `file_integrity.scan_buffer_size` | Optional checksum read buffer per worker, in bytes. Defaults to `65536`. |
| `file_integrity.baseline_public_key` | Optional 64-character hex-encoded 32-byte Ed25519 public key used to verify signed baseline manifests during scans and review operations. `BATMAN_BASELINE_PUBLIC_KEY` overrides this when both are set. |
| `file_integrity.scan_paths` | Files or directories included in the baseline. |
| `file_integrity.exclusions` | Files or directories skipped during baseline and file scans. |
| `file_integrity.excluded_filesystems` | Mounted filesystem types skipped when reached through a scan path. Linux defaults skip virtual/kernel filesystems and SquashFS snap images. Set to `[]` to disable this filter. |
| `file_integrity.metadata_only` | Metadata-only rules. `file.db` monitors one file without hashing content, `/path/` monitors the directory entry itself even when the directory is excluded, and `/path/*` monitors all contents recursively without hashing content. |
| `file_integrity.registry_paths` | Windows-only registry keys to baseline recursively, such as `HKLM\System\CurrentControlSet\Services`. Ignored on Unix. |

Baseline signing uses an Ed25519 private key only when creating or updating a
baseline. Store that private key somewhere safe, outside the monitored host
where possible. When a signed baseline is required, `batman baseline`,
`batman accept`, and `batman review --apply` prompt for the private key with
terminal echo disabled.

`BATMAN_BASELINE_PRIVATE_KEY` remains available for unattended automation, but
environment variables are a weak place for secrets: they often end up in shell
history, service definitions, crash diagnostics, process metadata, or runbooks.
For manual operations, use the prompt and retrieve the key from a password
manager, vault, or removable offline location. The public verification key can
be stored in `file_integrity.baseline_public_key` or provided as
`BATMAN_BASELINE_PUBLIC_KEY`; the environment value takes precedence. Keep
strict controls such as `BATMAN_REQUIRE_SIGNED_BASELINE`,
`BATMAN_EXPECTED_CONFIG_HASH`, and `BATMAN_BASELINE_MIN_GENERATION` outside
`batman.yaml` so a config edit cannot silently disable them:

| Environment | Purpose |
| --- | --- |
| `BATMAN_BASELINE_PRIVATE_KEY` | Optional 64-character hex-encoded 32-byte Ed25519 seed for unattended baseline creation or updates. Prefer the interactive prompt for manual runs, and keep this off production scan hosts where possible. |
| `BATMAN_BASELINE_PUBLIC_KEY` | Optional 64-character hex-encoded 32-byte Ed25519 public key. When set during reads, Batman verifies the Ed25519 manifest signature without needing the private key and overrides `file_integrity.baseline_public_key`. |
| `BATMAN_BASELINE_KEY` | Legacy optional 64-character hex-encoded 32-byte symmetric key for keyed BLAKE3 manifest signatures. Prefer Ed25519 for production so scan hosts cannot forge baselines. |
| `BATMAN_REQUIRE_SIGNED_BASELINE` | Set to `1` to refuse unsigned manifests, and to refuse signed manifests when no configured key can verify them. Use this in production once you have created a signed baseline. |
| `BATMAN_BASELINE_MIN_GENERATION` | Optional minimum accepted manifest generation. Set from an external checkpoint to reject rollback to an older signed baseline. |
| `BATMAN_STRICT_CONFIG` | Set to `1` for scheduled production scans to abort when `batman.yaml` differs from the config hash recorded in the baseline. Without this, config drift is reported as a review finding. |
| `BATMAN_EXPECTED_CONFIG_HASH` | Optional 64-character BLAKE3 hash of the approved `batman.yaml`. When set, Batman refuses to run if the active config does not match this externally supplied hash. |
| `BATMAN_AUDIT_TCP` | Optional `host:port` TCP sink for forwarding each audit event JSON line off-host. |
| `BATMAN_AUDIT_SYSLOG` | Set to `1` on Unix to forward audit events to syslog. |
| `BATMAN_AUDIT_SINK_REQUIRED` | Set to `1` for scheduled production runs to fail when configured audit forwarding fails. |

Generate an Ed25519 signing key pair with:

```bash
batman keygen
```

Store the printed private key in a password manager, vault, or removable
offline location. Put only the public key in `batman.yaml`:

```yaml
file_integrity:
  baseline_public_key: <public-key>
```

If `BATMAN_REQUIRE_SIGNED_BASELINE=1` is set, Batman refuses to write a
baseline unless a private Ed25519 key is entered at the prompt, supplied through
`BATMAN_BASELINE_PRIVATE_KEY`, or the legacy `BATMAN_BASELINE_KEY` is present.
If signing is configured but no private key is available, Batman tells you to
run `batman keygen` first or retrieve the existing private key from your secure
storage before it asks for the key.
If `BATMAN_BASELINE_PUBLIC_KEY` or `file_integrity.baseline_public_key` is
configured while creating a baseline, the private key must match that public
key; the legacy symmetric key cannot create a manifest accepted by Ed25519
public-key verification. Use `file_integrity.baseline_public_key` or
`BATMAN_BASELINE_PUBLIC_KEY` on production scan hosts to verify the baseline
without giving the host enough secret material to forge one.

To intentionally create an unsigned baseline, run:

```bash
sudo batman baseline --unsigned
```

This is an explicit opt-out. Scans with `file_integrity.baseline_public_key`,
`BATMAN_BASELINE_PUBLIC_KEY`, or `BATMAN_REQUIRE_SIGNED_BASELINE=1` will reject
the resulting unsigned baseline. `baseline --unsigned` is refused when
`BATMAN_REQUIRE_SIGNED_BASELINE=1` is enabled.

For a hardened production deployment, treat these as required controls rather
than optional diagnostics:

- keep `BATMAN_BASELINE_PRIVATE_KEY` off scheduled scan hosts;
- set `file_integrity.baseline_public_key` or `BATMAN_BASELINE_PUBLIC_KEY`,
  and set `BATMAN_REQUIRE_SIGNED_BASELINE=1`;
- set `BATMAN_STRICT_CONFIG=1` so `batman.yaml` drift aborts the scan;
- set `BATMAN_EXPECTED_CONFIG_HASH` from the approved config hash so policy is
  pinned outside `batman.yaml` itself;
- set `BATMAN_BASELINE_MIN_GENERATION` from an external checkpoint to reject
  rollback to older signed baselines; after each approved baseline, run
  `batman checkpoint` and store the printed generation/hash outside the host;
- forward audit events off-host and set `BATMAN_AUDIT_SINK_REQUIRED=1`.

Before enabling scheduled production scans, run:

```bash
sudo BATMAN_REQUIRE_SIGNED_BASELINE=1 \
  BATMAN_BASELINE_PUBLIC_KEY=<public-key> \
  BATMAN_BASELINE_MIN_GENERATION=<generation> \
  BATMAN_STRICT_CONFIG=1 \
  BATMAN_EXPECTED_CONFIG_HASH=<config-hash> \
  BATMAN_AUDIT_SINK_REQUIRED=1 \
  batman doctor --production
```

`doctor --production` exits non-zero when hardening is incomplete. It checks
trusted config/database permissions, signed-baseline policy, rollback policy,
whether the active `batman.yaml` still matches the baseline's recorded config
hash, off-host audit forwarding, and whether Batman's active config and
executable are content-hashed by the configured file-integrity scan paths. It
also checks the executable's trust metadata and any known installed Batman
scheduler artifacts it can find, because those files can change which config,
scheduler environment, or binary the scheduled scan uses. In production mode it
also warns if a scheduler artifact does not reference the active config or does
not carry the strict scheduler environment generated by
`--production-scheduler`. It also prints the verified baseline generation and
creation time; use that
generation value when updating an external `BATMAN_BASELINE_MIN_GENERATION`
checkpoint after an approved baseline.
`batman install --production-scheduler` adds the strict scheduler environment
defaults `BATMAN_REQUIRE_SIGNED_BASELINE=1`, `BATMAN_STRICT_CONFIG=1`,
`BATMAN_AUDIT_SINK_REQUIRED=1`, and the current
`BATMAN_EXPECTED_CONFIG_HASH` to generated systemd, launchd, and Windows Task
Scheduler artifacts. Use repeated `--scheduler-env KEY=VALUE` entries to add
the public key, external baseline generation, and audit sink details. After an
approved config change, update the scheduler's expected config hash before
scheduled production scans resume.
On Linux it also reports advisory filesystem flag hardening for Batman's own
artifacts. After approved baseline changes, operators can make the active
config and completed baseline files immutable and the audit log append-only:

```bash
sudo batman harden --dry-run
sudo batman harden
```

Before an approved baseline rebuild or review apply, unlock the artifacts, do
the maintenance, then harden them again:

```bash
sudo batman unharden
sudo batman review --apply
sudo batman baseline
sudo batman harden
```

On Linux, `batman harden` applies the equivalent of:

```bash
sudo chattr +i /etc/batman/batman.yaml /var/lib/batman/baseline.bfi /var/lib/batman/baseline.idx /var/lib/batman/baseline.manifest
sudo chattr +i "$(command -v batman)"
sudo chattr +a /var/lib/batman/audit.log
```

On macOS it uses file flags where available. On Windows it reapplies restrictive
ACLs; there is no direct immutable flag equivalent.

After each approved baseline, export a checkpoint and store it somewhere the
scanned host cannot rewrite:

```bash
sudo batman checkpoint
sudo batman checkpoint --json > /secure/off-host/batman-checkpoint.json
```

The checkpoint command verifies the baseline before printing anything. Use the
reported `BATMAN_BASELINE_MIN_GENERATION` value in scheduled scan environments
to reject rollback to an older signed baseline, and use the reported config hash
as `BATMAN_EXPECTED_CONFIG_HASH`.

Example:

```yaml
email_server_host: localhost
email_server_port: 25
email_from_address: scanner@localhost
report_on_success: false
report_to: root@localhost

file_integrity:
  scan_byte_limit: 0
  # scan_threads: 4
  # scan_buffer_size: 65536
  # baseline_public_key: <public-key>
  db_path: /var/lib/batman
  scan_paths:
    - /
  exclusions:
    - /dev
    - /proc
    - /run
    - /snap
    - /sys
    - /tmp
    - /var/lib/batman
    - /var/log
  excluded_filesystems:
    - proc
    - squashfs
    - sysfs
  metadata_only:
    - /var/lib/example.db
    - /var/log/
    - /var/lib/example-cache/*
  registry_paths: []
```

## Whole Filesystem Scans

For an entire local disk, keep `scan_byte_limit: 0` so whole files are hashed.
Partial scans are faster but weaker and can miss changes beyond the configured
byte limit.

On Linux, the default config excludes `/snap`. Snap revisions are read-only
loop-mounted SquashFS images, so scanning `/snap` hashes the expanded
decompressed view and can be much slower than normal filesystem reads. The
backing package images under `/var/lib/snapd/snaps` remain covered unless you
exclude them separately.

Start with broad scan paths and expect to tune exclusions after the first scan:

```bash
sudo batman baseline
sudo batman scan
sudo batman review
```

Review findings carefully. Directory exclusions remove every file under that
path from future monitoring, so use the TUI counters and affected-file counts
before applying. Use `metadata_only` for files such as databases whose content
changes normally but whose ownership, permissions, size, timestamps, or ACLs
should still be monitored. Use a trailing slash, for example `/var/log/`, when
you only want the directory entry baselined while its contents remain excluded.
Use `/*`, for example `/var/lib/app/*`, when every entry under that directory
should be metadata-only. Then apply reviewed actions and rebuild the baseline
if exclusions changed:

```bash
sudo batman review --apply
sudo batman baseline
```

## Baseline Store

Batman stores the baseline in three files under `db_path`:

- `baseline.bfi` contains file records sorted by path hash.
- `baseline.idx` contains a compact lookup index for targeted commands.
- `baseline.manifest` records hashes of the baseline files and policy hash so
  scans can detect partial or accidental baseline tampering before comparing
  files.
- `audit.log` records successful baseline, scan, review apply, and accept
  actions as append-oriented JSON lines. Each event contains a `previous_hash`
  and `hash` so edits or deleted lines break the audit chain. On Unix it is
  written with `0600` permissions.

Included directories are baselined as records so ownership, permissions, ACLs,
and file-kind changes are detected. Directory size and timestamp churn is not
reported as a separate modification because normal file adds and deletes already
produce explicit findings.
Batman also records platform security metadata in a fixed 32-byte hash. On
Unix-like systems this includes device/inode identity and the hard-link count
for non-directories, so replacement and hard-link changes are detected without
adding fields to each baseline record. Extended attributes are included in the
same hash; if Batman cannot list xattrs for a path, it records a deterministic
error marker rather than silently treating the path as having no ACL/xattr
state. On Linux, inode flags exposed through `FS_IOC_GETFLAGS`, such as
immutable and append-only flags, are included when the filesystem supports
them. On Windows, the same metadata slot records owner/group/DACL security
descriptor state.

When a baseline is written with a prompted private key or
`BATMAN_BASELINE_PRIVATE_KEY`, `baseline.manifest` includes an Ed25519 signature
over the manifest fields. Set `file_integrity.baseline_public_key` or
`BATMAN_BASELINE_PUBLIC_KEY`, plus `BATMAN_REQUIRE_SIGNED_BASELINE=1`, for
scheduled scans to reject unsigned, tampered, or unverifiable baselines without
putting the private key on the monitored host. `BATMAN_BASELINE_KEY` remains
available for keyed BLAKE3 signatures, but it is weaker operationally because a
host that can verify the baseline can also forge one if that symmetric key is
compromised.

The manifest also records a monotonically increasing generation and creation
time. Set `BATMAN_BASELINE_MIN_GENERATION` from an external checkpoint if you
need rollback protection against restoring an older but otherwise valid signed
baseline. `batman doctor --strict` exits non-zero when production hardening is
missing, including signed-baseline verification, generation rollback policy,
strict config handling, active-config drift, self-monitoring coverage, and
off-host audit forwarding. `batman doctor --production` is the preferred
spelling for deployment checks. On Linux, doctor also reports advisory
immutable/append-only hardening for Batman's own files; these advisories are not
hard failures because support varies by filesystem and the flags must be
temporarily removed for approved baseline maintenance.

File scans spool the current filesystem into bounded sorted chunks, then stream
those chunks against `baseline.bfi`. The index is kept for targeted lookups
such as file checks and review actions. This keeps memory bounded for large
filesystems with millions of files.

## Log Scanning

The log scanner is still supported, but example log scanner rules are kept out
of installed defaults. See [docs/log_scanner_example.yaml](docs/log_scanner_example.yaml)
for a sample `log_audits` configuration.

Run all configured log sources:

```bash
sudo batman logs
```

Run a configured source by name, a source against a different path, or a rule
against a path:

```bash
sudo batman logs app
sudo batman logs app /var/log/app.log
sudo batman logs errors /var/log/app.log
```

## Future Hardening

An eBPF-based Linux analysis and patrol mode is being considered as future
hardening. The current plan is documented in
[docs/ebpf_patrol_plan.md](docs/ebpf_patrol_plan.md).

## Development Flags

`--insecure` skips Batman's elevated privilege checks. It is intended for local
development and tests only; normal Unix scans should run with `sudo`, and
normal Windows scans should run from an elevated Administrator shell.

## Contributor Build

Batman requires Rust 1.88 or newer. Build and test from source:

```bash
cargo build --release
cargo test
./target/release/batman --help
```

Before publishing to crates.io, follow
[docs/cargo_release_checklist.md](docs/cargo_release_checklist.md).

## Dart Legacy Code

The previous Dart implementation has moved to [dart/](dart/). It is retained as
legacy/reference material; new development should target the Rust crate.
