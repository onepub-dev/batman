# 2.0.0
- Rust implementation is now the first-class project layout.
- Added bounded-memory baseline and scan workflows for large filesystems.
- Added compact progress and completion summaries.
- Added `accept PATH` for accepting known-good baseline changes.
- Added review sessions and a review TUI for approving, excluding, and flagging
  scan findings.
- Added before/after review evidence for file-integrity findings, including
  hashes and available metadata snapshots for modified, added, deleted, moved,
  and config-policy findings.
- Added metadata-only monitoring, directory metadata baselines, Windows registry
  monitoring, signed baseline manifests, strict config drift handling, and a
  hash-chained audit log.
- Added deterministic Unix xattr/ACL error markers so loss of metadata
  visibility is detectable.
- Added Unix device/inode identity and non-directory hard-link count monitoring
  inside the fixed-width security metadata hash.
- Added Linux inode flag monitoring for immutable/append-only style file flags.
- Added Ed25519 key generation, production hardening diagnostics, off-host
  audit forwarding, and self-monitoring checks for Batman's config and
  executable.
- Added `file_integrity.baseline_public_key` so scan hosts can verify signed
  baseline manifests from `batman.yaml` without storing private signing keys.
- Added interactive private-key prompting for signed baseline writes, so manual
  `baseline`, `accept`, and `review --apply` runs do not require exporting the
  private key into the process environment.
- Added `baseline --unsigned` as an explicit opt-out for creating unsigned
  baselines during non-hardened setup or testing.
- Added `BATMAN_EXPECTED_CONFIG_HASH` so production jobs can pin the approved
  `batman.yaml` hash outside the config file itself.
- Added Windows Administrator elevation detection for privileged commands.
- Added platform-specific install config templates.
- Added GitHub Actions coverage for Linux, macOS, Windows, MSRV, package
  contents, and Linux release memory checks.
- Moved Dart implementation under `dart/` as legacy/reference material.

# 1.0.8
Fixed errors when outputing command line errors
Added a default to baseline --docker

# 1.0.7
- incremented version no.
- Fixed a bug when running the integrity scan a second time from cron. Hive was not being re-initialised correctly.

# 1.0.6
- migrated to zone_di2
- first release
- change the default mount fo the dev compose to mount the local dir.
- Fixed the sweep process which had a cast problem.
- Fixed bugs in the integrity scanner which was trying to access the hive store without hashing the path.
- Improved error messages when yaml is incorrect.

# 1.0.1
- Added support for sending an email after each scan.
- Fixed problem with primssions when deleting the hashes directory

## 1.0.0

- Initial version.
