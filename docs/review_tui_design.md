# Review TUI Design

## Goals

The review workflow exists to triage file integrity scan findings without
rescanning the filesystem and without silently weakening monitoring.

A review session must support:

- large whole-filesystem scans with thousands or millions of findings
- pause and resume
- undo of the last 100 review actions
- bulk exclusion of a directory, hiding affected findings from the active list
- local interactive review on the scanned host
- portable offline review by sending a review artifact to another user
- explicit application of reviewed actions back on the production host

## Non-goals

- Binary review files. The review artifact is user-facing and should remain
  inspectable, diffable, and recoverable.
- File content diffs. Batman stores hashes and metadata, not baseline content.
  Review findings include before/after hash and metadata snapshots, not
  line-by-line content.
- Mutating `baseline.idx` for review state. The baseline index remains a lookup
  structure; review state lives in review artifacts.

## Workflow

Normal local workflow:

```bash
sudo batman baseline
sudo batman scan
sudo batman review
sudo batman review --apply
sudo batman baseline
```

Portable review workflow:

```bash
sudo batman scan
sudo batman review --export latest --output /tmp/batman-review.yaml
# send /tmp/batman-review.yaml to reviewer
# reviewer edits with Batman TUI on another machine or edits YAML directly
sudo batman review --apply /tmp/batman-review.yaml
sudo batman baseline
```

`scan` creates a timestamped review session. `review` opens the latest
in-progress review by default. `--apply` applies reviewed actions.

## Review Artifact

Review sessions are YAML files:

```text
<db_path>/reviews/
  2026-06-28T14-32-10.review.yaml
  2026-06-28T16-05-44.review.yaml
  latest.review.yaml
```

`latest.review.yaml` is a copy of the latest session for portability on file
systems where symlinks are unavailable or inconvenient.

The file is self-contained enough to be reviewed away from the production
server:

```yaml
format: batman-review-v1
session_id: "2026-06-28T14-32-10"
status: in_progress
host: prod-01
config_path: /etc/batman/batman.yaml
baseline_db: /var/lib/batman
summary:
  files: 5290000
  bytes: 1400000000000
  modified: 381
  added: 13712
  deleted: 337
findings:
- id: 1
  kind: modified
  path: /etc/ssh/sshd_config
  reason: checksum, size, modified_time
  before:
    checksum: 5b8d...
    kind: file
    size: 3612
    permissions_octal: '100644'
    owner: 0
    group: 0
    modified_ns: 1782817000000000000
    metadata_changed_ns: 1782817000000000000
    security_metadata_hash: 048a...
  after:
    checksum: ae91...
    kind: file
    size: 3668
    permissions_octal: '100644'
    owner: 0
    group: 0
    modified_ns: 1782817600000000000
    metadata_changed_ns: 1782817600000000000
    security_metadata_hash: 048a...
  size: 3668
  modified_ns: 1782817600000000000
  state: unreviewed
  action: none
actions:
  - id: 17
    kind: exclude
    target: /snap/postman/248/usr/lib/locale
    affected: [1, 2, 3]
    applied: false
```

`before` and `after` are evidence snapshots, not stored file contents. Modified
and moved findings include both snapshots; added findings include only `after`;
deleted findings include only `before`. Snapshot fields are omitted when the
platform cannot provide them. Config policy drift uses the recorded baseline
config hash as `before.checksum` and the active config hash and metadata as
`after`.

## States and Actions

Finding states:

- `unreviewed`: default after scan
- `approved`: known-good change selected for baseline update
- `excluded`: selected for exclusion from future scans
- `flagged`: suspicious or unresolved, no automatic action

Actions:

- `approve`: update baseline for the path
- `exclude`: add exact file or selected parent directory to
  `file_integrity.exclusions`
- `flag`: keep reporting/investigating
- `none`: no reviewed action yet

Deleting a YAML finding is not the review mechanism. Review state is explicit.

## TUI Layout

```text
┌ Batman Review ───────────────────────────────────────────────────────────────────────────────┐
│ Session: 2026-06-28T14-32-10        Status: in progress        Baseline: /var/lib/batman    │
│ Scan: 5.29M files, 1.40TB           Findings: 14,430           Review file: latest           │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ States       Unreviewed 12,481   Approved 42   Excluded 1,904   Flagged 3                   │
│ Kinds        Modified 381        Added 13,712  Deleted 337                                  │
│ Visible      12,481              Filter: state=unreviewed kind=all   Search: /snap/postman  │
├───────────────────────────────┬──────────────────────────────────────────────────────────────┤
│ Findings                      │ Selected Finding                                             │
│                               │                                                              │
│ > ADDED     /snap/postman/... │ Kind: ADDED                                                  │
│   ADDED     /snap/postman/... │ Path: /snap/postman/248/usr/lib/locale/cmn_TW/LC_NAME        │
│   ADDED     /snap/postman/... │ Size: 12.4KB                                                  │
│   MODIFIED  /etc/ssh/sshd...  │ State: unreviewed                                            │
│                               │                                                              │
│                               │ Exclusion Targets                                            │
│                               │   [1] file       .../cmn_TW/LC_NAME              affects 1    │
│                               │   [2] directory  /snap/postman/248/usr/lib/locale affects 423 │
│                               │   [3] directory  /snap/postman/248/usr/lib        affects 891 │
│                               │   [4] directory  /snap/postman                   affects 1,102│
│                               │                                                              │
│                               │ Recent Actions                                                │
│                               │   #17 excluded /snap/postman/248/usr/lib/locale, 423 findings │
├───────────────────────────────┴──────────────────────────────────────────────────────────────┤
│ Commands                                                                                     │
│   ↑/↓ move   enter next   a approve   f flag   1-4 exclude target   u undo   / search        │
│   m state filter   k kind filter   l list sessions   s save   A apply reviewed   q quit      │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Interaction Rules

- Pressing `1` excludes the selected file.
- Pressing `2`-`4` excludes the displayed parent directory target.
- Excluding a directory marks all findings under it as `excluded` and removes
  them from the active unreviewed list.
- `a` approves the selected finding.
- `f` flags the selected finding.
- `u` undoes the most recent review action, including bulk directory
  exclusions. Batman keeps the last 100 actions in memory and in the review
  file.
- `s` saves the review session.
- `A` applies reviewed actions.

## Applying Review Actions

Applying happens on the production host:

- `exclude` actions update `file_integrity.exclusions`
- `approve` actions update the baseline for those paths
- `flagged` findings are left unchanged

`review --apply --operator NAME --comment TEXT` records `applied_at`,
`applied_by`, and `apply_comment` in the review YAML, and records the same
operator/reason in the hash-chained audit log. When the TUI applies a review,
Batman records the current OS user as the operator.

After exclusions are applied, the user should run a new baseline because the
monitored file set has changed.

## Performance Notes

- The review artifact is text because it is user-facing and not the scan hot
  path.
- The TUI should keep findings in memory for responsiveness. A million findings
  is large but feasible if stored compactly. If this becomes a problem, add a
  paged JSONL review format later.
- Directory exclusion target counts should be precomputed once when loading the
  session and updated incrementally after actions.
- Rendering should only build visible rows, not strings for every finding on
  every frame.
