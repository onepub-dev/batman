# eBPF Analysis and Patrol Plan

This document captures a future Linux-only hardening idea for Batman. It is not
current product behavior.

## Objective

Use Linux eBPF to learn which files and directories legitimately change during
normal operation, then optionally enforce that policy by blocking writes outside
the approved mutable set.

This would complement Batman's current file integrity monitoring:

- FIM detects and reviews changes after they happen.
- eBPF analysis observes legitimate runtime mutation patterns.
- eBPF patrol mode prevents unexpected mutation attempts at kernel decision
  points.

## Terminology

Use **mutable allowlist** for patrol mode, not "exclusion list".

In Batman's current FIM workflow, an exclusion means "do not monitor this path".
In enforcement, the more accurate policy is "these are the only paths allowed to
change". Those are different security concepts and should stay distinct in the
CLI, config, and docs.

Suggested policy names:

- `file_integrity.exclusions`: paths not monitored by FIM.
- `file_integrity.metadata_only`: paths monitored without content hashing.
- `patrol.mutable_paths`: paths that eBPF patrol allows to be modified.
- `patrol.mutable_directories`: directories where creates/deletes/renames are
  allowed.

## Candidate Workflow

### Analysis Mode

Analysis mode observes write-like activity and produces a reviewable report. It
must not silently rewrite policy without operator review.

Candidate commands:

```bash
sudo batman patrol analyze --duration 24h
sudo batman patrol report
sudo batman patrol apply --reviewed
```

Operational flow:

1. Install Batman and create a normal baseline.
2. Start analysis mode.
3. Reboot if required for the target workload.
4. Run the main applications and scheduled jobs.
5. Stop analysis and review the observed writes.
6. Apply approved mutable allowlist entries.
7. Re-baseline after approved policy changes.

The analysis report should classify observations as:

- regular file content writes;
- file creates/deletes;
- directory creates/deletes;
- renames, with source and destination;
- chmod/chown;
- xattr/ACL/security metadata changes;
- mmap-backed writes where detectable;
- high-volume paths, such as logs, queues, caches, databases, and temp trees.

The report should propose one of:

- add to `patrol.mutable_paths`;
- add to `patrol.mutable_directories`;
- add to `file_integrity.metadata_only`;
- add to `file_integrity.exclusions`;
- leave monitored and immutable;
- investigate as suspicious.

### Patrol Mode

Patrol mode enforces an approved mutable allowlist. Write attempts outside the
allowlist are denied and audited.

Candidate commands:

```bash
sudo batman patrol enable
sudo batman patrol status
sudo batman patrol disable
sudo batman patrol audit
```

Patrol mode should require explicit operator action and should not be enabled by
default. It should also require a recovery plan before activation.

## Linux Mechanism

The likely enforcement mechanism is BPF LSM, available on kernels with eBPF LSM
support. BPF LSM programs attach to Linux Security Module hooks and can allow or
deny operations.

Candidate hook areas:

- file open/truncate/write intent;
- inode create/unlink/mkdir/rmdir;
- rename/link/symlink;
- chmod/chown/setattr;
- xattr and ACL changes;
- mmap with writable mappings.

The exact hook set needs kernel-version testing. The implementation should avoid
claiming complete protection until the hooks are validated across target
distributions.

## Architecture

Suggested components:

- Rust userspace loader and controller.
- Small eBPF programs for observation/enforcement.
- BPF maps for mutable allowlist policy.
- Ring buffer for analysis and denial events.
- Batman audit log integration.
- Config-to-policy compiler that turns reviewed config into BPF map entries.
- Emergency disable path.

The eBPF program should stay deliberately small. Complex path normalization,
reporting, policy review, and persistence belong in userspace.

## Major Challenges

### Path Matching

Path matching in eBPF is difficult and kernel-version-sensitive. Patrol policy
may need to key on a combination of mount id, inode, device, and normalized path
prefixes rather than plain strings.

Open questions:

- How stable are inode-based policies across package upgrades and reboots?
- How should bind mounts, overlayfs, containers, and chroot environments be
  handled?
- Can recursive directory allowlists be enforced cheaply enough in BPF maps?

### Rename Semantics

Renames need both source and destination policy checks. A move from an allowed
mutable directory into a protected path should be denied. A move out of a
protected path should also be treated carefully.

### Package Updates and Maintenance

Patrol mode can break normal package updates, log rotation, database repair, and
application migrations. Batman needs an explicit maintenance workflow:

```bash
sudo batman patrol disable --maintenance
sudo apt upgrade
sudo batman baseline
sudo batman patrol enable
```

Longer term, a scoped maintenance mode could allow a signed update process or a
specific command to write outside the normal mutable allowlist.

### Boot Safety

A bad patrol policy could prevent a system from booting cleanly or accepting
SSH logins. Patrol mode needs a documented recovery mechanism, such as:

- kernel command-line disable flag;
- systemd unit override;
- boot into rescue mode and remove a pinned BPF link or Batman patrol config;
- timeout-based automatic rollback after first enable.

### Audit Volume

Analysis mode on busy systems can produce high event volume. The userspace
collector needs bounded memory, backpressure handling, event coalescing, and
clear reporting of dropped events.

## Security Model

Patrol mode should be treated as hardening, not as a replacement for baseline
verification.

Required controls should include:

- signed baseline manifests;
- trusted Batman config;
- off-host audit forwarding;
- immutable or otherwise protected Batman binaries/config where available;
- explicit emergency recovery path;
- clear operator review before changing mutable policy.

Attackers with sufficient privilege to unload eBPF programs, edit pinned maps,
or alter Batman config can bypass patrol mode unless those controls are also
hardened.

## Compatibility Requirements

Minimum requirements are likely:

- Linux only.
- Kernel with BPF LSM support.
- BTF availability for CO-RE builds.
- CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON or equivalent privileges, depending on
  kernel and distribution.
- A loader strategy using libbpf, aya, or another maintained eBPF toolchain.

Distribution support must be tested explicitly. Do not assume all supported
Linux hosts can run patrol mode.

## Implementation Phases

### Phase 1: Analysis Prototype

Goal: observe write-like events and produce an operator-readable report.

Deliverables:

- eBPF analysis program and Rust loader.
- Ring-buffer event ingestion.
- Event coalescing by path and operation type.
- `batman patrol analyze` and `batman patrol report`.
- No enforcement.

Estimated effort: 1-2 weeks for a prototype.

### Phase 2: Reviewable Policy Generation

Goal: turn observations into proposed Batman config changes.

Deliverables:

- report classification;
- review/apply workflow;
- config patch generation;
- tests for noisy paths, directories, databases, logs, and temp trees.

Estimated effort: 3-5 weeks total including Phase 1 hardening.

### Phase 3: Patrol Prototype

Goal: deny clear write attempts outside an approved mutable allowlist.

Deliverables:

- BPF LSM enforcement program;
- BPF map policy compiler;
- audit events for denied writes;
- `patrol enable`, `patrol disable`, and `patrol status`;
- first-pass emergency disable documentation.

Estimated effort: 2-4 additional weeks for a controlled prototype.

### Phase 4: Production Patrol

Goal: make patrol mode safe enough for real deployment.

Deliverables:

- distribution compatibility matrix;
- boot-safe rollback;
- maintenance mode;
- robust rename/mount/container semantics;
- CI or system tests on supported kernels;
- release documentation and operational runbooks.

Estimated effort: 2-4 months.

## Recommendation

Build analysis mode first. It is valuable by itself and has low operational
risk. Defer patrol mode until analysis reports and policy review are mature.

Patrol mode should be opt-in, Linux-only, and documented as advanced hardening.
The first production target should be a narrow, well-understood server workload,
not a general desktop or frequently changing development host.
