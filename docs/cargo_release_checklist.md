# Cargo Release Checklist

Use this checklist before publishing the Rust crate to crates.io.

## Local Gates

Run these before any networked Cargo command:

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
cargo doc --no-deps --locked
cargo +1.88.0 check --all-targets --locked
cargo check --target x86_64-pc-windows-gnu --locked
cargo package --locked --offline
cargo package --list --locked --offline
```

Run the release memory checks and keep each maximum RSS below 50MB:

```bash
cargo test --release --locked --no-run
```

Then run the ignored release memory tests used by CI:

- `synthetic_baseline_writer_memory_experiment`
- `synthetic_identical_scan_compare_avoids_per_record_group_allocations`
- `synthetic_moved_scan_compare_stays_under_memory_budget`

## Metadata Gates

Check these before publishing:

- `Cargo.toml` has the intended `version`.
- `Cargo.toml` has a clear `description`, `license`, `repository`, `readme`,
  `keywords`, `categories`, and `rust-version`.
- `cargo package --list --locked --offline` includes `README.md`, `CHANGELOG.md`,
  `LICENSE`, `src/**`, `docs/**`, and only the platform install resources
  embedded by the Rust binary.
- `cargo package --list --locked --offline` does not include legacy Dart artifacts.
- The changelog has a release section for the version being published.
- `tests/release_metadata.rs` passes, proving the top changelog section matches
  `Cargo.toml`'s package version.
- The README getting-started flow still matches the installed CLI.

## CI Gates

GitHub Actions should be green for:

- Rust 1.88.0 MSRV check on Linux.
- Formatting, clippy, tests, and release build on Linux, macOS, and Windows.
- Linux documentation build with `cargo doc --no-deps --locked`.
- Linux release memory checks under 50MB RSS.
- `cargo package --locked --offline` and packaged-source list checks.

## Networked Dry-Run

`cargo publish --dry-run` can contact crates.io and may transmit packaged source
content as part of the publish validation path. Run it only after explicitly
accepting that source-disclosure risk for the current worktree:

```bash
cargo publish --dry-run --allow-dirty --locked
```

If the dry-run succeeds, publish with:

```bash
cargo publish --allow-dirty --locked
```

For the final release, drop `--allow-dirty` and publish from a reviewed clean
tree. `--allow-dirty` is shown only for the current pre-release branch because
this repository currently carries the Rust reorganisation as a large
uncommitted change set.
