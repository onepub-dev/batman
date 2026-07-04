use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use batman::integrity::ContentDigest;
use batman::integrity::store::{
    BaselineFinishProgress, BaselineReader, BaselineWriter, CurrentScanSpool, FileMetadata,
    SeenSet, parse_baseline_private_key,
};
use ed25519_dalek::SigningKey;

#[test]
fn opening_missing_baseline_reports_actionable_error() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-missing");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let error = match BaselineReader::open(&dir) {
        Ok(_) => panic!("expected missing baseline error"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("no baseline exists"));
    assert!(error.contains(&dir.join("baseline.bfi").display().to_string()));
    assert!(error.contains(&dir.join("baseline.idx").display().to_string()));
    assert!(error.contains("batman baseline"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn writes_looks_up_and_sweeps_records() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store");
    fs::create_dir_all(&dir).unwrap();

    let mut writer = BaselineWriter::create(&dir, 100).unwrap();
    writer
        .add_file(Path::new("/tmp/a.txt"), digest(10), 2, 123)
        .unwrap();
    writer
        .add_file(Path::new("/tmp/b.txt"), digest(20), 2, 456)
        .unwrap();
    assert_eq!(writer.finish().unwrap(), 2);

    let mut reader = BaselineReader::open(&dir).unwrap();
    assert_eq!(reader.record_count(), 2);
    let mut seen = SeenSet::new(reader.record_count());

    match reader.lookup(Path::new("/tmp/a.txt")).unwrap() {
        batman::integrity::store::LookupResult::Found { ordinal, record } => {
            seen.mark(ordinal);
            assert_eq!(record.checksum, digest(10));
            assert_eq!(record.metadata.size, 2);
        }
        _ => panic!("expected /tmp/a.txt"),
    }

    match reader.lookup(Path::new("/tmp/missing.txt")).unwrap() {
        batman::integrity::store::LookupResult::Missing => {}
        _ => panic!("expected missing"),
    }

    let mut unseen = Vec::new();
    reader
        .visit_unseen_paths(&seen, |path| {
            unseen.push(path);
            Ok(())
        })
        .unwrap();
    assert_eq!(unseen, vec![Path::new("/tmp/b.txt")]);

    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn baseline_files_are_written_with_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-permissions");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(dir.join("baseline.bfi"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(dir.join("baseline.idx"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(dir.join("baseline.manifest"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_reader_rejects_tampered_record_file() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-tamper-record");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(dir.join("baseline.bfi"))
        .unwrap();
    file.write_all(b"tamper").unwrap();
    drop(file);

    let error = match BaselineReader::open(&dir) {
        Ok(_) => panic!("expected tampered baseline error"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("baseline record file hash mismatch"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_reader_rejects_tampered_index_file() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-tamper-index");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(dir.join("baseline.idx"))
        .unwrap();
    file.write_all(b"tamper").unwrap();
    drop(file);

    let error = match BaselineReader::open(&dir) {
        Ok(_) => panic!("expected tampered baseline error"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("baseline index file hash mismatch"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_manifest_is_signed_when_external_key_is_set() {
    let _guard = env_lock();
    unsafe {
        std::env::set_var("BATMAN_BASELINE_KEY", signing_key());
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
    }
    let dir = unique_dir("batman-store-signed-manifest");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    let manifest = fs::read_to_string(dir.join("baseline.manifest")).unwrap();
    assert!(manifest.contains("signature: keyed-blake3:"));
    BaselineReader::open(&dir).unwrap();

    unsafe {
        std::env::remove_var("BATMAN_BASELINE_KEY");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_manifest_can_be_signed_with_ed25519_and_verified_with_public_key() {
    let _guard = env_lock();
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    unsafe {
        std::env::set_var("BATMAN_BASELINE_PRIVATE_KEY", hex_bytes(&[9; 32]));
        std::env::set_var(
            "BATMAN_BASELINE_PUBLIC_KEY",
            hex_bytes(signing_key.verifying_key().as_bytes()),
        );
        std::env::set_var("BATMAN_REQUIRE_SIGNED_BASELINE", "1");
        std::env::remove_var("BATMAN_BASELINE_KEY");
    }
    let dir = unique_dir("batman-store-ed25519-manifest");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    let manifest = fs::read_to_string(dir.join("baseline.manifest")).unwrap();
    assert!(manifest.contains("signature: ed25519:"));
    BaselineReader::open(&dir).unwrap();

    unsafe {
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_manifest_can_be_verified_with_configured_public_key() {
    let _guard = env_lock();
    let signing_key = SigningKey::from_bytes(&[13; 32]);
    let public_key = hex_bytes(signing_key.verifying_key().as_bytes());
    unsafe {
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_KEY");
    }
    let dir = unique_dir("batman-store-configured-public-key");
    fs::create_dir_all(&dir).unwrap();
    let key = parse_baseline_private_key(&hex_bytes(&[13; 32])).unwrap();
    let mut writer =
        BaselineWriter::create_with_config_hash_and_signing_key(&dir, 100, [0; 32], Some(key))
            .unwrap();
    writer
        .add_file(Path::new("/tmp/a.txt"), digest(10), 2, 123)
        .unwrap();
    assert_eq!(writer.finish().unwrap(), 1);

    BaselineReader::open_with_public_key(&dir, Some(&public_key)).unwrap();

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_reader_rejects_tampered_signed_manifest() {
    let _guard = env_lock();
    unsafe {
        std::env::set_var("BATMAN_BASELINE_KEY", signing_key());
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
    }
    let dir = unique_dir("batman-store-signed-manifest-tamper");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    let path = dir.join("baseline.manifest");
    let mut manifest = fs::read_to_string(&path).unwrap();
    let signature_at = manifest
        .find("signature: keyed-blake3:")
        .expect("signed manifest should contain a signature");
    let last = manifest
        .trim_end()
        .len()
        .checked_sub(1)
        .expect("manifest should not be empty");
    manifest.replace_range(
        last..last + 1,
        if &manifest[last..last + 1] == "0" {
            "1"
        } else {
            "0"
        },
    );
    assert!(signature_at < manifest.len());
    fs::write(&path, manifest).unwrap();

    let error = match BaselineReader::open(&dir) {
        Ok(_) => panic!("expected signed manifest error"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("baseline manifest signature mismatch"));

    unsafe {
        std::env::remove_var("BATMAN_BASELINE_KEY");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn chunked_index_writer_preserves_lookup_and_sweep() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-chunked");
    fs::create_dir_all(&dir).unwrap();

    let mut writer = BaselineWriter::with_index_chunk_limit(&dir, 100, [0; 32], 2).unwrap();
    for index in (0..7).rev() {
        writer
            .add_file(
                Path::new(&format!("/tmp/chunked-{index}.txt")),
                digest(index),
                index,
                index as i128,
            )
            .unwrap();
    }
    assert_eq!(writer.finish().unwrap(), 7);

    let mut reader = BaselineReader::open(&dir).unwrap();
    assert_eq!(reader.record_count(), 7);
    let mut seen = SeenSet::new(reader.record_count());
    for index in [0, 3, 6] {
        match reader
            .lookup(Path::new(&format!("/tmp/chunked-{index}.txt")))
            .unwrap()
        {
            batman::integrity::store::LookupResult::Found { ordinal, record } => {
                seen.mark(ordinal);
                assert_eq!(record.checksum, digest(index));
            }
            _ => panic!("expected chunked record {index}"),
        }
    }

    let mut unseen = Vec::new();
    reader
        .visit_unseen_paths(&seen, |path| {
            unseen.push(path);
            Ok(())
        })
        .unwrap();
    assert_eq!(unseen.len(), 4);
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".chunk.")
    }));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_writer_reports_finalisation_progress() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-progress");
    fs::create_dir_all(&dir).unwrap();

    let mut writer = BaselineWriter::with_index_chunk_limit(&dir, 100, [0; 32], 2).unwrap();
    for index in 0..5 {
        writer
            .add_file(
                Path::new(&format!("/tmp/progress-{index}.txt")),
                digest(index),
                index,
                index as i128,
            )
            .unwrap();
    }

    let mut events = Vec::new();
    assert_eq!(
        writer
            .finish_with_progress(|progress| {
                events.push(progress);
                Ok(())
            })
            .unwrap(),
        5
    );

    assert!(matches!(
        events.first(),
        Some(BaselineFinishProgress::Preparing { records: 5 })
    ));
    assert!(events.iter().any(|event| matches!(
        event,
        BaselineFinishProgress::Writing {
            written: 5,
            records: 5
        }
    )));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, BaselineFinishProgress::Syncing { records: 5 }))
    );
    assert!(matches!(
        events.last(),
        Some(BaselineFinishProgress::Replacing { records: 5 })
    ));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_reader_recovers_record_backup_after_interrupted_replace() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-recover-record");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    fs::rename(dir.join("baseline.bfi"), dir.join("baseline.bfi.prev")).unwrap();

    let reader = BaselineReader::open(&dir).unwrap();
    assert_eq!(reader.record_count(), 2);
    assert!(dir.join("baseline.bfi").exists());
    assert!(dir.join("baseline.idx").exists());
    assert!(dir.join("baseline.manifest").exists());
    assert!(!dir.join("baseline.bfi.prev").exists());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn baseline_reader_rolls_back_partial_new_pair_after_interrupted_replace() {
    let _guard = unsigned_baseline_env();
    let dir = unique_dir("batman-store-recover-pair");
    fs::create_dir_all(&dir).unwrap();
    write_small_baseline(&dir);

    fs::rename(dir.join("baseline.bfi"), dir.join("baseline.bfi.prev")).unwrap();
    fs::rename(dir.join("baseline.idx"), dir.join("baseline.idx.prev")).unwrap();
    fs::write(dir.join("baseline.bfi"), b"incomplete replacement").unwrap();

    let reader = BaselineReader::open(&dir).unwrap();
    assert_eq!(reader.record_count(), 2);
    assert!(dir.join("baseline.bfi").exists());
    assert!(dir.join("baseline.idx").exists());
    assert!(dir.join("baseline.manifest").exists());
    assert!(!dir.join("baseline.bfi.prev").exists());
    assert!(!dir.join("baseline.idx.prev").exists());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn current_scan_spool_merges_chunks_in_hash_order() {
    let dir = unique_dir("batman-current-spool");
    fs::create_dir_all(&dir).unwrap();

    let mut spool = CurrentScanSpool::with_chunk_limit(&dir, 2);
    for index in (0..6).rev() {
        spool
            .push(
                Path::new(&format!("/tmp/current-{index}.txt")),
                digest(index),
                index,
                index as i128,
            )
            .unwrap();
    }

    let mut reader = spool.into_reader().unwrap();
    let mut hashes = Vec::new();
    while let Some(entry) = reader.next_entry().unwrap() {
        hashes.push(entry.path_hash);
    }
    drop(reader);

    assert!(hashes.windows(2).all(|window| window[0] <= window[1]));
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("current_scan.chunk.")
    }));

    fs::remove_dir_all(dir).unwrap();
}

fn write_small_baseline(dir: &Path) {
    let mut writer = BaselineWriter::create(dir, 100).unwrap();
    writer
        .add_file(Path::new("/tmp/a.txt"), digest(10), 2, 123)
        .unwrap();
    writer
        .add_file(Path::new("/tmp/b.txt"), digest(20), 2, 456)
        .unwrap();
    assert_eq!(writer.finish().unwrap(), 2);
}

#[test]
#[ignore = "large synthetic store benchmark"]
fn synthetic_large_baseline_store_scales_to_millions() {
    let _guard = unsigned_baseline_env();
    let records = std::env::var("BATMAN_STORE_RECORDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5_000_000);
    let dir = unique_dir("batman-store-large");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let started = Instant::now();
    let mut writer = BaselineWriter::create(&dir, 100).unwrap();
    for index in 0..records {
        let path = format!("/synthetic/tree/{:03}/{:09}.dat", index % 1000, index);
        writer
            .add_file(Path::new(&path), digest(index), 128, index as i128)
            .unwrap();
    }
    let written = writer.finish().unwrap();
    let write_elapsed = started.elapsed();
    assert_eq!(written, records);

    let open_started = Instant::now();
    let mut reader = BaselineReader::open(&dir).unwrap();
    let open_elapsed = open_started.elapsed();
    assert_eq!(reader.record_count(), records);

    let lookup_started = Instant::now();
    for index in [0, records / 4, records / 2, records - 1] {
        let path = format!("/synthetic/tree/{:03}/{:09}.dat", index % 1000, index);
        match reader.lookup(Path::new(&path)).unwrap() {
            batman::integrity::store::LookupResult::Found { record, .. } => {
                assert_eq!(record.checksum, digest(index));
            }
            _ => panic!("expected synthetic record {index}"),
        }
    }
    let lookup_elapsed = lookup_started.elapsed();

    println!(
        "records={records} write={write_elapsed:?} open={open_elapsed:?} lookups={lookup_elapsed:?}"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "synthetic compare-read benchmark"]
fn synthetic_sorted_baseline_read_experiment() {
    let _guard = unsigned_baseline_env();
    let records = std::env::var("BATMAN_STORE_RECORDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(500_000);
    let dir = unique_dir("batman-store-sorted-experiment");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let mut writer = BaselineWriter::create(&dir, 0).unwrap();
    for index in 0..records {
        let path = format!(
            "/synthetic/tree/{:03}/{:03}/{:09}.dat",
            index % 1000,
            (index / 1000) % 1000,
            index
        );
        writer
            .add_file(Path::new(&path), digest(index), 128, index as i128)
            .unwrap();
    }
    assert_eq!(writer.finish().unwrap(), records);

    let streaming_started = Instant::now();
    let mut reader = BaselineReader::open(&dir).unwrap();
    let mut streaming_sum = 0_u64;
    while let Some(record) = reader.next_record().unwrap() {
        streaming_sum = streaming_sum
            .wrapping_add(record.metadata.size)
            .wrapping_add(record.path.to_string_lossy().len() as u64);
    }
    let streaming_elapsed = streaming_started.elapsed();

    let sorted_path = dir.join("baseline.sorted.records");
    let mut reader = BaselineReader::open(&dir).unwrap();
    write_sorted_record_stream(&mut reader, &sorted_path);

    let sequential_started = Instant::now();
    let sequential_sum = read_sorted_record_stream(&sorted_path);
    let sequential_elapsed = sequential_started.elapsed();
    assert_eq!(streaming_sum, sequential_sum);

    println!(
        "records={records} production_streaming_records={streaming_elapsed:?} raw_sequential_records={sequential_elapsed:?} overhead={:.2}x",
        streaming_elapsed.as_secs_f64() / sequential_elapsed.as_secs_f64()
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "synthetic sorted baseline write benchmark"]
fn synthetic_sorted_baseline_write_experiment() {
    let _guard = unsigned_baseline_env();
    let records = std::env::var("BATMAN_STORE_RECORDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(500_000);
    let current_dir = unique_dir("batman-store-current-write");
    let sorted_dir = unique_dir("batman-store-sorted-write");
    let _ = fs::remove_dir_all(&current_dir);
    let _ = fs::remove_dir_all(&sorted_dir);
    fs::create_dir_all(&current_dir).unwrap();
    fs::create_dir_all(&sorted_dir).unwrap();

    let current_started = Instant::now();
    let mut writer = BaselineWriter::create(&current_dir, 0).unwrap();
    for index in 0..records {
        let path = synthetic_path(index);
        writer
            .add_file(Path::new(&path), digest(index), 128, index as i128)
            .unwrap();
    }
    assert_eq!(writer.finish().unwrap(), records);
    let current_elapsed = current_started.elapsed();

    let sorted_started = Instant::now();
    let mut sorted = Vec::with_capacity(records as usize);
    for index in 0..records {
        let path = synthetic_path(index);
        sorted.push(SyntheticRecord {
            key: batman::integrity::store::path_key(Path::new(&path)),
            path,
            checksum: digest(index),
            metadata: synthetic_metadata(index),
        });
    }
    let collect_elapsed = sorted_started.elapsed();
    sorted.sort_by(|left, right| left.key.cmp(&right.key));
    let sort_elapsed = sorted_started.elapsed() - collect_elapsed;
    write_sorted_records_only(&sorted_dir.join("baseline.sorted.bfi"), &sorted);
    let total_sorted_elapsed = sorted_started.elapsed();
    let write_elapsed = total_sorted_elapsed - collect_elapsed - sort_elapsed;

    println!(
        "records={records} production_writer={current_elapsed:?} in_memory_sorted_total={total_sorted_elapsed:?} collect={collect_elapsed:?} sort={sort_elapsed:?} write={write_elapsed:?} ratio={:.2}x",
        total_sorted_elapsed.as_secs_f64() / current_elapsed.as_secs_f64()
    );

    fs::remove_dir_all(current_dir).unwrap();
    fs::remove_dir_all(sorted_dir).unwrap();
}

#[test]
#[ignore = "synthetic production baseline writer memory benchmark"]
fn synthetic_baseline_writer_memory_experiment() {
    let _guard = unsigned_baseline_env();
    let records = std::env::var("BATMAN_STORE_RECORDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(500_000);
    let dir = unique_dir("batman-store-writer-memory");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let started = Instant::now();
    let mut writer = BaselineWriter::create(&dir, 0).unwrap();
    for index in 0..records {
        let path = synthetic_path(index);
        writer
            .add_file(Path::new(&path), digest(index), 128, index as i128)
            .unwrap();
    }
    let (chunks, estimated_bytes) = writer.progress_counters();
    assert_eq!(writer.finish().unwrap(), records);
    let elapsed = started.elapsed();

    println!(
        "records={records} production_writer={elapsed:?} spool_chunks={chunks} spool_bytes={estimated_bytes}"
    );

    fs::remove_dir_all(dir).unwrap();
}

struct SyntheticRecord {
    key: String,
    path: String,
    checksum: ContentDigest,
    metadata: FileMetadata,
}

fn synthetic_path(index: u64) -> String {
    format!(
        "/synthetic/tree/{:03}/{:03}/{:09}.dat",
        index % 1000,
        (index / 1000) % 1000,
        index
    )
}

fn write_sorted_records_only(path: &Path, records: &[SyntheticRecord]) {
    let file = File::create(path).unwrap();
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    writer
        .write_all(&(records.len() as u64).to_le_bytes())
        .unwrap();
    for record in records {
        let path_bytes = record.path.as_bytes();
        let path_hash = u128::from_str_radix(&record.key, 16).unwrap();
        writer.write_all(&path_hash.to_le_bytes()).unwrap();
        writer.write_all(&record.checksum).unwrap();
        write_metadata(&mut writer, record.metadata);
        writer
            .write_all(&(path_bytes.len() as u32).to_le_bytes())
            .unwrap();
        writer.write_all(path_bytes).unwrap();
    }
    writer.flush().unwrap();
}

fn write_sorted_record_stream(reader: &mut BaselineReader, path: &Path) {
    let file = File::create(path).unwrap();
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    let count = reader.record_count();
    writer.write_all(&count.to_le_bytes()).unwrap();
    while let Some(record) = reader.next_record().unwrap() {
        let path_text = record.path.to_string_lossy();
        let path_bytes = path_text.as_bytes();
        let path_hash = record.path_hash;
        writer.write_all(&path_hash.to_le_bytes()).unwrap();
        writer.write_all(&record.checksum).unwrap();
        write_metadata(&mut writer, record.metadata);
        writer
            .write_all(&(path_bytes.len() as u32).to_le_bytes())
            .unwrap();
        writer.write_all(path_bytes).unwrap();
    }
    writer.flush().unwrap();
}

fn read_sorted_record_stream(path: &Path) -> u64 {
    let file = File::open(path).unwrap();
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut count_bytes = [0_u8; 8];
    reader.read_exact(&mut count_bytes).unwrap();
    let count = u64::from_le_bytes(count_bytes);
    let mut sum = 0_u64;
    for _ in 0..count {
        let mut hash = [0_u8; 16];
        let mut checksum = [0_u8; 32];
        let mut path_len = [0_u8; 4];
        reader.read_exact(&mut hash).unwrap();
        reader.read_exact(&mut checksum).unwrap();
        let metadata = read_metadata(&mut reader);
        reader.read_exact(&mut path_len).unwrap();
        let path_len = u32::from_le_bytes(path_len) as usize;
        let mut path = vec![0_u8; path_len];
        reader.read_exact(&mut path).unwrap();
        sum = sum
            .wrapping_add(metadata.size)
            .wrapping_add(path_len as u64);
    }
    sum
}

fn synthetic_metadata(index: u64) -> FileMetadata {
    FileMetadata {
        flags: 0,
        size: 128,
        permissions: 0,
        owner: 0,
        group: 0,
        modified_ns: index as i128,
        created_ns: 0,
        changed_ns: 0,
        acl_hash: [0; 32],
    }
}

fn write_metadata<W: Write>(writer: &mut W, metadata: FileMetadata) {
    writer.write_all(&metadata.flags.to_le_bytes()).unwrap();
    writer.write_all(&metadata.size.to_le_bytes()).unwrap();
    writer
        .write_all(&metadata.permissions.to_le_bytes())
        .unwrap();
    writer.write_all(&metadata.owner.to_le_bytes()).unwrap();
    writer.write_all(&metadata.group.to_le_bytes()).unwrap();
    writer
        .write_all(&metadata.modified_ns.to_le_bytes())
        .unwrap();
    writer
        .write_all(&metadata.created_ns.to_le_bytes())
        .unwrap();
    writer
        .write_all(&metadata.changed_ns.to_le_bytes())
        .unwrap();
    writer.write_all(&metadata.acl_hash).unwrap();
}

fn read_metadata<R: Read>(reader: &mut R) -> FileMetadata {
    let mut flags = [0_u8; 4];
    let mut size = [0_u8; 8];
    let mut permissions = [0_u8; 8];
    let mut owner = [0_u8; 8];
    let mut group = [0_u8; 8];
    let mut modified_ns = [0_u8; 16];
    let mut created_ns = [0_u8; 16];
    let mut changed_ns = [0_u8; 16];
    let mut acl_hash = [0_u8; 32];
    reader.read_exact(&mut flags).unwrap();
    reader.read_exact(&mut size).unwrap();
    reader.read_exact(&mut permissions).unwrap();
    reader.read_exact(&mut owner).unwrap();
    reader.read_exact(&mut group).unwrap();
    reader.read_exact(&mut modified_ns).unwrap();
    reader.read_exact(&mut created_ns).unwrap();
    reader.read_exact(&mut changed_ns).unwrap();
    reader.read_exact(&mut acl_hash).unwrap();
    FileMetadata {
        flags: u32::from_le_bytes(flags),
        size: u64::from_le_bytes(size),
        permissions: u64::from_le_bytes(permissions),
        owner: u64::from_le_bytes(owner),
        group: u64::from_le_bytes(group),
        modified_ns: i128::from_le_bytes(modified_ns),
        created_ns: i128::from_le_bytes(created_ns),
        changed_ns: i128::from_le_bytes(changed_ns),
        acl_hash,
    }
}

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()))
}

fn env_lock() -> MutexGuard<'static, ()> {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    ENV_LOCK.lock().expect("env lock poisoned")
}

fn unsigned_baseline_env() -> MutexGuard<'static, ()> {
    let guard = env_lock();
    unsafe {
        std::env::remove_var("BATMAN_BASELINE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
    }
    guard
}

fn signing_key() -> &'static str {
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn digest(value: u64) -> ContentDigest {
    *blake3::hash(&value.to_le_bytes()).as_bytes()
}
