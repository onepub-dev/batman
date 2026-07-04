use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

use batman::cli::GlobalOptions;
use batman::commands::CommandContext;
use batman::commands::review::{
    ReviewFinding, ReviewFindingKind, ReviewFindingSpool, ReviewReason, ReviewSummary,
    read_review_session, write_review_from_finding_spool,
};
use batman::config::{BatmanConfig, EmailConfig, FileIntegrityConfig, LocalSettings};

#[test]
#[ignore = "synthetic large review-generation benchmark"]
fn synthetic_large_review_generation_uses_spooled_findings() {
    let records = std::env::var("BATMAN_REVIEW_FINDINGS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100_000);
    let root = unique_dir("batman-review-spool");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::create_dir_all(&db_path).unwrap();
    fs::write(&config_path, "file_integrity:\n  scan_paths: []\n").unwrap();

    let config = test_config(db_path.clone());
    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            quiet: true,
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };

    let mut spool = ReviewFindingSpool::create(&config).unwrap();
    let started = Instant::now();
    for index in 0..records {
        let id = u32::try_from(index + 1).expect("synthetic review ids fit in u32");
        let kind = match index % 3 {
            0 => ReviewFindingKind::Added,
            1 => ReviewFindingKind::Modified,
            _ => ReviewFindingKind::Deleted,
        };
        let reason = if kind == ReviewFindingKind::Modified {
            ReviewReason::from_names(&["checksum"])
        } else {
            ReviewReason::empty()
        };
        spool
            .push(&ReviewFinding::new(
                id,
                kind,
                format!("/synthetic/review/tree/{index:09}/file-{index:09}.dat").into_boxed_str(),
                4096 + index,
                1_782_700_000_000_000_000_i64 + index as i64,
                reason,
            ))
            .unwrap();
    }
    let spool_write = started.elapsed();

    let summary = ReviewSummary {
        files: records,
        bytes: records * 4096,
        modified: records / 3 + u64::from(records % 3 > 1),
        added: records / 3 + u64::from(!records.is_multiple_of(3)),
        deleted: records / 3,
        moved: 0,
    };
    let started = Instant::now();
    let review_path =
        write_review_from_finding_spool(&context, &config, &summary, spool.finish().unwrap())
            .unwrap();
    let yaml_write = started.elapsed();

    let latest = db_path.join("reviews").join("latest.review.yaml");
    assert!(review_path.exists());
    assert!(latest.exists());
    assert!(fs::read_dir(db_path.join("reviews")).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".review-findings-")
    }));

    let counted = count_yaml_findings(&latest);
    assert_eq!(counted, records);
    let decode = std::env::var("BATMAN_REVIEW_DECODE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let decode_time = if decode {
        let started = Instant::now();
        let decoded = read_review_session(&latest).unwrap();
        assert_eq!(decoded.findings.len(), records as usize);
        Some(started.elapsed())
    } else {
        None
    };

    eprintln!(
        "records={records} spool_write={spool_write:?} yaml_write={yaml_write:?} decode={decode_time:?} yaml_bytes={}",
        fs::metadata(&latest).unwrap().len(),
    );
    fs::remove_dir_all(root).unwrap();
}

fn test_config(db_path: PathBuf) -> BatmanConfig {
    BatmanConfig {
        file_integrity: FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 64 * 1024,
            baseline_public_key: None,
            db_path,
            scan_paths: Vec::new(),
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: std::env::temp_dir(),
        },
        email: EmailConfig {
            send_on_fail: false,
            send_on_success: false,
            server_host: String::new(),
            server_port: 25,
            from_address: String::new(),
            fail_to_address: String::new(),
            success_to_address: String::new(),
        },
    }
}

fn unique_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{}-{}-{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn count_yaml_findings(path: &PathBuf) -> u64 {
    let reader = BufReader::new(fs::File::open(path).unwrap());
    reader
        .lines()
        .map(|line| line.unwrap())
        .filter(|line| line.starts_with("- id: "))
        .count() as u64
}
