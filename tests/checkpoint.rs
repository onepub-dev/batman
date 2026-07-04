use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use batman::cli::{CheckpointOptions, GlobalOptions};
use batman::commands::{CommandContext, checkpoint};
use batman::config::LocalSettings;
use batman::integrity::store::BaselineWriter;
use batman::output::Output;
use batman::security::file_content_hash;

#[test]
fn checkpoint_prints_verified_baseline_generation_and_hashes() {
    let _guard = unsigned_baseline_env();
    let root = unique_dir("batman-checkpoint");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    let logfile = root.join("checkpoint.log");
    write_config(&config_path, &db_path);
    write_baseline(&config_path, &db_path);

    let context = test_context(&config_path, &logfile);
    let mut output = Output::new(&context.global).unwrap();
    let code = checkpoint::run(&context, &mut output, CheckpointOptions { json: false }).unwrap();

    assert_eq!(code, 0);
    let report = fs::read_to_string(logfile).unwrap();
    assert!(report.contains("Batman Baseline Checkpoint"));
    assert!(report.contains("Records: 1"));
    assert!(report.contains("Generation: 1"));
    assert!(report.contains("Manifest hash: "));
    assert!(report.contains("Config hash: "));
    assert!(report.contains("BATMAN_BASELINE_MIN_GENERATION=1"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checkpoint_json_is_single_portable_record() {
    let _guard = unsigned_baseline_env();
    let root = unique_dir("batman-checkpoint-json");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    let logfile = root.join("checkpoint-json.log");
    write_config(&config_path, &db_path);
    write_baseline(&config_path, &db_path);

    let context = test_context(&config_path, &logfile);
    let mut output = Output::new(&context.global).unwrap();
    let code = checkpoint::run(&context, &mut output, CheckpointOptions { json: true }).unwrap();

    assert_eq!(code, 0);
    let report = fs::read_to_string(logfile).unwrap();
    assert!(report.starts_with("{\"format\":\"batman-baseline-checkpoint-v1\""));
    assert!(report.contains("\"generation\":1"));
    assert!(report.contains("\"min_generation_env\":\"BATMAN_BASELINE_MIN_GENERATION=1\""));
    assert_eq!(report.lines().count(), 1);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checkpoint_rejects_tampered_baseline() {
    let _guard = unsigned_baseline_env();
    let root = unique_dir("batman-checkpoint-tampered");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    let logfile = root.join("checkpoint-tampered.log");
    write_config(&config_path, &db_path);
    write_baseline(&config_path, &db_path);
    fs::write(db_path.join("baseline.idx"), "tampered").unwrap();

    let context = test_context(&config_path, &logfile);
    let mut output = Output::new(&context.global).unwrap();
    let error = checkpoint::run(&context, &mut output, CheckpointOptions { json: false })
        .unwrap_err()
        .to_string();

    assert!(error.contains("baseline"));

    fs::remove_dir_all(root).unwrap();
}

fn write_config(config_path: &std::path::Path, db_path: &std::path::Path) {
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::create_dir_all(db_path).unwrap();
    fs::write(
        config_path,
        format!(
            "file_integrity:\n  scan_byte_limit: 0\n  db_path: {}\n  scan_paths: []\n",
            db_path.display()
        ),
    )
    .unwrap();
}

fn write_baseline(config_path: &std::path::Path, db_path: &std::path::Path) {
    let mut writer = BaselineWriter::create_with_config_hash(
        db_path,
        0,
        file_content_hash(config_path).unwrap(),
    )
    .unwrap();
    writer
        .add_file("/tmp/example.txt".as_ref(), [1; 32], 12, 123)
        .unwrap();
    assert_eq!(writer.finish().unwrap(), 1);
}

fn test_context(config_path: &std::path::Path, logfile: &std::path::Path) -> CommandContext {
    CommandContext {
        global: GlobalOptions {
            colour: false,
            insecure: true,
            logfile: Some(logfile.to_path_buf()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.to_path_buf()),
    }
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

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unique_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
