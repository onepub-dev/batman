use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use crate::config::{FileIntegrityConfig, default_max_scan_threads};
use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ContentDigest;
use crate::integrity::checksum::content_checksum_with_buffer;
use crate::integrity::checksum::content_checksum_with_buffer_and_trace_detail;
use crate::integrity::checksum::processed_byte_count;
use crate::integrity::mounts::MountTable;
use crate::integrity::perf_trace;
use crate::integrity::registry::scan_registry_paths;
use crate::integrity::scanner::ScanStats;
use crate::integrity::store::{FileMetadata, META_DIRECTORY};

const RESULT_BUFFER: usize = 1024;
const THREAD_STACK_SIZE: usize = 256 * 1024;

#[derive(Debug)]
pub struct ScannedFile {
    pub path: PathBuf,
    pub checksum: ContentDigest,
    pub size: u64,
    pub processed_bytes: u64,
    pub modified_ns: i128,
    pub metadata: FileMetadata,
}

enum ScanEvent {
    Directory,
    Failed,
    File(ScannedFile),
    Error(BatmanError),
}

struct WorkQueue {
    state: Mutex<WorkState>,
    ready: Condvar,
}

struct WorkState {
    queue: VecDeque<PathBuf>,
    pending: usize,
}

pub fn scan_checksums<F>(config: &FileIntegrityConfig, mut on_file: F) -> BatmanResult<ScanStats>
where
    F: FnMut(ScannedFile, &mut ScanStats) -> BatmanResult<()>,
{
    let mut stats = ScanStats::default();
    let mount_table = Arc::new(MountTable::current());
    let mut initial = VecDeque::new();
    for path in &config.scan_paths {
        if !path.exists() {
            stats.failed += 1;
        } else if !mount_table.path_is_on_excluded_fs(config, path) {
            initial.push_back(path.clone());
        }
    }

    if initial.is_empty() {
        scan_registry_records(config, &mut stats, &mut on_file)?;
        return Ok(stats);
    }

    let queue = Arc::new(WorkQueue {
        state: Mutex::new(WorkState {
            pending: initial.len(),
            queue: initial,
        }),
        ready: Condvar::new(),
    });
    let config = Arc::new(config.clone());
    let (sender, receiver) = sync_channel(RESULT_BUFFER);
    let workers = scan_threads(&config);
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let worker_queue = Arc::clone(&queue);
        let worker_config = Arc::clone(&config);
        let worker_mount_table = Arc::clone(&mount_table);
        let worker_sender = sender.clone();
        let handle = thread::Builder::new()
            .name("batman-scan".to_string())
            .stack_size(THREAD_STACK_SIZE)
            .spawn(move || {
                worker(
                    worker_config,
                    worker_mount_table,
                    worker_queue,
                    worker_sender,
                )
            })
            .map_err(|error| BatmanError::io("spawn scan worker", error))?;
        handles.push(handle);
    }
    drop(sender);

    let mut first_error = None;
    let mut callback_error = None;
    for event in receiver {
        match event {
            ScanEvent::Directory => stats.directories += 1,
            ScanEvent::Failed => stats.failed += 1,
            ScanEvent::File(file) => {
                if file.metadata.flags & META_DIRECTORY == 0 {
                    stats.files += 1;
                    stats.bytes += file.size;
                    stats.processed_bytes += file.processed_bytes;
                }
                if callback_error.is_none()
                    && let Err(error) = on_file(file, &mut stats)
                {
                    callback_error = Some(error);
                }
            }
            ScanEvent::Error(error) => {
                stats.failed += 1;
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    for handle in handles {
        handle
            .join()
            .map_err(|_| BatmanError::Store("scan worker panicked".to_string()))?;
    }

    if let Some(error) = callback_error {
        Err(error)
    } else if let Some(error) = first_error {
        Err(error)
    } else {
        scan_registry_records(&config, &mut stats, &mut on_file)?;
        Ok(stats)
    }
}

fn scan_registry_records<F>(
    config: &FileIntegrityConfig,
    stats: &mut ScanStats,
    on_file: &mut F,
) -> BatmanResult<()>
where
    F: FnMut(ScannedFile, &mut ScanStats) -> BatmanResult<()>,
{
    scan_registry_paths(config, |file| {
        stats.files += 1;
        stats.bytes += file.size;
        stats.processed_bytes += file.processed_bytes;
        on_file(file, stats)
    })
}

fn worker(
    config: Arc<FileIntegrityConfig>,
    mount_table: Arc<MountTable>,
    queue: Arc<WorkQueue>,
    sender: SyncSender<ScanEvent>,
) {
    let mut checksum_buffer = vec![0_u8; scan_buffer_size(&config)];
    while let Some(path) = next_path(&queue) {
        process_path(
            &config,
            &mount_table,
            &queue,
            &sender,
            path,
            &mut checksum_buffer,
        );
        finish_path(&queue);
    }
}

fn next_path(queue: &WorkQueue) -> Option<PathBuf> {
    let mut state = queue.state.lock().expect("scan queue lock poisoned");
    loop {
        if let Some(path) = state.queue.pop_front() {
            return Some(path);
        }
        if state.pending == 0 {
            return None;
        }
        state = queue.ready.wait(state).expect("scan queue lock poisoned");
    }
}

fn finish_path(queue: &WorkQueue) {
    let mut state = queue.state.lock().expect("scan queue lock poisoned");
    state.pending = state.pending.saturating_sub(1);
    queue.ready.notify_all();
}

fn enqueue_child_batch(queue: &WorkQueue, children: &mut Vec<PathBuf>) {
    if children.is_empty() {
        return;
    }
    let mut state = queue.state.lock().expect("scan queue lock poisoned");
    state.pending += children.len();
    for child in children.drain(..).rev() {
        state.queue.push_front(child);
    }
    queue.ready.notify_all();
}

fn process_path(
    config: &FileIntegrityConfig,
    mount_table: &MountTable,
    queue: &WorkQueue,
    sender: &SyncSender<ScanEvent>,
    path: PathBuf,
    checksum_buffer: &mut [u8],
) {
    let metadata_directory = config.is_metadata_directory(&path);
    if (config.is_excluded(&path) && !metadata_directory)
        || mount_table.mountpoint_is_excluded(config, &path)
    {
        return;
    }

    let stat_started = perf_trace::enabled().then(Instant::now);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if let Some(started) = stat_started {
                perf_trace::event(
                    "stat",
                    StatTraceDetail {
                        path: &path,
                        fs_type: mount_table.fs_type_for_path(&path),
                        outcome: StatTraceOutcome::Ok {
                            kind: metadata_kind(&metadata),
                            bytes: metadata.len(),
                        },
                    },
                    started.elapsed(),
                );
            }
            metadata
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(started) = stat_started {
                perf_trace::event(
                    "stat",
                    StatTraceDetail {
                        path: &path,
                        fs_type: mount_table.fs_type_for_path(&path),
                        outcome: StatTraceOutcome::Error("not_found"),
                    },
                    started.elapsed(),
                );
            }
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            if let Some(started) = stat_started {
                perf_trace::event(
                    "stat",
                    StatTraceDetail {
                        path: &path,
                        fs_type: mount_table.fs_type_for_path(&path),
                        outcome: StatTraceOutcome::Error("permission_denied"),
                    },
                    started.elapsed(),
                );
            }
            send_event(sender, ScanEvent::Failed);
            return;
        }
        Err(error) => {
            if let Some(started) = stat_started {
                perf_trace::event(
                    "stat",
                    StatTraceDetail {
                        path: &path,
                        fs_type: mount_table.fs_type_for_path(&path),
                        outcome: StatTraceOutcome::Error("error"),
                    },
                    started.elapsed(),
                );
            }
            send_event(
                sender,
                ScanEvent::Error(BatmanError::io(format!("stat {}", path.display()), error)),
            );
            return;
        }
    };

    if metadata.is_file() {
        let metadata_only = config.is_metadata_only(&path);
        let before_identity = if metadata_only {
            None
        } else {
            platform_file_identity(&path, &metadata)
        };
        let checksum_result = if metadata_only {
            Ok([0; 32])
        } else if perf_trace::enabled() {
            content_checksum_with_buffer_and_trace_detail(
                &path,
                config.scan_byte_limit,
                checksum_buffer,
                HashTraceDetail {
                    path: &path,
                    fs_type: mount_table.fs_type_for_path(&path),
                    bytes: processed_byte_count(metadata.len(), config.scan_byte_limit),
                },
            )
        } else {
            content_checksum_with_buffer(&path, config.scan_byte_limit, checksum_buffer)
        };
        match checksum_result {
            Ok(checksum) => {
                let record_metadata = if metadata_only {
                    metadata
                } else {
                    match stable_file_metadata_after_hash(&path, &metadata, before_identity) {
                        Ok(Some(metadata)) => metadata,
                        Ok(None) => {
                            send_event(sender, ScanEvent::Failed);
                            return;
                        }
                        Err(error) => {
                            send_event(sender, ScanEvent::Error(error));
                            return;
                        }
                    }
                };
                let processed_bytes = if metadata_only {
                    0
                } else {
                    processed_byte_count(record_metadata.len(), config.scan_byte_limit)
                };
                send_event(
                    sender,
                    ScanEvent::File(ScannedFile {
                        checksum,
                        processed_bytes,
                        size: record_metadata.len(),
                        modified_ns: modified_ns(&record_metadata),
                        metadata: FileMetadata::from_path_metadata(&path, &record_metadata),
                        path,
                    }),
                );
            }
            Err(BatmanError::Io { ref source, .. })
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                send_event(sender, ScanEvent::Failed);
            }
            Err(error) => send_event(sender, ScanEvent::Error(error)),
        }
        return;
    }

    if metadata.file_type().is_symlink() {
        match symlink_checksum(&path) {
            Ok(checksum) => send_event(
                sender,
                ScanEvent::File(ScannedFile {
                    checksum,
                    processed_bytes: 0,
                    size: metadata.len(),
                    modified_ns: modified_ns(&metadata),
                    metadata: FileMetadata::from_path_metadata(&path, &metadata),
                    path,
                }),
            ),
            Err(error) => send_event(sender, ScanEvent::Error(error)),
        }
        return;
    }

    if metadata.is_dir() {
        send_event(
            sender,
            ScanEvent::File(ScannedFile {
                checksum: [0; 32],
                processed_bytes: 0,
                size: metadata.len(),
                modified_ns: modified_ns(&metadata),
                metadata: FileMetadata::from_path_metadata(&path, &metadata),
                path: path.clone(),
            }),
        );
        send_event(sender, ScanEvent::Directory);
        if config.is_excluded(&path) {
            return;
        }
        let read_started = perf_trace::enabled().then(Instant::now);
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                send_event(sender, ScanEvent::Failed);
                return;
            }
            Err(error) => {
                send_event(
                    sender,
                    ScanEvent::Error(BatmanError::io(format!("read {}", path.display()), error)),
                );
                return;
            }
        };

        let mut children = Vec::with_capacity(256);
        let mut entries_seen = 0_u64;
        let mut children_enqueued = 0_u64;
        for entry in entries {
            entries_seen += 1;
            match entry {
                Ok(entry) => {
                    let child = entry.path();
                    if (config.is_excluded(&child) && !config.is_metadata_directory(&child))
                        || mount_table.mountpoint_is_excluded(config, &child)
                    {
                        continue;
                    }
                    children.push(child);
                    children_enqueued += 1;
                    if children.len() >= 256 {
                        enqueue_child_batch(queue, &mut children);
                    }
                }
                Err(error) => send_event(
                    sender,
                    ScanEvent::Error(BatmanError::io("read directory entry", error)),
                ),
            }
        }
        enqueue_child_batch(queue, &mut children);
        if let Some(started) = read_started {
            perf_trace::event(
                "read-dir",
                DirectoryTraceDetail {
                    path: &path,
                    fs_type: mount_table.fs_type_for_path(&path),
                    entries: entries_seen,
                    children: children_enqueued,
                },
                started.elapsed(),
            );
        }
        return;
    }

    if !metadata.is_file() {
        send_event(
            sender,
            ScanEvent::File(ScannedFile {
                checksum: [0; 32],
                processed_bytes: 0,
                size: metadata.len(),
                modified_ns: modified_ns(&metadata),
                metadata: FileMetadata::from_path_metadata(&path, &metadata),
                path,
            }),
        );
    }
}

fn stable_file_metadata_after_hash(
    path: &Path,
    before: &fs::Metadata,
    before_identity: Option<PlatformFileIdentity>,
) -> BatmanResult<Option<fs::Metadata>> {
    let after = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(BatmanError::io(format!("stat {}", path.display()), error)),
    };
    if !same_file_hash_identity(path, before, before_identity, &after) {
        return Ok(None);
    }
    Ok(Some(after))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlatformFileIdentity {
    volume: u64,
    file: u64,
}

fn same_file_hash_identity(
    path: &Path,
    before: &fs::Metadata,
    before_identity: Option<PlatformFileIdentity>,
    after: &fs::Metadata,
) -> bool {
    before.is_file()
        && after.is_file()
        && platform_same_file_identity(path, before_identity, after)
        && before.len() == after.len()
        && modified_ns(before) == modified_ns(after)
}

#[cfg(unix)]
fn platform_file_identity(_path: &Path, metadata: &fs::Metadata) -> Option<PlatformFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(PlatformFileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(windows)]
fn platform_file_identity(path: &Path, _metadata: &fs::Metadata) -> Option<PlatformFileIdentity> {
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING,
    };

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        return None;
    }
    Some(PlatformFileIdentity {
        volume: u64::from(info.dwVolumeSerialNumber),
        file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn platform_file_identity(_path: &Path, _metadata: &fs::Metadata) -> Option<PlatformFileIdentity> {
    None
}

fn platform_same_file_identity(
    path: &Path,
    before: Option<PlatformFileIdentity>,
    after: &fs::Metadata,
) -> bool {
    match (before, platform_file_identity(path, after)) {
        (Some(before), Some(after)) => before == after,
        _ => true,
    }
}

fn symlink_checksum(path: &Path) -> BatmanResult<ContentDigest> {
    let target = fs::read_link(path)
        .map_err(|error| BatmanError::io(format!("readlink {}", path.display()), error))?;
    Ok(*blake3::hash(&path_bytes(&target)).as_bytes())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

fn metadata_kind(metadata: &fs::Metadata) -> &'static str {
    if metadata.is_file() {
        "file"
    } else if metadata.is_dir() {
        "dir"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

struct HashTraceDetail<'a> {
    path: &'a Path,
    fs_type: Option<&'a str>,
    bytes: u64,
}

impl fmt::Display for HashTraceDetail<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fs={} bytes={} {}",
            self.fs_type.unwrap_or("unknown"),
            self.bytes,
            self.path.display()
        )
    }
}

struct DirectoryTraceDetail<'a> {
    path: &'a Path,
    fs_type: Option<&'a str>,
    entries: u64,
    children: u64,
}

impl fmt::Display for DirectoryTraceDetail<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fs={} entries={} children={} {}",
            self.fs_type.unwrap_or("unknown"),
            self.entries,
            self.children,
            self.path.display()
        )
    }
}

struct StatTraceDetail<'a> {
    path: &'a Path,
    fs_type: Option<&'a str>,
    outcome: StatTraceOutcome<'a>,
}

enum StatTraceOutcome<'a> {
    Ok { kind: &'a str, bytes: u64 },
    Error(&'a str),
}

impl fmt::Display for StatTraceDetail<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fs={} ", self.fs_type.unwrap_or("unknown"))?;
        match self.outcome {
            StatTraceOutcome::Ok { kind, bytes } => {
                write!(formatter, "kind={kind} bytes={bytes} ")?;
            }
            StatTraceOutcome::Error(error) => {
                write!(formatter, "error={error} ")?;
            }
        }
        write!(formatter, "{}", self.path.display())
    }
}

fn send_event(sender: &SyncSender<ScanEvent>, event: ScanEvent) {
    if perf_trace::enabled() {
        let started = Instant::now();
        let _ = sender.send(event);
        perf_trace::event(
            "scan-send",
            "worker blocked sending scan result",
            started.elapsed(),
        );
    } else {
        let _ = sender.send(event);
    }
}

fn scan_threads(config: &FileIntegrityConfig) -> usize {
    std::env::var("BATMAN_SCAN_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(default_max_scan_threads()))
        .unwrap_or(config.scan_threads)
}

fn scan_buffer_size(config: &FileIntegrityConfig) -> usize {
    std::env::var("BATMAN_SCAN_BUFFER_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 4 * 1024)
        .unwrap_or(config.scan_buffer_size)
}

fn modified_ns(metadata: &fs::Metadata) -> i128 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as i128)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    use crate::config::{FileIntegrityConfig, default_max_scan_threads};
    use crate::integrity::store::META_DIRECTORY;

    use super::{
        DirectoryTraceDetail, HashTraceDetail, StatTraceDetail, StatTraceOutcome,
        platform_file_identity, same_file_hash_identity, scan_checksums, scan_threads,
        stable_file_metadata_after_hash,
    };

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    fn config(scan_threads: usize) -> FileIntegrityConfig {
        FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads,
            scan_buffer_size: 256 * 1024,
            baseline_public_key: None,
            db_path: PathBuf::from("/tmp/batman-db"),
            scan_paths: Vec::new(),
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: PathBuf::from("/tmp"),
        }
    }

    #[test]
    fn hash_trace_detail_includes_filesystem_and_bytes() {
        let path = PathBuf::from("/snap/app/1/bin/tool");
        let detail = HashTraceDetail {
            path: &path,
            fs_type: Some("squashfs"),
            bytes: 123_456,
        };

        assert_eq!(
            detail.to_string(),
            "fs=squashfs bytes=123456 /snap/app/1/bin/tool"
        );
    }

    #[test]
    fn directory_trace_detail_includes_filesystem_and_counts() {
        let path = PathBuf::from("/snap/app/1/usr/lib");
        let detail = DirectoryTraceDetail {
            path: &path,
            fs_type: Some("squashfs"),
            entries: 512,
            children: 500,
        };

        assert_eq!(
            detail.to_string(),
            "fs=squashfs entries=512 children=500 /snap/app/1/usr/lib"
        );
    }

    #[test]
    fn stat_trace_detail_includes_filesystem_kind_and_bytes() {
        let path = PathBuf::from("/snap/app/1/bin/tool");
        let detail = StatTraceDetail {
            path: &path,
            fs_type: Some("squashfs"),
            outcome: StatTraceOutcome::Ok {
                kind: "file",
                bytes: 4096,
            },
        };

        assert_eq!(
            detail.to_string(),
            "fs=squashfs kind=file bytes=4096 /snap/app/1/bin/tool"
        );
    }

    #[test]
    fn stat_trace_detail_includes_errors() {
        let path = PathBuf::from("/snap/app/1/missing");
        let detail = StatTraceDetail {
            path: &path,
            fs_type: Some("squashfs"),
            outcome: StatTraceOutcome::Error("not_found"),
        };

        assert_eq!(
            detail.to_string(),
            "fs=squashfs error=not_found /snap/app/1/missing"
        );
    }

    #[test]
    fn uses_configured_scan_workers_when_env_is_absent() {
        let _guard = env_lock();
        unsafe {
            std::env::remove_var("BATMAN_SCAN_THREADS");
        }

        assert_eq!(scan_threads(&config(3)), 3);
    }

    #[test]
    fn caps_env_scan_workers_to_default_max() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("BATMAN_SCAN_THREADS", "999999");
        }

        assert_eq!(scan_threads(&config(3)), default_max_scan_threads());

        unsafe {
            std::env::remove_var("BATMAN_SCAN_THREADS");
        }
    }

    #[test]
    #[ignore = "synthetic scanner workload benchmark"]
    fn synthetic_small_vs_large_file_scan_experiment() {
        let total_bytes = std::env::var("BATMAN_SCAN_BENCH_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(128 * 1024 * 1024);
        let root = unique_dir("batman-scan-workload");
        let small_dir = root.join("small");
        let large_dir = root.join("large");
        fs::create_dir_all(&small_dir).unwrap();
        fs::create_dir_all(&large_dir).unwrap();

        create_synthetic_files(&small_dir, total_bytes, 16 * 1024);
        create_synthetic_files(&large_dir, total_bytes, 32 * 1024 * 1024);

        run_scan_workload("small", small_dir, &root, total_bytes);
        run_scan_workload("large", large_dir, &root, total_bytes);

        fs::remove_dir_all(root).unwrap();
    }

    fn run_scan_workload(label: &str, path: PathBuf, root: &std::path::Path, expected_bytes: u64) {
        let mut scan_config = config(4);
        scan_config.db_path = root.join("db");
        scan_config.settings_dir = root.join("settings");
        scan_config.scan_buffer_size = 64 * 1024;
        scan_config.scan_paths = vec![path];

        let started = Instant::now();
        let stats = scan_checksums(&scan_config, |_file, _stats| Ok(())).unwrap();
        let elapsed = started.elapsed();
        let mib_per_second = stats.processed_bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
        let files_per_second = stats.files as f64 / elapsed.as_secs_f64();

        assert_eq!(stats.processed_bytes, expected_bytes);
        println!(
            "workload={label} files={} bytes={} elapsed={elapsed:?} throughput={mib_per_second:.1}MiB/s files_per_second={files_per_second:.1}",
            stats.files, stats.processed_bytes
        );
    }

    fn create_synthetic_files(dir: &std::path::Path, total_bytes: u64, file_bytes: u64) {
        let buffer = vec![0_u8; 1024 * 1024];
        let mut written_total = 0_u64;
        let mut index = 0_u64;
        while written_total < total_bytes {
            let target_bytes = (total_bytes - written_total).min(file_bytes);
            let path = dir.join(format!("file-{index:09}.bin"));
            let mut file = File::create(path).unwrap();
            let mut written_file = 0_u64;
            while written_file < target_bytes {
                let write_len = (target_bytes - written_file).min(buffer.len() as u64) as usize;
                file.write_all(&buffer[..write_len]).unwrap();
                written_file += write_len as u64;
            }
            written_total += target_bytes;
            index += 1;
        }
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn scanner_prunes_excluded_subtrees() {
        let root = std::env::temp_dir().join(format!(
            "batman-prune-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let included = root.join("included");
        let excluded = root.join("excluded");
        fs::create_dir_all(&included).unwrap();
        fs::create_dir_all(&excluded).unwrap();
        fs::write(included.join("keep.txt"), "keep").unwrap();
        for index in 0..128 {
            fs::write(excluded.join(format!("skip-{index}.txt")), "skip").unwrap();
        }

        let mut config = config(1);
        config.scan_paths = vec![root.clone()];
        config.exclusions = vec![excluded.clone()];
        config.settings_dir = root.join("settings");
        config.db_path = root.join("db");

        let mut paths = Vec::new();
        let stats = scan_checksums(&config, |file, _stats| {
            paths.push((file.path, file.metadata.flags));
            Ok(())
        })
        .unwrap();

        assert_eq!(stats.files, 1);
        assert!(
            paths
                .iter()
                .any(|(path, flags)| path == &root && flags & META_DIRECTORY != 0)
        );
        assert!(
            paths
                .iter()
                .any(|(path, flags)| path == &included && flags & META_DIRECTORY != 0)
        );
        assert!(paths.iter().any(|(path, flags)| {
            path == &included.join("keep.txt") && flags & META_DIRECTORY == 0
        }));
        assert!(!paths.iter().any(|(path, _)| path.starts_with(&excluded)));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn scanner_records_symlink_target_without_hashing_target_file() {
        use std::os::unix::fs::symlink;

        let root = unique_dir("batman-symlink");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("target.txt"), "target").unwrap();
        symlink("target.txt", root.join("link.txt")).unwrap();

        let mut config = config(1);
        config.scan_paths = vec![root.join("link.txt")];
        config.settings_dir = root.join("settings");
        config.db_path = root.join("db");

        let mut records = Vec::new();
        let stats = scan_checksums(&config, |file, _stats| {
            records.push(file);
            Ok(())
        })
        .unwrap();

        assert_eq!(stats.files, 1);
        assert_eq!(stats.processed_bytes, 0);
        assert_eq!(records[0].path, root.join("link.txt"));
        assert_ne!(records[0].checksum, [0; 32]);
        assert!(
            records[0].metadata.flags & crate::integrity::store::META_SYMLINK != 0,
            "symlink metadata flag should be present"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_stability_check_rejects_size_change_after_hash() {
        let root = unique_dir("batman-stable-file");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("changing.txt");
        fs::write(&path, "before").unwrap();
        let before = fs::symlink_metadata(&path).unwrap();
        let before_identity = platform_file_identity(&path, &before);
        fs::write(&path, "after with a different size").unwrap();

        let after = fs::symlink_metadata(&path).unwrap();
        assert!(!same_file_hash_identity(
            &path,
            &before,
            before_identity,
            &after
        ));
        assert!(
            stable_file_metadata_after_hash(&path, &before, before_identity)
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_stability_check_rejects_same_size_replacement_after_hash() {
        use std::os::unix::fs::MetadataExt;

        let root = unique_dir("batman-replaced-file");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("changing.txt");
        let replacement = root.join("replacement.txt");
        fs::write(&path, "abcdef").unwrap();
        fs::write(&replacement, "uvwxyz").unwrap();
        let before = fs::symlink_metadata(&path).unwrap();
        let before_identity = platform_file_identity(&path, &before);
        fs::rename(&replacement, &path).unwrap();
        let after = fs::symlink_metadata(&path).unwrap();

        assert_eq!(before.len(), after.len());
        assert_ne!(before.ino(), after.ino());
        assert!(!same_file_hash_identity(
            &path,
            &before,
            before_identity,
            &after
        ));
        assert!(
            stable_file_metadata_after_hash(&path, &before, before_identity)
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn metadata_directory_is_recorded_without_scanning_excluded_contents() {
        let root = unique_dir("batman-metadata-directory");
        let noisy = root.join("noisy");
        fs::create_dir_all(&noisy).unwrap();
        fs::write(noisy.join("changing.log"), "skip").unwrap();

        let mut config = config(1);
        config.scan_paths = vec![root.clone()];
        config.exclusions = vec![noisy.clone()];
        config.metadata_directories = vec![noisy.clone()];
        config.settings_dir = root.join("settings");
        config.db_path = root.join("db");

        let mut paths = Vec::new();
        let stats = scan_checksums(&config, |file, _stats| {
            paths.push((file.path, file.checksum, file.processed_bytes));
            Ok(())
        })
        .unwrap();

        assert_eq!(stats.files, 0);
        assert_eq!(stats.directories, 2);
        assert_eq!(
            paths,
            vec![(root.clone(), [0; 32], 0), (noisy, [0; 32], 0),]
        );

        fs::remove_dir_all(root).unwrap();
    }
}
