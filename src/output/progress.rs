use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

const RATE_WINDOW: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub struct ProgressSnapshot {
    pub total_files: u64,
    pub total_bytes: u64,
    pub db_chunks: u64,
    pub db_bytes: u64,
    pub average_elapsed: Duration,
    pub recent_files: u64,
    pub recent_bytes: u64,
    pub recent_elapsed: Duration,
}

pub struct ProgressMeter {
    started: Instant,
    samples: VecDeque<ProgressSample>,
}

struct ProgressSample {
    at: Instant,
    files: u64,
    bytes: u64,
}

impl ProgressMeter {
    pub fn new() -> Self {
        let now = Instant::now();
        let mut samples = VecDeque::new();
        samples.push_back(ProgressSample {
            at: now,
            files: 0,
            bytes: 0,
        });
        Self {
            started: now,
            samples,
        }
    }

    pub fn snapshot(
        &mut self,
        total_files: u64,
        total_bytes: u64,
        db_chunks: u64,
        db_bytes: u64,
    ) -> ProgressSnapshot {
        let now = Instant::now();
        self.samples.push_back(ProgressSample {
            at: now,
            files: total_files,
            bytes: total_bytes,
        });
        self.prune(now);
        let oldest = self.samples.front().expect("progress meter has samples");

        ProgressSnapshot {
            total_files,
            total_bytes,
            db_chunks,
            db_bytes,
            average_elapsed: now.duration_since(self.started),
            recent_files: total_files.saturating_sub(oldest.files),
            recent_bytes: total_bytes.saturating_sub(oldest.bytes),
            recent_elapsed: now.duration_since(oldest.at),
        }
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(RATE_WINDOW).unwrap_or(now);
        while self.samples.len() > 2 {
            let second_is_old = self
                .samples
                .get(1)
                .map(|sample| sample.at <= cutoff)
                .unwrap_or(false);
            if !second_is_old {
                break;
            }
            self.samples.pop_front();
        }
    }
}

impl Default for ProgressMeter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn format_count(value: u64) -> String {
    const UNITS: &[&str] = &["", "K", "M", "B", "T"];
    format_scaled(value as f64, UNITS)
}

pub fn format_bytes(value: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    format_scaled(value as f64, UNITS)
}

pub fn format_byte_rate(bytes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return "0B/s".to_string();
    }
    format!(
        "{}/s",
        format_scaled(bytes as f64 / seconds, &["B", "KB", "MB", "GB", "TB", "PB"])
    )
}

pub fn format_file_rate(files: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return "0f/s".to_string();
    }
    format!(
        "{}/s",
        format_scaled(files as f64 / seconds, &["f", "Kf", "Mf", "Bf"])
    )
}

pub fn format_path_progress(
    prefix: &str,
    count: u64,
    snapshot: ProgressSnapshot,
    path: &Path,
    columns: usize,
    verbose: bool,
) -> String {
    let prefix = format_scan_prefix(prefix, count, snapshot, verbose);
    let prefix_len = prefix.chars().count();
    if prefix_len >= columns {
        return prefix.chars().take(columns).collect();
    }
    let path = path.display().to_string();
    let available = columns - prefix_len;
    format!("{prefix}{}", clip_left(&path, available))
}

pub fn format_count_progress(
    prefix: &str,
    directories: u64,
    files: u64,
    snapshot: ProgressSnapshot,
    verbose: bool,
) -> String {
    if verbose {
        format!(
            "{prefix}: dirs={} files={} bytes={} avg={} speed={} file_rate={} db={}c/{}",
            format_count(directories),
            format_count(files),
            format_bytes(snapshot.total_bytes),
            format_byte_rate(snapshot.total_bytes, snapshot.average_elapsed),
            format_byte_rate(snapshot.recent_bytes, snapshot.recent_elapsed),
            format_file_rate(snapshot.recent_files, snapshot.recent_elapsed),
            format_count(snapshot.db_chunks),
            format_bytes(snapshot.db_bytes)
        )
    } else {
        format!(
            "{prefix}: dirs={} files={} bytes={} speed={}",
            format_count(directories),
            format_count(files),
            format_bytes(snapshot.total_bytes),
            format_byte_rate(snapshot.recent_bytes, snapshot.recent_elapsed)
        )
    }
}

fn format_scan_prefix(
    prefix: &str,
    count: u64,
    snapshot: ProgressSnapshot,
    verbose: bool,
) -> String {
    if verbose {
        format!(
            "{prefix}: (files={} bytes={} avg={} speed={} file_rate={} db={}c/{}) ",
            format_count(count),
            format_bytes(snapshot.total_bytes),
            format_byte_rate(snapshot.total_bytes, snapshot.average_elapsed),
            format_byte_rate(snapshot.recent_bytes, snapshot.recent_elapsed),
            format_file_rate(snapshot.recent_files, snapshot.recent_elapsed),
            format_count(snapshot.db_chunks),
            format_bytes(snapshot.db_bytes)
        )
    } else {
        format!(
            "{prefix}: (files={} bytes={} speed={}) ",
            format_count(count),
            format_bytes(snapshot.total_bytes),
            format_byte_rate(snapshot.recent_bytes, snapshot.recent_elapsed)
        )
    }
}

fn format_scaled(value: f64, units: &[&str]) -> String {
    let mut unit = 0;
    let mut scaled = value.max(0.0);
    while scaled >= 1_000.0 && unit + 1 < units.len() {
        scaled /= 1_000.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{scaled:.0}{}", units[unit])
    } else if scaled < 10.0 {
        format!("{scaled:.2}{}", units[unit])
    } else if scaled < 100.0 {
        format!("{scaled:.1}{}", units[unit])
    } else {
        format!("{scaled:.0}{}", units[unit])
    }
}

fn clip_left(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let tail_len = max_chars.saturating_sub(1);
    let tail = value
        .chars()
        .rev()
        .take(tail_len)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use super::{
        ProgressSnapshot, clip_left, format_byte_rate, format_bytes, format_count,
        format_count_progress, format_file_rate, format_path_progress,
    };

    fn snapshot() -> ProgressSnapshot {
        ProgressSnapshot {
            total_files: 101_000,
            total_bytes: 12_300_000,
            db_chunks: 12,
            db_bytes: 2_800_000,
            average_elapsed: Duration::from_secs(2),
            recent_files: 2_000,
            recent_bytes: 4_000_000,
            recent_elapsed: Duration::from_secs(1),
        }
    }

    #[test]
    fn formats_progress_counts_compactly() {
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1.00K");
        assert_eq!(format_count(10_100), "10.1K");
        assert_eq!(format_count(100_000), "100K");
        assert_eq!(format_count(101_000), "101K");
        assert_eq!(format_count(999_000), "999K");
        assert_eq!(format_count(1_000_000), "1.00M");
        assert_eq!(format_count(12_300_000), "12.3M");
        assert_eq!(format_count(123_456_789), "123M");
    }

    #[test]
    fn formats_byte_totals_and_rates_compactly() {
        assert_eq!(format_bytes(999), "999B");
        assert_eq!(format_bytes(1_000), "1.00KB");
        assert_eq!(format_bytes(12_300_000), "12.3MB");
        assert_eq!(
            format_byte_rate(12_300_000, Duration::from_secs(2)),
            "6.15MB/s"
        );
        assert_eq!(format_file_rate(2_000, Duration::from_secs(1)), "2.00Kf/s");
    }

    #[test]
    fn clips_long_paths_from_left() {
        assert_eq!(clip_left("/a/b/c", 20), "/a/b/c");
        assert_eq!(clip_left("/very/long/path/file.txt", 10), "…/file.txt");
    }

    #[test]
    fn path_progress_uses_short_prefix() {
        let line = format_path_progress(
            "Calculating Hashes",
            101_000,
            snapshot(),
            Path::new("/tmp/file.txt"),
            120,
            false,
        );

        assert_eq!(
            line,
            "Calculating Hashes: (files=101K bytes=12.3MB speed=4.00MB/s) /tmp/file.txt"
        );
    }

    #[test]
    fn verbose_path_progress_includes_profiling_values() {
        let line = format_path_progress(
            "Calculating Hashes",
            101_000,
            snapshot(),
            Path::new("/tmp/file.txt"),
            140,
            true,
        );

        assert_eq!(
            line,
            "Calculating Hashes: (files=101K bytes=12.3MB avg=6.15MB/s speed=4.00MB/s file_rate=2.00Kf/s db=12c/2.80MB) /tmp/file.txt"
        );
    }

    #[test]
    fn path_progress_fits_terminal_width() {
        let line = format_path_progress(
            "Calculating Hashes",
            101_000,
            snapshot(),
            Path::new("/very/long/path/to/a/file.txt"),
            80,
            false,
        );

        assert!(line.chars().count() <= 80);
        assert!(line.contains('…'));
    }

    #[test]
    fn count_progress_includes_bytes_and_rate() {
        let line = format_count_progress("Processed", 10, 101_000, snapshot(), true);

        assert_eq!(
            line,
            "Processed: dirs=10 files=101K bytes=12.3MB avg=6.15MB/s speed=4.00MB/s file_rate=2.00Kf/s db=12c/2.80MB"
        );
    }

    #[test]
    fn count_progress_omits_profiling_values_by_default() {
        let line = format_count_progress("Processed", 10, 101_000, snapshot(), false);

        assert_eq!(
            line,
            "Processed: dirs=10 files=101K bytes=12.3MB speed=4.00MB/s"
        );
    }
}
