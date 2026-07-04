#![allow(clippy::too_many_arguments)]

use std::borrow::Cow;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audit::append_event;
use crate::cli::ScanOptions;
use crate::commands::{CommandContext, ensure_trusted_config, ensure_trusted_data_path, review};
use crate::config::BatmanConfig;
use crate::errors::BatmanResult;
use crate::integrity::ScanStats;
use crate::integrity::checksum::content_checksum;
use crate::integrity::format_digest;
use crate::integrity::scan_checksums;
use crate::integrity::store::{
    BaselineReader, BaselineRecord, CurrentScanEntry, CurrentScanReader, CurrentScanSpool,
    FileMetadata, LookupResult, META_ACL, META_CHANGED, META_CREATED, META_DIRECTORY, META_GROUP,
    META_KIND_MASK, META_OWNER, META_PERMISSIONS, REQUIRE_SIGNED_BASELINE_ENV, path_hash_value,
    path_key,
};
use crate::output::{
    Output, ProgressMeter, Style, format_bytes, format_count, notify_integrity_result,
};
use crate::security::{env_flag_enabled, file_content_hash};
use crate::system::{is_privileged, required_privilege_description};

const MAX_EMAIL_DETAILS: usize = 1000;
const LAST_SCAN_FINDINGS_FILE: &str = "last_scan.findings";
const COMPARE_PROGRESS_INTERVAL: u64 = 100_000;
const STRICT_CONFIG_ENV: &str = "BATMAN_STRICT_CONFIG";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrityFindingKind {
    Altered,
    New,
    Deleted,
}

impl IntegrityFindingKind {
    pub fn as_review_label(&self) -> &'static str {
        match self {
            Self::Altered => "MODIFIED",
            Self::New => "ADDED",
            Self::Deleted => "DELETED",
        }
    }

    pub fn from_review_label(value: &str) -> Option<Self> {
        match value {
            "MODIFIED" => Some(Self::Altered),
            "ADDED" => Some(Self::New),
            "DELETED" => Some(Self::Deleted),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityFinding {
    pub kind: IntegrityFindingKind,
    pub path: Box<Path>,
    pub size: u64,
    pub modified_ns: i128,
    pub reason: Cow<'static, str>,
}

pub struct IntegrityReport {
    pub stats: ScanStats,
    pub summary: review::ReviewSummary,
    pub findings: Option<review::ReviewFindingSpoolFile>,
    details: Vec<String>,
    omitted_details: u64,
}

struct IntegrityFindings {
    count: u64,
    summary: review::ReviewSummary,
    findings: Option<review::ReviewFindingSpool>,
    moves: Option<MoveTracker>,
    details: Vec<String>,
    omitted_details: u64,
}

struct MoveTracker {
    root: PathBuf,
    added: Option<CurrentScanSpool>,
    deleted: Option<CurrentScanSpool>,
}

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: ScanOptions,
) -> BatmanResult<u8> {
    if !context.global.insecure && !is_privileged() {
        output.error(format!(
            "Error: You must run with {} to run a file scan",
            required_privilege_description()
        ))?;
        return Ok(1);
    }
    if !ensure_trusted_config(context, output)? {
        return Ok(1);
    }

    if let Some(path) = options.path {
        if !path.is_dir() {
            return inspect_path(context, output, &path);
        }
        let (config, mut report) =
            scan_report_for_target(context, output, context.global.verbose, Some(&path))?;
        return finish_report(context, output, config, &mut report);
    }

    let (config, mut report) = scan_report(context, output, context.global.verbose)?;

    finish_report(context, output, config, &mut report)
}

fn finish_report(
    context: &CommandContext,
    output: &mut Output,
    config: BatmanConfig,
    report: &mut IntegrityReport,
) -> BatmanResult<u8> {
    let summary = &report.summary;
    let finding_count = summary.modified + summary.added + summary.deleted + summary.moved;
    let exit_code = if finding_count == 0 && report.stats.failed == 0 {
        0
    } else {
        1
    };
    output.line(Style::Plain, "")?;
    if finding_count == 0 {
        output.line(
            Style::Summary,
            format!(
                "File Integrity Scan complete. No errors. Scanned dirs: {} Scanned files: {} Bytes: {}",
                format_count(report.stats.directories),
                format_count(report.stats.files),
                format_bytes(report.stats.bytes)
            ),
        )?;
    } else {
        output.line(
            Style::Summary,
            format!(
                "File Integrity Scan found {} issues: modified {} added {} deleted {} moved {}. Scanned files: {} Dirs: {} Bytes: {}",
                format_count(finding_count),
                format_count(summary.modified),
                format_count(summary.added),
                format_count(summary.deleted),
                format_count(summary.moved),
                format_count(report.stats.files),
                format_count(report.stats.directories),
                format_bytes(report.stats.bytes)
            ),
        )?;
    }
    if report.omitted_details > 0 {
        report.details.push(format!(
            "{} additional findings omitted from email details",
            report.omitted_details
        ));
    }
    let findings = report
        .findings
        .take()
        .ok_or_else(|| crate::errors::BatmanError::Store("missing review findings".to_string()))?;
    let review_path =
        review::write_review_from_finding_spool(context, &config, &report.summary, findings)?;
    output.line(
        Style::Plain,
        format!("Review file: {}", review_path.display()),
    )?;
    append_event(
        &config.file_integrity.db_path,
        "scan",
        &[
            ("review_file", review_path.display().to_string()),
            ("issues", finding_count.to_string()),
            ("modified", summary.modified.to_string()),
            ("added", summary.added.to_string()),
            ("deleted", summary.deleted.to_string()),
            ("moved", summary.moved.to_string()),
            ("directories", report.stats.directories.to_string()),
            ("files", report.stats.files.to_string()),
            ("bytes", report.stats.bytes.to_string()),
            ("failed", report.stats.failed.to_string()),
        ],
    )?;

    notify_integrity_result(
        &config.email,
        output,
        "File Integrity Scan",
        finding_count == 0,
        &report.stats,
        finding_count,
        &report.details,
    )?;
    Ok(exit_code)
}

pub fn last_findings_path(config: &BatmanConfig) -> PathBuf {
    config.file_integrity.db_path.join(LAST_SCAN_FINDINGS_FILE)
}

pub fn write_last_findings(
    config: &BatmanConfig,
    findings: &[IntegrityFinding],
) -> BatmanResult<()> {
    let path = last_findings_path(config);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            crate::errors::BatmanError::io(format!("create {}", parent.display()), error)
        })?;
    }
    let mut content = String::new();
    content.push_str("# Batman last scan findings v1\n");
    content.push_str("# Generated by `batman scan`; tab-separated KIND<TAB>PATH.\n");
    content.push_str("# This file is used by `batman review` to avoid rescanning.\n");
    for finding in findings {
        content.push_str(finding.kind.as_review_label());
        content.push('\t');
        content.push_str(&finding.path.display().to_string());
        content.push('\n');
    }
    fs::write(&path, content)
        .map_err(|error| crate::errors::BatmanError::io(format!("write {}", path.display()), error))
}

pub fn read_last_findings(config: &BatmanConfig) -> BatmanResult<Option<Vec<IntegrityFinding>>> {
    let findings_path = last_findings_path(config);
    let content = match fs::read_to_string(&findings_path) {
        Ok(content) => content,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(crate::errors::BatmanError::io(
                format!("read {}", findings_path.display()),
                error,
            ));
        }
    };
    let mut findings = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((kind, path_text)) = trimmed.split_once('\t') else {
            return Err(crate::errors::BatmanError::Parse(format!(
                "{}:{} expected KIND<TAB>PATH",
                findings_path.display(),
                line_no + 1
            )));
        };
        findings.push(IntegrityFinding {
            kind: IntegrityFindingKind::from_review_label(kind).ok_or_else(|| {
                crate::errors::BatmanError::Parse(format!(
                    "{}:{} unknown finding kind {kind}",
                    findings_path.display(),
                    line_no + 1
                ))
            })?,
            path: PathBuf::from(path_text).into_boxed_path(),
            size: 0,
            modified_ns: 0,
            reason: Cow::Borrowed(""),
        });
    }
    Ok(Some(findings))
}

pub fn scan_report(
    context: &CommandContext,
    output: &mut Output,
    emit_findings: bool,
) -> BatmanResult<(BatmanConfig, IntegrityReport)> {
    scan_report_for_target(context, output, emit_findings, None)
}

fn scan_report_for_target(
    context: &CommandContext,
    output: &mut Output,
    emit_findings: bool,
    target: Option<&Path>,
) -> BatmanResult<(BatmanConfig, IntegrityReport)> {
    let mut config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    if !ensure_trusted_data_path(context, output, &config.file_integrity.db_path)? {
        return Err(crate::errors::BatmanError::Store(
            "untrusted database path".to_string(),
        ));
    }
    let mut reader = BaselineReader::open_with_public_key(
        &config.file_integrity.db_path,
        config.file_integrity.baseline_public_key.as_deref(),
    )?;
    let baseline_config_hash = reader.config_hash();
    let current_config_hash = file_content_hash(&context.local_settings.config_path)?;
    let config_changed =
        baseline_config_hash != [0; 32] && baseline_config_hash != current_config_hash;
    if config_changed {
        let message = "Config changed since the baseline was created. Review policy changes and run 'batman baseline' after approval.";
        if strict_config_drift_enabled() {
            append_event(
                &config.file_integrity.db_path,
                "scan_aborted",
                &[
                    ("reason", "config_changed_since_baseline".to_string()),
                    (
                        "config_path",
                        context.local_settings.config_path.display().to_string(),
                    ),
                ],
            )?;
            return Err(crate::errors::BatmanError::Config(format!(
                "{message} Strict config drift checking is enabled."
            )));
        }
        output.line(Style::Warn, message)?;
    }
    if let Some(target) = target {
        config.file_integrity.scan_paths = vec![target.to_path_buf()];
    }
    let scan_config = config.file_integrity.clone();
    let mut spool = CurrentScanSpool::new(&config.file_integrity.db_path);
    let mut progress = ProgressMeter::new();

    let mut stats = scan_checksums(&scan_config, |file, stats| {
        spool.push_with_metadata(&file.path, file.checksum, file.metadata)?;
        if !context.global.quiet && stats.files % 100 == 0 {
            let (db_chunks, db_bytes) = if context.global.verbose {
                spool.progress_counters()
            } else {
                (0, 0)
            };
            let snapshot =
                progress.snapshot(stats.files, stats.processed_bytes, db_chunks, db_bytes);
            if context.global.progress {
                output.progress_count(
                    Style::Plain,
                    "Processed",
                    stats.directories,
                    stats.files,
                    snapshot,
                )?;
            } else {
                output.progress_path(
                    Style::Plain,
                    "Scanning",
                    stats.files,
                    snapshot,
                    &file.path,
                )?;
            }
        }
        Ok(())
    })?;

    let mut findings = IntegrityFindings::new(
        review::ReviewFindingSpool::create(&config)?,
        &config.file_integrity.db_path,
    )?;
    if config_changed {
        report_policy_change(
            &context.local_settings.config_path,
            baseline_config_hash,
            current_config_hash,
            &mut stats,
            &mut findings,
            output,
            emit_findings,
            !context.global.quiet && !emit_findings,
        )?;
    }
    compare_current_scan(
        &config.file_integrity,
        &mut reader,
        spool,
        &mut stats,
        &mut findings,
        output,
        emit_findings,
        !context.global.quiet && !emit_findings,
        target,
    )?;
    findings.summary.files = stats.files;
    findings.summary.bytes = stats.bytes;

    Ok((
        config,
        IntegrityReport {
            stats,
            summary: findings.summary,
            findings: Some(
                findings
                    .findings
                    .take()
                    .expect("scan findings spool exists")
                    .finish()?,
            ),
            details: findings.details,
            omitted_details: findings.omitted_details,
        },
    ))
}

fn strict_config_drift_enabled() -> bool {
    env_flag_enabled(STRICT_CONFIG_ENV) || env_flag_enabled(REQUIRE_SIGNED_BASELINE_ENV)
}

fn inspect_path(context: &CommandContext, output: &mut Output, path: &Path) -> BatmanResult<u8> {
    let config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    if !ensure_trusted_data_path(context, output, &config.file_integrity.db_path)? {
        return Ok(1);
    }
    let mut reader = BaselineReader::open_with_public_key(
        &config.file_integrity.db_path,
        config.file_integrity.baseline_public_key.as_deref(),
    )?;

    output.line(Style::Success, format!("Checking {}", path.display()))?;
    match reader.lookup(path)? {
        LookupResult::Found { record, .. } => {
            output.line(Style::Plain, "Checksum:")?;
            output.line(
                Style::Plain,
                format!("  Path To: {}", record.path.display()),
            )?;
            output.line(
                Style::Plain,
                format!("  Path Checksum: {}", format_digest(&record.checksum)),
            )?;
            output.line(
                Style::Plain,
                format!("  Path Key: {}", path_key(&record.path)),
            )?;
            output.line(
                Style::Plain,
                format!("  Path Size: {}", record.metadata.size),
            )?;
            output.line(
                Style::Plain,
                format!("  Modified Ns: {}", record.metadata.modified_ns),
            )?;
            output.line(Style::Plain, "  Marked: false")?;
        }
        LookupResult::Missing => {
            output.line(Style::Warn, "The path has not been baselined")?;
        }
    }

    if !path.exists() {
        output.line(Style::Warn, "The path does not exist on disk")?;
        return Ok(0);
    }
    if !path.is_file() {
        output.line(
            Style::Warn,
            "The path is a directory; run scan with the directory path to scan it",
        )?;
        return Ok(1);
    }

    let metadata = path.metadata().ok();
    let checksum = if config.file_integrity.is_metadata_only(path) {
        [0; 32]
    } else {
        content_checksum(path, config.file_integrity.scan_byte_limit)?
    };
    let current_metadata = metadata
        .as_ref()
        .map(|metadata| FileMetadata::from_path_metadata(path, metadata))
        .unwrap_or(FileMetadata {
            flags: 0,
            size: 0,
            permissions: 0,
            owner: 0,
            group: 0,
            modified_ns: 0,
            created_ns: 0,
            changed_ns: 0,
            acl_hash: [0; 32],
        });
    output.line(Style::Info, "File:")?;
    output.line(Style::Plain, format!("  Path To: {}", path.display()))?;
    output.line(Style::Plain, format!("  Path Hash: {}", path_key(path)))?;
    output.line(
        Style::Plain,
        format!("  Path Checksum: {}", format_digest(&checksum)),
    )?;
    output.line(
        Style::Plain,
        format!("  Path Size: {}", current_metadata.size),
    )?;

    if let LookupResult::Found { record, .. } = reader.lookup(path)? {
        let current = CurrentScanEntry {
            path_hash: record.path_hash,
            path: path.to_path_buf(),
            checksum,
            metadata: current_metadata,
        };
        let reasons = modification_reasons(&config.file_integrity, &record, &current);
        if reasons.is_empty() {
            output.line(Style::Success, "File integrity is intact!")?;
        } else {
            output.error(format!(
                "Warning: File integrity may have been compromised ({})",
                reasons.join(", ")
            ))?;
        }
    }
    Ok(0)
}

impl IntegrityFindings {
    fn new(findings: review::ReviewFindingSpool, db_path: &Path) -> BatmanResult<Self> {
        Ok(Self {
            count: 0,
            summary: review::ReviewSummary::default(),
            findings: Some(findings),
            moves: Some(MoveTracker::new(db_path)?),
            details: Vec::new(),
            omitted_details: 0,
        })
    }

    fn push_finding(&mut self, finding: &review::ReviewFinding) -> BatmanResult<()> {
        if let Some(spool) = &mut self.findings {
            spool.push(finding)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn details_only() -> Self {
        Self {
            count: 0,
            summary: review::ReviewSummary::default(),
            findings: None,
            moves: None,
            details: Vec::new(),
            omitted_details: 0,
        }
    }

    fn flush_moves(
        &mut self,
        stats: &mut crate::integrity::ScanStats,
        output: &mut Output,
        emit_findings: bool,
        emit_progress: bool,
    ) -> BatmanResult<()> {
        let Some(moves) = self.moves.take() else {
            return Ok(());
        };
        moves.flush(self, stats, output, emit_findings, emit_progress)
    }
}

impl MoveTracker {
    fn new(db_path: &Path) -> BatmanResult<Self> {
        let root = db_path.join(format!(
            ".move-candidates-{}-{}",
            std::process::id(),
            monotonic_nanos()
        ));
        let added_dir = root.join("added");
        let deleted_dir = root.join("deleted");
        fs::create_dir_all(&added_dir).map_err(|error| {
            crate::errors::BatmanError::io(format!("create {}", added_dir.display()), error)
        })?;
        fs::create_dir_all(&deleted_dir).map_err(|error| {
            crate::errors::BatmanError::io(format!("create {}", deleted_dir.display()), error)
        })?;
        Ok(Self {
            root,
            added: Some(CurrentScanSpool::new(&added_dir)),
            deleted: Some(CurrentScanSpool::new(&deleted_dir)),
        })
    }

    fn push_added(&mut self, current: &CurrentScanEntry) -> BatmanResult<bool> {
        let Some(key) = move_candidate_key(current.checksum, &current.metadata) else {
            return Ok(false);
        };
        self.added
            .as_mut()
            .expect("move tracker added spool is present")
            .push_with_sort_key(key, &current.path, current.checksum, current.metadata)?;
        Ok(true)
    }

    fn push_deleted(&mut self, baseline: &BaselineRecord) -> BatmanResult<bool> {
        let Some(key) = move_candidate_key(baseline.checksum, &baseline.metadata) else {
            return Ok(false);
        };
        self.deleted
            .as_mut()
            .expect("move tracker deleted spool is present")
            .push_with_sort_key(key, &baseline.path, baseline.checksum, baseline.metadata)?;
        Ok(true)
    }

    fn flush(
        mut self,
        findings: &mut IntegrityFindings,
        stats: &mut crate::integrity::ScanStats,
        output: &mut Output,
        emit_findings: bool,
        emit_progress: bool,
    ) -> BatmanResult<()> {
        let root = self.root.clone();
        let mut added_reader = self
            .added
            .take()
            .expect("move tracker added spool is present")
            .into_reader()?;
        let mut deleted_reader = self
            .deleted
            .take()
            .expect("move tracker deleted spool is present")
            .into_reader()?;
        let mut next_added = added_reader.next_entry()?;
        let mut next_deleted = deleted_reader.next_entry()?;

        while next_added.is_some() || next_deleted.is_some() {
            match (&next_added, &next_deleted) {
                (Some(added), Some(deleted)) if added.path_hash == deleted.path_hash => {
                    let added = next_added.take().expect("added is some");
                    let deleted = next_deleted.take().expect("deleted is some");
                    report_moved_now(
                        &deleted,
                        &added,
                        stats,
                        findings,
                        output,
                        emit_findings,
                        emit_progress,
                    )?;
                    next_added = added_reader.next_entry()?;
                    next_deleted = deleted_reader.next_entry()?;
                }
                (Some(added), Some(deleted)) if added.path_hash < deleted.path_hash => {
                    let added = next_added.take().expect("added is some");
                    report_new_now(
                        &added,
                        stats,
                        findings,
                        output,
                        emit_findings,
                        emit_progress,
                    )?;
                    next_added = added_reader.next_entry()?;
                }
                (Some(_), Some(_)) | (None, Some(_)) => {
                    let deleted = next_deleted.take().expect("deleted is some");
                    let deleted_baseline = BaselineRecord {
                        path_hash: path_hash_value(&deleted.path),
                        path: deleted.path,
                        checksum: deleted.checksum,
                        metadata: deleted.metadata,
                    };
                    report_deleted_now(
                        &deleted_baseline,
                        stats,
                        findings,
                        output,
                        emit_findings,
                        emit_progress,
                    )?;
                    next_deleted = deleted_reader.next_entry()?;
                }
                (Some(_), None) => {
                    let added = next_added.take().expect("added is some");
                    report_new_now(
                        &added,
                        stats,
                        findings,
                        output,
                        emit_findings,
                        emit_progress,
                    )?;
                    next_added = added_reader.next_entry()?;
                }
                (None, None) => break,
            }
        }
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}

impl Drop for MoveTracker {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn monotonic_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn move_candidate_key(
    checksum: crate::integrity::ContentDigest,
    metadata: &FileMetadata,
) -> Option<u128> {
    if checksum == [0; 32] {
        return None;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&checksum);
    hasher.update(&metadata.size.to_le_bytes());
    hasher.update(&(metadata.flags & META_KIND_MASK).to_le_bytes());
    let hash = hasher.finalize();
    let mut key = [0_u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    Some(u128::from_le_bytes(key))
}

fn compare_current_scan(
    config: &crate::config::FileIntegrityConfig,
    reader: &mut BaselineReader,
    spool: CurrentScanSpool,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
    target_scope: Option<&Path>,
) -> BatmanResult<()> {
    let current_count = spool.record_count();
    let mut current_reader = spool.into_reader()?;
    let mut current = current_reader.next_entry()?;
    let mut baseline = reader.next_record()?;
    let mut baseline_ordinal = 0_u64;
    let mut current_ordinal = 0_u64;
    let baseline_count = reader.record_count();
    let total_compare_records = baseline_count + current_count;
    let mut next_progress = if emit_progress {
        COMPARE_PROGRESS_INTERVAL.min(total_compare_records)
    } else {
        u64::MAX
    };

    while baseline.is_some() || current.is_some() {
        let baseline_hash = baseline.as_ref().map(|record| record.path_hash);
        let current_hash = current.as_ref().map(|entry| entry.path_hash);

        match (baseline_hash, current_hash) {
            (Some(left), Some(right)) if left < right => {
                let (next_baseline, processed) = report_deleted_group(
                    reader,
                    baseline,
                    left,
                    stats,
                    findings,
                    output,
                    emit_findings,
                    emit_progress,
                    target_scope,
                )?;
                baseline = next_baseline;
                baseline_ordinal += processed;
            }
            (Some(left), Some(right)) if right < left => {
                let (next_current, processed) = report_new_group(
                    &mut current_reader,
                    current,
                    right,
                    stats,
                    findings,
                    output,
                    emit_findings,
                    emit_progress,
                )?;
                current = next_current;
                current_ordinal += processed;
            }
            (Some(hash), Some(_)) => {
                let (next_baseline, next_current, baseline_processed, current_processed) =
                    compare_matching_hash(
                        config,
                        reader,
                        &mut current_reader,
                        baseline,
                        current,
                        hash,
                        stats,
                        findings,
                        output,
                        emit_findings,
                        emit_progress,
                        target_scope,
                    )?;
                baseline = next_baseline;
                current = next_current;
                baseline_ordinal += baseline_processed;
                current_ordinal += current_processed;
            }
            (Some(hash), None) => {
                let (next_baseline, processed) = report_deleted_group(
                    reader,
                    baseline,
                    hash,
                    stats,
                    findings,
                    output,
                    emit_findings,
                    emit_progress,
                    target_scope,
                )?;
                baseline = next_baseline;
                baseline_ordinal += processed;
            }
            (None, Some(hash)) => {
                let (next_current, processed) = report_new_group(
                    &mut current_reader,
                    current,
                    hash,
                    stats,
                    findings,
                    output,
                    emit_findings,
                    emit_progress,
                )?;
                current = next_current;
                current_ordinal += processed;
            }
            (None, None) => break,
        }
        let compared = baseline_ordinal + current_ordinal;
        if emit_progress && compared >= next_progress {
            show_compare_progress(findings, compared, total_compare_records, output)?;
            next_progress = compared.saturating_add(COMPARE_PROGRESS_INTERVAL);
        }
    }
    findings.flush_moves(stats, output, emit_findings, emit_progress)?;
    Ok(())
}

fn compare_matching_hash(
    config: &crate::config::FileIntegrityConfig,
    baseline_reader: &mut BaselineReader,
    current_reader: &mut CurrentScanReader,
    baseline: Option<BaselineRecord>,
    current: Option<CurrentScanEntry>,
    hash: u128,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
    target_scope: Option<&Path>,
) -> BatmanResult<(Option<BaselineRecord>, Option<CurrentScanEntry>, u64, u64)> {
    let baseline_first = baseline.expect("matching hash requires a baseline record");
    let current_first = current.expect("matching hash requires a current record");
    let baseline_next = baseline_reader.next_record()?;
    let current_next = current_reader.next_entry()?;

    let baseline_single = baseline_next
        .as_ref()
        .map(|record| record.path_hash != hash)
        .unwrap_or(true);
    let current_single = current_next
        .as_ref()
        .map(|entry| entry.path_hash != hash)
        .unwrap_or(true);

    if baseline_single && current_single {
        compare_single_match(
            config,
            &baseline_first,
            &current_first,
            stats,
            findings,
            output,
            emit_findings,
            emit_progress,
            target_scope,
        )?;
        return Ok((baseline_next, current_next, 1, 1));
    }

    let (baseline_group, baseline_next, baseline_processed) =
        read_baseline_group_after_first(baseline_reader, baseline_first, baseline_next, hash)?;
    let (current_group, current_next) =
        read_current_group_after_first(current_reader, current_first, current_next, hash)?;
    let current_processed = current_group.len() as u64;
    compare_groups(
        config,
        &baseline_group,
        &current_group,
        stats,
        findings,
        output,
        emit_findings,
        emit_progress,
        target_scope,
    )?;
    Ok((
        baseline_next,
        current_next,
        baseline_processed,
        current_processed,
    ))
}

fn compare_single_match(
    config: &crate::config::FileIntegrityConfig,
    baseline: &BaselineRecord,
    current: &CurrentScanEntry,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
    target_scope: Option<&Path>,
) -> BatmanResult<()> {
    if baseline.path == current.path {
        let reasons = modification_reasons(config, baseline, current);
        if !reasons.is_empty() {
            report_altered(
                baseline,
                current,
                reasons,
                stats,
                findings,
                output,
                emit_findings,
                emit_progress,
            )?;
        }
        return Ok(());
    }

    if target_scope
        .map(|target| baseline.path.starts_with(target))
        .unwrap_or(true)
    {
        report_deleted(
            baseline,
            stats,
            findings,
            output,
            emit_findings,
            emit_progress,
        )?;
    }
    report_new(
        current,
        stats,
        findings,
        output,
        emit_findings,
        emit_progress,
    )
}

fn read_baseline_group_after_first(
    reader: &mut BaselineReader,
    first: BaselineRecord,
    next: Option<BaselineRecord>,
    hash: u128,
) -> BatmanResult<(Vec<BaselineRecord>, Option<BaselineRecord>, u64)> {
    let mut group = vec![first];
    let mut next = next;
    while let Some(record) = next {
        if record.path_hash != hash {
            let processed = group.len() as u64;
            return Ok((group, Some(record), processed));
        }
        group.push(record);
        next = reader.next_record()?;
    }
    let processed = group.len() as u64;
    Ok((group, None, processed))
}

fn read_current_group_after_first(
    reader: &mut CurrentScanReader,
    first: CurrentScanEntry,
    current: Option<CurrentScanEntry>,
    hash: u128,
) -> BatmanResult<(Vec<CurrentScanEntry>, Option<CurrentScanEntry>)> {
    let mut group = vec![first];
    let mut next = current;
    while let Some(entry) = next {
        if entry.path_hash != hash {
            return Ok((group, Some(entry)));
        }
        group.push(entry);
        next = reader.next_entry()?;
    }
    Ok((group, None))
}

fn read_current_group(
    reader: &mut CurrentScanReader,
    current: Option<CurrentScanEntry>,
    hash: u128,
) -> BatmanResult<(Vec<CurrentScanEntry>, Option<CurrentScanEntry>)> {
    let mut group = Vec::new();
    let mut next = current;
    while let Some(entry) = next {
        if entry.path_hash != hash {
            return Ok((group, Some(entry)));
        }
        group.push(entry);
        next = reader.next_entry()?;
    }
    Ok((group, None))
}

fn compare_groups(
    config: &crate::config::FileIntegrityConfig,
    baseline_group: &[BaselineRecord],
    current_group: &[CurrentScanEntry],
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
    target_scope: Option<&Path>,
) -> BatmanResult<()> {
    let mut current_seen = vec![false; current_group.len()];
    for baseline in baseline_group {
        if let Some((index, current)) = current_group
            .iter()
            .enumerate()
            .find(|(_, current)| current.path == baseline.path)
        {
            current_seen[index] = true;
            let reasons = modification_reasons(config, baseline, current);
            if !reasons.is_empty() {
                report_altered(
                    baseline,
                    current,
                    reasons,
                    stats,
                    findings,
                    output,
                    emit_findings,
                    emit_progress,
                )?;
            }
        } else {
            if target_scope
                .map(|target| baseline.path.starts_with(target))
                .unwrap_or(true)
            {
                report_deleted(
                    baseline,
                    stats,
                    findings,
                    output,
                    emit_findings,
                    emit_progress,
                )?;
            }
        }
    }
    for (index, current) in current_group.iter().enumerate() {
        if !current_seen[index] {
            report_new(
                current,
                stats,
                findings,
                output,
                emit_findings,
                emit_progress,
            )?;
        }
    }
    Ok(())
}

fn report_deleted_group(
    reader: &mut BaselineReader,
    first: Option<BaselineRecord>,
    hash: u128,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
    target_scope: Option<&Path>,
) -> BatmanResult<(Option<BaselineRecord>, u64)> {
    let mut next = first;
    let mut processed = 0_u64;
    while let Some(record) = next {
        if record.path_hash != hash {
            return Ok((Some(record), processed));
        }
        if target_scope
            .map(|target| record.path.starts_with(target))
            .unwrap_or(true)
        {
            report_deleted(
                &record,
                stats,
                findings,
                output,
                emit_findings,
                emit_progress,
            )?;
        }
        processed += 1;
        next = reader.next_record()?;
    }
    Ok((None, processed))
}

fn report_new_group(
    reader: &mut CurrentScanReader,
    current: Option<CurrentScanEntry>,
    hash: u128,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<(Option<CurrentScanEntry>, u64)> {
    let (group, next) = read_current_group(reader, current, hash)?;
    let processed = group.len() as u64;
    for entry in group {
        report_new(
            &entry,
            stats,
            findings,
            output,
            emit_findings,
            emit_progress,
        )?;
    }
    Ok((next, processed))
}

fn report_altered(
    baseline: &BaselineRecord,
    current: &CurrentScanEntry,
    reasons: Vec<&'static str>,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    stats.failed += 1;
    findings.count += 1;
    findings.summary.modified += 1;
    let reason = reasons.join(", ");
    let finding = review::ReviewFinding::new_with_snapshots(
        review::review_finding_id(findings.count)?,
        review::ReviewFindingKind::Modified,
        current.path.display().to_string().into_boxed_str(),
        current.metadata.size,
        review_modified_ns(current.metadata.modified_ns),
        review::ReviewReason::from_names(&reasons),
        review::ReviewChange {
            before: Some(review::ReviewSnapshot::from_file(
                baseline.checksum,
                &baseline.metadata,
            )),
            after: Some(review::ReviewSnapshot::from_file(
                current.checksum,
                &current.metadata,
            )),
        },
    );
    findings.push_finding(&finding)?;
    if should_format_finding_detail(findings, emit_findings) {
        let message = finding_message("MODIFIED", &current.path, Some(&reason));
        push_detail(findings, message.clone());
        if emit_findings {
            output.line(Style::Modified, message)?;
        } else if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    } else {
        findings.omitted_details += 1;
        if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    }
    Ok(())
}

fn report_policy_change(
    config_path: &Path,
    baseline_config_hash: crate::integrity::ContentDigest,
    current_config_hash: crate::integrity::ContentDigest,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    let metadata = fs::symlink_metadata(config_path)
        .ok()
        .map(|metadata| FileMetadata::from_path_metadata(config_path, &metadata))
        .unwrap_or(FileMetadata {
            flags: 0,
            size: 0,
            permissions: 0,
            owner: 0,
            group: 0,
            modified_ns: 0,
            created_ns: 0,
            changed_ns: 0,
            acl_hash: [0; 32],
        });
    stats.failed += 1;
    findings.count += 1;
    findings.summary.modified += 1;
    let finding = review::ReviewFinding::new_with_snapshots(
        review::review_finding_id(findings.count)?,
        review::ReviewFindingKind::Modified,
        config_path.display().to_string().into_boxed_str(),
        metadata.size,
        review_modified_ns(metadata.modified_ns),
        review::ReviewReason::from_names(&["policy"]),
        review::ReviewChange {
            before: Some(review::ReviewSnapshot::checksum_only(baseline_config_hash)),
            after: Some(review::ReviewSnapshot::from_file(
                current_config_hash,
                &metadata,
            )),
        },
    );
    findings.push_finding(&finding)?;
    if should_format_finding_detail(findings, emit_findings) {
        let message = finding_message("MODIFIED", config_path, Some("policy"));
        push_detail(findings, message.clone());
        if emit_findings {
            output.line(Style::Modified, message)?;
        } else if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    } else {
        findings.omitted_details += 1;
        if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    }
    Ok(())
}

fn report_new(
    current: &CurrentScanEntry,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    if let Some(moves) = &mut findings.moves
        && moves.push_added(current)?
    {
        return Ok(());
    }
    report_new_now(
        current,
        stats,
        findings,
        output,
        emit_findings,
        emit_progress,
    )
}

fn report_new_now(
    current: &CurrentScanEntry,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    stats.failed += 1;
    findings.count += 1;
    findings.summary.added += 1;
    let finding = review::ReviewFinding::new_with_snapshots(
        review::review_finding_id(findings.count)?,
        review::ReviewFindingKind::Added,
        current.path.display().to_string().into_boxed_str(),
        current.metadata.size,
        review_modified_ns(current.metadata.modified_ns),
        review::ReviewReason::empty(),
        review::ReviewChange {
            before: None,
            after: Some(review::ReviewSnapshot::from_file(
                current.checksum,
                &current.metadata,
            )),
        },
    );
    findings.push_finding(&finding)?;
    if should_format_finding_detail(findings, emit_findings) {
        let message = finding_message("ADDED", &current.path, None);
        push_detail(findings, message.clone());
        if emit_findings {
            output.line(Style::Added, message)?;
        } else if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    } else {
        findings.omitted_details += 1;
        if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    }
    Ok(())
}

fn report_deleted(
    baseline: &BaselineRecord,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    if let Some(moves) = &mut findings.moves
        && moves.push_deleted(baseline)?
    {
        return Ok(());
    }
    report_deleted_now(
        baseline,
        stats,
        findings,
        output,
        emit_findings,
        emit_progress,
    )
}

fn report_deleted_now(
    baseline: &BaselineRecord,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    stats.failed += 1;
    findings.count += 1;
    findings.summary.deleted += 1;
    let finding = review::ReviewFinding::new_with_snapshots(
        review::review_finding_id(findings.count)?,
        review::ReviewFindingKind::Deleted,
        baseline.path.display().to_string().into_boxed_str(),
        baseline.metadata.size,
        review_modified_ns(baseline.metadata.modified_ns),
        review::ReviewReason::empty(),
        review::ReviewChange {
            before: Some(review::ReviewSnapshot::from_file(
                baseline.checksum,
                &baseline.metadata,
            )),
            after: None,
        },
    );
    findings.push_finding(&finding)?;
    if should_format_finding_detail(findings, emit_findings) {
        let message = finding_message("DELETED", &baseline.path, None);
        push_detail(findings, message.clone());
        if emit_findings {
            output.line(Style::Deleted, message)?;
        } else if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    } else {
        findings.omitted_details += 1;
        if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    }
    Ok(())
}

fn report_moved_now(
    deleted: &CurrentScanEntry,
    added: &CurrentScanEntry,
    stats: &mut crate::integrity::ScanStats,
    findings: &mut IntegrityFindings,
    output: &mut Output,
    emit_findings: bool,
    emit_progress: bool,
) -> BatmanResult<()> {
    stats.failed += 1;
    findings.count += 1;
    findings.summary.moved += 1;
    let finding = review::ReviewFinding::moved_with_snapshots(
        review::review_finding_id(findings.count)?,
        deleted.path.display().to_string().into_boxed_str(),
        added.path.display().to_string().into_boxed_str(),
        added.metadata.size,
        review_modified_ns(added.metadata.modified_ns),
        Some(review::ReviewSnapshot::from_file(
            deleted.checksum,
            &deleted.metadata,
        )),
        Some(review::ReviewSnapshot::from_file(
            added.checksum,
            &added.metadata,
        )),
    );
    findings.push_finding(&finding)?;
    if should_format_finding_detail(findings, emit_findings) {
        let message = format!(
            "MOVED    {} -> {}",
            deleted.path.display(),
            added.path.display()
        );
        push_detail(findings, message.clone());
        if emit_findings {
            output.line(Style::Modified, message)?;
        } else if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    } else {
        findings.omitted_details += 1;
        if emit_progress {
            show_finding_progress(findings, stats, output)?;
        }
    }
    Ok(())
}

fn finding_message(label: &str, path: &std::path::Path, reason: Option<&str>) -> String {
    match reason {
        Some(reason) if !reason.is_empty() => format!("{label:<8} {} ({reason})", path.display()),
        _ => format!("{label:<8} {}", path.display()),
    }
}

fn review_modified_ns(value: i128) -> i64 {
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn modification_reasons(
    config: &crate::config::FileIntegrityConfig,
    baseline: &BaselineRecord,
    current: &CurrentScanEntry,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if !config.is_metadata_only(&current.path) && current.checksum != baseline.checksum {
        reasons.push("checksum");
    }
    metadata_reasons(&baseline.metadata, &current.metadata, &mut reasons);
    reasons
}

fn metadata_reasons(
    baseline: &FileMetadata,
    current: &FileMetadata,
    reasons: &mut Vec<&'static str>,
) {
    if (baseline.flags & META_KIND_MASK) != (current.flags & META_KIND_MASK) {
        reasons.push("kind");
    }
    let directory_record =
        (baseline.flags & META_DIRECTORY != 0) && (current.flags & META_DIRECTORY != 0);
    if !directory_record && baseline.size != current.size {
        reasons.push("size");
    }
    if !directory_record && baseline.modified_ns != current.modified_ns {
        reasons.push("modified_time");
    }
    let common_flags = baseline.flags & current.flags;
    if common_flags & META_PERMISSIONS != 0 && baseline.permissions != current.permissions {
        reasons.push("permissions");
    }
    if common_flags & META_OWNER != 0 && baseline.owner != current.owner {
        reasons.push("owner");
    }
    if common_flags & META_GROUP != 0 && baseline.group != current.group {
        reasons.push("group");
    }
    if !directory_record
        && common_flags & META_CREATED != 0
        && baseline.created_ns != current.created_ns
    {
        reasons.push("created_time");
    }
    if !directory_record
        && common_flags & META_CHANGED != 0
        && baseline.changed_ns != current.changed_ns
    {
        reasons.push("metadata_change_time");
    }
    if common_flags & META_ACL != 0 && baseline.acl_hash != current.acl_hash {
        reasons.push("security_metadata");
    }
}

fn show_finding_progress(
    findings: &IntegrityFindings,
    stats: &crate::integrity::ScanStats,
    output: &mut Output,
) -> BatmanResult<()> {
    if findings.count != 1 && !findings.count.is_multiple_of(100) {
        return Ok(());
    }
    output.progress(
        Style::Plain,
        format!(
            "Review: issues={} modified={} added={} deleted={} moved={} scanned_files={} bytes={}",
            format_count(findings.count),
            format_count(findings.summary.modified),
            format_count(findings.summary.added),
            format_count(findings.summary.deleted),
            format_count(findings.summary.moved),
            format_count(stats.files),
            format_bytes(stats.bytes)
        ),
    )
}

fn show_compare_progress(
    findings: &IntegrityFindings,
    compared: u64,
    total: u64,
    output: &mut Output,
) -> BatmanResult<()> {
    output.progress(
        Style::Plain,
        format!(
            "Reviewing: records={}/{} issues={} modified={} added={} deleted={} moved={}",
            format_count(compared),
            format_count(total),
            format_count(findings.count),
            format_count(findings.summary.modified),
            format_count(findings.summary.added),
            format_count(findings.summary.deleted),
            format_count(findings.summary.moved),
        ),
    )
}

fn push_detail(findings: &mut IntegrityFindings, detail: String) {
    if findings.details.len() < MAX_EMAIL_DETAILS {
        findings.details.push(detail);
    } else {
        findings.omitted_details += 1;
    }
}

fn should_format_finding_detail(findings: &IntegrityFindings, emit_findings: bool) -> bool {
    emit_findings || findings.details.len() < MAX_EMAIL_DETAILS
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Instant;

    use crate::cli::GlobalOptions;
    use crate::config::FileIntegrityConfig;
    use crate::integrity::ScanStats;
    use crate::integrity::store::{
        BaselineReader, BaselineRecord, BaselineWriter, CurrentScanEntry, CurrentScanSpool,
        FileMetadata, META_ACL, META_DIRECTORY, META_OWNER, META_PERMISSIONS, path_hash_value,
    };
    use crate::output::Output;

    use super::{
        IntegrityFindings, MAX_EMAIL_DETAILS, compare_current_scan, metadata_reasons,
        modification_reasons, push_detail,
    };

    #[test]
    fn email_details_are_bounded() {
        let mut findings = IntegrityFindings::details_only();

        for index in 0..(MAX_EMAIL_DETAILS + 2) {
            push_detail(&mut findings, format!("finding {index}"));
        }

        assert_eq!(findings.details.len(), MAX_EMAIL_DETAILS);
        assert_eq!(findings.omitted_details, 2);
    }

    #[test]
    fn metadata_reasons_identify_specific_changes() {
        let mut baseline = FileMetadata {
            flags: META_PERMISSIONS | META_OWNER,
            size: 10,
            permissions: 0o100644,
            owner: 1000,
            group: 0,
            modified_ns: 1,
            created_ns: 0,
            changed_ns: 0,
            acl_hash: [0; 32],
        };
        let mut current = baseline;
        current.size = 12;
        current.permissions = 0o100600;
        current.owner = 0;
        current.modified_ns = 2;
        current.acl_hash = [1; 32];

        let mut reasons = Vec::new();
        metadata_reasons(&baseline, &current, &mut reasons);

        assert_eq!(
            reasons,
            vec!["size", "modified_time", "permissions", "owner"]
        );

        baseline.flags |= META_ACL;
        current.flags |= META_ACL;
        let mut acl_reasons = Vec::new();
        metadata_reasons(&baseline, &current, &mut acl_reasons);
        assert_eq!(
            acl_reasons,
            vec![
                "size",
                "modified_time",
                "permissions",
                "owner",
                "security_metadata"
            ]
        );

        baseline.flags = 0;
        current.flags = 0;
        let mut portable_reasons = Vec::new();
        metadata_reasons(&baseline, &current, &mut portable_reasons);
        assert_eq!(portable_reasons, vec!["size", "modified_time"]);
    }

    #[test]
    fn directory_metadata_reasons_ignore_volatile_size_and_times() {
        let baseline = FileMetadata {
            flags: META_DIRECTORY | META_PERMISSIONS | META_OWNER,
            size: 10,
            permissions: 0o40755,
            owner: 1000,
            group: 0,
            modified_ns: 1,
            created_ns: 1,
            changed_ns: 1,
            acl_hash: [0; 32],
        };
        let mut current = baseline;
        current.size = 12;
        current.modified_ns = 2;
        current.created_ns = 2;
        current.changed_ns = 2;

        let mut reasons = Vec::new();
        metadata_reasons(&baseline, &current, &mut reasons);
        assert!(reasons.is_empty());

        current.permissions = 0o40700;
        metadata_reasons(&baseline, &current, &mut reasons);
        assert_eq!(reasons, vec!["permissions"]);
    }

    #[test]
    fn metadata_only_paths_ignore_checksum_changes() {
        let path = PathBuf::from("/var/lib/app/data.db");
        let metadata = FileMetadata {
            flags: META_PERMISSIONS | META_OWNER,
            size: 10,
            permissions: 0o100600,
            owner: 1000,
            group: 0,
            modified_ns: 1,
            created_ns: 0,
            changed_ns: 0,
            acl_hash: [0; 32],
        };
        let baseline = BaselineRecord {
            path_hash: path_hash_value(&path),
            path: path.clone(),
            checksum: [1; 32],
            metadata,
        };
        let current = CurrentScanEntry {
            path_hash: path_hash_value(&path),
            path: path.clone(),
            checksum: [2; 32],
            metadata,
        };
        let config = FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 256 * 1024,
            baseline_public_key: None,
            db_path: PathBuf::from("/tmp/batman-db"),
            scan_paths: vec![PathBuf::from("/")],
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: vec![PathBuf::from("/var/lib/app")],
            registry_paths: Vec::new(),
            settings_dir: PathBuf::from("/tmp"),
        };

        assert!(modification_reasons(&config, &baseline, &current).is_empty());
    }

    #[test]
    #[ignore = "synthetic scan compare benchmark"]
    fn synthetic_identical_scan_compare_avoids_per_record_group_allocations() {
        let records = std::env::var("BATMAN_COMPARE_RECORDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1_000_000);
        let dir = unique_dir("batman-compare-identical");
        let current_dir = dir.join("current");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&current_dir).unwrap();
        let config = FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 256 * 1024,
            baseline_public_key: None,
            db_path: dir.clone(),
            scan_paths: vec![PathBuf::from("/")],
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: std::env::temp_dir(),
        };

        let mut writer = BaselineWriter::create(&dir, 0).unwrap();
        let mut spool = CurrentScanSpool::new(&current_dir);
        for index in 0..records {
            let path = synthetic_path(index);
            let metadata = synthetic_metadata(index);
            writer
                .add_file_with_metadata(&path, [1; 32], metadata)
                .unwrap();
            spool.push_with_metadata(&path, [1; 32], metadata).unwrap();
        }
        assert_eq!(writer.finish().unwrap(), records);

        let mut reader = BaselineReader::open(&dir).unwrap();
        let mut stats = ScanStats {
            files: records,
            bytes: records * 128,
            ..ScanStats::default()
        };
        let review_spool =
            crate::commands::review::ReviewFindingSpool::create(&crate::config::BatmanConfig {
                file_integrity: config.clone(),
                email: crate::config::EmailConfig {
                    send_on_fail: false,
                    send_on_success: false,
                    server_host: String::new(),
                    server_port: 25,
                    from_address: String::new(),
                    fail_to_address: String::new(),
                    success_to_address: String::new(),
                },
            })
            .unwrap();
        let mut findings = IntegrityFindings::new(review_spool, &dir).unwrap();
        let mut output = Output::new(&GlobalOptions {
            quiet: true,
            insecure: true,
            ..GlobalOptions::default()
        })
        .unwrap();

        let started = Instant::now();
        compare_current_scan(
            &config,
            &mut reader,
            spool,
            &mut stats,
            &mut findings,
            &mut output,
            false,
            false,
            None,
        )
        .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(findings.count, 0);
        eprintln!("records={records} compare_identical={elapsed:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "synthetic move-heavy scan compare benchmark"]
    fn synthetic_moved_scan_compare_stays_under_memory_budget() {
        let records = std::env::var("BATMAN_MOVE_RECORDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(100_000);
        let dir = unique_dir("batman-compare-moved");
        let current_dir = dir.join("current");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&current_dir).unwrap();
        let config = FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 256 * 1024,
            baseline_public_key: None,
            db_path: dir.clone(),
            scan_paths: vec![PathBuf::from("/")],
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: std::env::temp_dir(),
        };

        let mut writer = BaselineWriter::create(&dir, 0).unwrap();
        let mut spool = CurrentScanSpool::new(&current_dir);
        for index in 0..records {
            let metadata = synthetic_metadata(index);
            let checksum = synthetic_digest(index);
            writer
                .add_file_with_metadata(&synthetic_old_path(index), checksum, metadata)
                .unwrap();
            spool
                .push_with_metadata(&synthetic_new_path(index), checksum, metadata)
                .unwrap();
        }
        assert_eq!(writer.finish().unwrap(), records);

        let mut reader = BaselineReader::open(&dir).unwrap();
        let mut stats = ScanStats {
            files: records,
            bytes: records * 128,
            ..ScanStats::default()
        };
        let review_spool =
            crate::commands::review::ReviewFindingSpool::create(&crate::config::BatmanConfig {
                file_integrity: config.clone(),
                email: crate::config::EmailConfig {
                    send_on_fail: false,
                    send_on_success: false,
                    server_host: String::new(),
                    server_port: 25,
                    from_address: String::new(),
                    fail_to_address: String::new(),
                    success_to_address: String::new(),
                },
            })
            .unwrap();
        let mut findings = IntegrityFindings::new(review_spool, &dir).unwrap();
        let mut output = Output::new(&GlobalOptions {
            quiet: true,
            insecure: true,
            ..GlobalOptions::default()
        })
        .unwrap();

        let started = Instant::now();
        compare_current_scan(
            &config,
            &mut reader,
            spool,
            &mut stats,
            &mut findings,
            &mut output,
            false,
            false,
            None,
        )
        .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(findings.summary.moved, records);
        assert_eq!(findings.summary.added, 0);
        assert_eq!(findings.summary.deleted, 0);
        eprintln!("records={records} compare_moved={elapsed:?}");
        fs::remove_dir_all(dir).unwrap();
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

    fn synthetic_path(index: u64) -> PathBuf {
        PathBuf::from(format!(
            "/synthetic/tree/{:03}/{:03}/{:09}.dat",
            index % 1000,
            (index / 1000) % 1000,
            index
        ))
    }

    fn synthetic_old_path(index: u64) -> PathBuf {
        PathBuf::from(format!(
            "/synthetic/old/{:03}/{:03}/{:09}.dat",
            index % 1000,
            (index / 1000) % 1000,
            index
        ))
    }

    fn synthetic_new_path(index: u64) -> PathBuf {
        PathBuf::from(format!(
            "/synthetic/new/{:03}/{:03}/{:09}.dat",
            index % 1000,
            (index / 1000) % 1000,
            index
        ))
    }

    fn synthetic_digest(index: u64) -> crate::integrity::ContentDigest {
        let mut digest = [0_u8; 32];
        let value = index + 1;
        digest[..8].copy_from_slice(&value.to_le_bytes());
        digest[8..16].copy_from_slice(&value.rotate_left(17).to_le_bytes());
        digest
    }

    fn synthetic_metadata(index: u64) -> FileMetadata {
        FileMetadata {
            flags: META_PERMISSIONS | META_OWNER,
            size: 128,
            permissions: 0o100600,
            owner: 1000,
            group: 0,
            modified_ns: index as i128,
            created_ns: 0,
            changed_ns: 0,
            acl_hash: [0; 32],
        }
    }
}
