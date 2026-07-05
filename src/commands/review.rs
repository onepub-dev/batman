use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style as TuiStyle};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use serde::ser::{Error as SerializeError, SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

use crate::audit::append_event;
use crate::cli::ReviewOptions;
use crate::commands::{CommandContext, ensure_trusted_config, ensure_trusted_data_path};
use crate::config::{BatmanConfig, FileIntegrityConfig};
use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ContentDigest;
use crate::integrity::scan_checksums;
use crate::integrity::store::{
    BaselineReader, BaselineRecord, BaselineWriter, FileMetadata, META_ACL, META_CHANGED,
    META_CREATED, META_DIRECTORY, META_GROUP, META_OWNER, META_PERMISSIONS, META_SPECIAL,
    META_SYMLINK, path_hash_value,
};
use crate::output::{Output, Style, format_bytes, format_count};
use crate::security::{
    file_content_hash, hex_hash, secure_config_path, write_secure_config_atomic,
};

const FORMAT: &str = "batman-review-v1";
const FINDING_SPOOL_MAGIC: &[u8; 8] = b"BATRVF\0\x01";
const REVIEWS_DIR: &str = "reviews";
const LATEST_REVIEW_FILE: &str = "latest.review.yaml";
const UNDO_LIMIT: usize = 100;
const MOVE_PATH_SEPARATOR: char = '\u{1f}';

type ReviewIndex = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewSession {
    pub format: String,
    pub session_id: String,
    pub status: String,
    #[serde(default)]
    pub scanned_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub applied_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub applied_by: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apply_comment: String,
    pub host: String,
    pub config_path: String,
    pub baseline_db: String,
    pub summary: ReviewSummary,
    pub findings: Vec<ReviewFinding>,
    #[serde(default)]
    pub actions: Vec<ReviewAction>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReviewSummary {
    pub files: u64,
    pub bytes: u64,
    pub modified: u64,
    pub added: u64,
    pub deleted: u64,
    #[serde(default)]
    pub moved: u64,
}

#[derive(Clone, Debug)]
pub struct ReviewFinding {
    pub id: u32,
    pub path: Box<str>,
    pub size: u64,
    pub modified_ns: i64,
    flags: u32,
    change: Option<Box<ReviewChange>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReviewChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<ReviewSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<ReviewSnapshot>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReviewSnapshot {
    #[serde(default, skip_serializing_if = "box_str_is_empty")]
    pub checksum: Box<str>,
    #[serde(default, skip_serializing_if = "box_str_is_empty")]
    pub kind: Box<str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions_octal: Option<Box<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_changed_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_metadata_hash: Option<Box<str>>,
}

pub struct ReviewFindingSpool {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    count: u64,
    keep: bool,
}

pub struct ReviewFindingSpoolFile {
    path: PathBuf,
    count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewAction {
    pub id: u64,
    pub kind: ReviewActionKind,
    pub target: Box<str>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<u64>,
    #[serde(default, skip_serializing_if = "box_str_is_empty")]
    pub affected_ids: Box<str>,
    #[serde(default)]
    pub previous: Vec<PreviousState>,
    pub applied: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviousState {
    pub id: u64,
    pub state: ReviewState,
    pub action: ReviewActionKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingKind {
    Added,
    Modified,
    Deleted,
    Moved,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReviewReason(u16);

const REASON_CHECKSUM: u16 = 1 << 0;
const REASON_SIZE: u16 = 1 << 1;
const REASON_MODIFIED_TIME: u16 = 1 << 2;
const REASON_PERMISSIONS: u16 = 1 << 3;
const REASON_OWNER: u16 = 1 << 4;
const REASON_GROUP: u16 = 1 << 5;
const REASON_CREATED_TIME: u16 = 1 << 6;
const REASON_METADATA_CHANGE_TIME: u16 = 1 << 7;
const REASON_SECURITY_METADATA: u16 = 1 << 8;
const REASON_POLICY: u16 = 1 << 9;

const FINDING_KIND_SHIFT: u32 = 0;
const FINDING_STATE_SHIFT: u32 = 2;
const FINDING_ACTION_SHIFT: u32 = 4;
const FINDING_REASON_SHIFT: u32 = 8;
const FINDING_LOW_MASK: u32 = 0b11;
const FINDING_REASON_MASK: u32 = 0xffff << FINDING_REASON_SHIFT;

impl ReviewFindingKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::Moved => "moved",
        }
    }
}

impl std::fmt::Display for ReviewFindingKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    #[default]
    Unreviewed,
    Approved,
    Excluded,
    Flagged,
}

impl ReviewState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Approved => "approved",
            Self::Excluded => "excluded",
            Self::Flagged => "flagged",
        }
    }
}

impl std::fmt::Display for ReviewState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewActionKind {
    #[default]
    None,
    Approve,
    Exclude,
    Flag,
}

impl ReviewActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Approve => "approve",
            Self::Exclude => "exclude",
            Self::Flag => "flag",
        }
    }
}

impl std::fmt::Display for ReviewActionKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl ReviewFinding {
    pub fn new(
        id: u32,
        kind: ReviewFindingKind,
        path: Box<str>,
        size: u64,
        modified_ns: i64,
        reason: ReviewReason,
    ) -> Self {
        Self {
            id,
            path,
            size,
            modified_ns,
            flags: finding_flags(
                kind,
                ReviewState::Unreviewed,
                ReviewActionKind::None,
                reason,
            ),
            change: None,
        }
    }

    pub fn new_with_snapshots(
        id: u32,
        kind: ReviewFindingKind,
        path: Box<str>,
        size: u64,
        modified_ns: i64,
        reason: ReviewReason,
        change: ReviewChange,
    ) -> Self {
        let mut finding = Self::new(id, kind, path, size, modified_ns, reason);
        finding.set_change(change);
        finding
    }

    pub fn moved(
        id: u32,
        previous_path: Box<str>,
        path: Box<str>,
        size: u64,
        modified_ns: i64,
    ) -> Self {
        Self {
            id,
            path: encode_move_paths(&path, &previous_path).into_boxed_str(),
            size,
            modified_ns,
            flags: finding_flags(
                ReviewFindingKind::Moved,
                ReviewState::Unreviewed,
                ReviewActionKind::None,
                ReviewReason::empty(),
            ),
            change: None,
        }
    }

    pub fn moved_with_snapshots(
        id: u32,
        previous_path: Box<str>,
        path: Box<str>,
        size: u64,
        modified_ns: i64,
        before: Option<ReviewSnapshot>,
        after: Option<ReviewSnapshot>,
    ) -> Self {
        let mut finding = Self::moved(id, previous_path, path, size, modified_ns);
        finding.set_snapshots(before, after);
        finding
    }

    fn set_snapshots(&mut self, before: Option<ReviewSnapshot>, after: Option<ReviewSnapshot>) {
        self.set_change(ReviewChange { before, after });
    }

    fn set_change(&mut self, change: ReviewChange) {
        self.change = if change.before.is_none() && change.after.is_none() {
            None
        } else {
            Some(Box::new(change))
        };
    }

    fn before(&self) -> Option<&ReviewSnapshot> {
        self.change
            .as_deref()
            .and_then(|change| change.before.as_ref())
    }

    fn after(&self) -> Option<&ReviewSnapshot> {
        self.change
            .as_deref()
            .and_then(|change| change.after.as_ref())
    }

    fn path_text(&self) -> &str {
        self.path
            .split_once(MOVE_PATH_SEPARATOR)
            .map(|(path, _)| path)
            .unwrap_or(&self.path)
    }

    fn previous_path_text(&self) -> Option<&str> {
        self.path
            .split_once(MOVE_PATH_SEPARATOR)
            .map(|(_, previous_path)| previous_path)
    }

    fn kind(&self) -> ReviewFindingKind {
        finding_kind_from_bits((self.flags >> FINDING_KIND_SHIFT) & FINDING_LOW_MASK)
    }

    fn state(&self) -> ReviewState {
        review_state_from_bits((self.flags >> FINDING_STATE_SHIFT) & FINDING_LOW_MASK)
    }

    fn action(&self) -> ReviewActionKind {
        action_kind_from_bits((self.flags >> FINDING_ACTION_SHIFT) & FINDING_LOW_MASK)
    }

    fn reason(&self) -> ReviewReason {
        ReviewReason(((self.flags & FINDING_REASON_MASK) >> FINDING_REASON_SHIFT) as u16)
    }

    fn set_state_action(&mut self, state: ReviewState, action: ReviewActionKind) {
        self.flags &= !((FINDING_LOW_MASK << FINDING_STATE_SHIFT)
            | (FINDING_LOW_MASK << FINDING_ACTION_SHIFT));
        self.flags |= review_state_bits(state) << FINDING_STATE_SHIFT;
        self.flags |= action_kind_bits(action) << FINDING_ACTION_SHIFT;
    }
}

fn encode_move_paths(path: &str, previous_path: &str) -> String {
    format!("{path}{MOVE_PATH_SEPARATOR}{previous_path}")
}

impl Serialize for ReviewFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let reason = self.reason();
        let mut fields = if reason.is_empty() { 7 } else { 8 };
        if self.previous_path_text().is_some() {
            fields += 1;
        }
        if self.before().is_some() {
            fields += 1;
        }
        if self.after().is_some() {
            fields += 1;
        }
        let mut state = serializer.serialize_struct("ReviewFinding", fields)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("kind", &self.kind())?;
        state.serialize_field("path", self.path_text())?;
        if let Some(previous_path) = self.previous_path_text() {
            state.serialize_field("previous_path", previous_path)?;
        }
        if !reason.is_empty() {
            state.serialize_field("reason", &reason.text())?;
        }
        if let Some(before) = self.before() {
            state.serialize_field("before", before)?;
        }
        if let Some(after) = self.after() {
            state.serialize_field("after", after)?;
        }
        state.serialize_field("size", &self.size)?;
        state.serialize_field("modified_ns", &self.modified_ns)?;
        state.serialize_field("state", &self.state())?;
        state.serialize_field("action", &self.action())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ReviewFinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireFinding {
            id: u32,
            kind: ReviewFindingKind,
            path: Box<str>,
            #[serde(default)]
            previous_path: Option<Box<str>>,
            #[serde(default)]
            reason: Box<str>,
            #[serde(default)]
            before: Option<ReviewSnapshot>,
            #[serde(default)]
            after: Option<ReviewSnapshot>,
            size: u64,
            modified_ns: i64,
            #[serde(default)]
            state: ReviewState,
            #[serde(default)]
            action: ReviewActionKind,
            #[serde(default)]
            target: Option<Box<str>>,
        }

        let wire = WireFinding::deserialize(deserializer)?;
        let _ = wire.target;
        let reason = ReviewReason::parse(&wire.reason).map_err(serde::de::Error::custom)?;
        let path = if wire.kind == ReviewFindingKind::Moved {
            encode_move_paths(
                &wire.path,
                wire.previous_path.as_deref().ok_or_else(|| {
                    serde::de::Error::custom("moved finding missing previous_path")
                })?,
            )
            .into_boxed_str()
        } else {
            wire.path
        };
        let mut finding = Self::new(
            wire.id,
            wire.kind,
            path,
            wire.size,
            wire.modified_ns,
            reason,
        );
        finding.set_snapshots(wire.before, wire.after);
        finding.set_state_action(wire.state, wire.action);
        Ok(finding)
    }
}

impl ReviewSnapshot {
    pub fn from_file(checksum: ContentDigest, metadata: &FileMetadata) -> Self {
        Self {
            checksum: hex_hash(&checksum).into_boxed_str(),
            kind: snapshot_kind(metadata.flags).into(),
            size: Some(metadata.size),
            permissions_octal: (metadata.flags & META_PERMISSIONS != 0)
                .then(|| format!("{:o}", metadata.permissions).into_boxed_str()),
            owner: (metadata.flags & META_OWNER != 0).then_some(metadata.owner),
            group: (metadata.flags & META_GROUP != 0).then_some(metadata.group),
            modified_ns: Some(snapshot_ns(metadata.modified_ns)),
            created_ns: (metadata.flags & META_CREATED != 0)
                .then_some(snapshot_ns(metadata.created_ns)),
            metadata_changed_ns: (metadata.flags & META_CHANGED != 0)
                .then_some(snapshot_ns(metadata.changed_ns)),
            security_metadata_hash: (metadata.flags & META_ACL != 0)
                .then(|| hex_hash(&metadata.acl_hash).into_boxed_str()),
        }
    }

    pub fn checksum_only(checksum: ContentDigest) -> Self {
        Self {
            checksum: hex_hash(&checksum).into_boxed_str(),
            ..Self::default()
        }
    }
}

fn snapshot_kind(flags: u32) -> &'static str {
    if flags & META_DIRECTORY != 0 {
        "directory"
    } else if flags & META_SYMLINK != 0 {
        "symlink"
    } else if flags & META_SPECIAL != 0 {
        "special"
    } else {
        "file"
    }
}

fn snapshot_ns(value: i128) -> i64 {
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

impl ReviewReason {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn from_names(names: &[&str]) -> Self {
        let mut flags = 0_u16;
        for name in names {
            flags |= reason_flag(name).unwrap_or(0);
        }
        Self(flags)
    }

    fn parse(value: &str) -> BatmanResult<Self> {
        if value.is_empty() {
            return Ok(Self::empty());
        }
        let mut flags = 0_u16;
        for name in value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            flags |= reason_flag(name).ok_or_else(|| {
                BatmanError::Parse(format!("unknown review finding reason {name}"))
            })?;
        }
        Ok(Self(flags))
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn text(self) -> String {
        let mut names = Vec::new();
        for (flag, name) in [
            (REASON_CHECKSUM, "checksum"),
            (REASON_SIZE, "size"),
            (REASON_MODIFIED_TIME, "modified_time"),
            (REASON_PERMISSIONS, "permissions"),
            (REASON_OWNER, "owner"),
            (REASON_GROUP, "group"),
            (REASON_CREATED_TIME, "created_time"),
            (REASON_METADATA_CHANGE_TIME, "metadata_change_time"),
            (REASON_SECURITY_METADATA, "security_metadata"),
            (REASON_POLICY, "policy"),
        ] {
            if self.0 & flag != 0 {
                names.push(name);
            }
        }
        names.join(", ")
    }
}

fn reason_flag(name: &str) -> Option<u16> {
    match name {
        "checksum" => Some(REASON_CHECKSUM),
        "size" => Some(REASON_SIZE),
        "modified_time" => Some(REASON_MODIFIED_TIME),
        "permissions" => Some(REASON_PERMISSIONS),
        "owner" => Some(REASON_OWNER),
        "group" => Some(REASON_GROUP),
        "created_time" => Some(REASON_CREATED_TIME),
        "metadata_change_time" => Some(REASON_METADATA_CHANGE_TIME),
        "security_metadata" | "acl" => Some(REASON_SECURITY_METADATA),
        "policy" => Some(REASON_POLICY),
        _ => None,
    }
}

fn finding_flags(
    kind: ReviewFindingKind,
    state: ReviewState,
    action: ReviewActionKind,
    reason: ReviewReason,
) -> u32 {
    (finding_kind_bits(kind) << FINDING_KIND_SHIFT)
        | (review_state_bits(state) << FINDING_STATE_SHIFT)
        | (action_kind_bits(action) << FINDING_ACTION_SHIFT)
        | (u32::from(reason.0) << FINDING_REASON_SHIFT)
}

fn finding_kind_bits(kind: ReviewFindingKind) -> u32 {
    match kind {
        ReviewFindingKind::Added => 0,
        ReviewFindingKind::Modified => 1,
        ReviewFindingKind::Deleted => 2,
        ReviewFindingKind::Moved => 3,
    }
}

fn finding_kind_from_bits(value: u32) -> ReviewFindingKind {
    match value {
        1 => ReviewFindingKind::Modified,
        2 => ReviewFindingKind::Deleted,
        3 => ReviewFindingKind::Moved,
        _ => ReviewFindingKind::Added,
    }
}

fn review_state_bits(state: ReviewState) -> u32 {
    match state {
        ReviewState::Unreviewed => 0,
        ReviewState::Approved => 1,
        ReviewState::Excluded => 2,
        ReviewState::Flagged => 3,
    }
}

fn review_state_from_bits(value: u32) -> ReviewState {
    match value {
        1 => ReviewState::Approved,
        2 => ReviewState::Excluded,
        3 => ReviewState::Flagged,
        _ => ReviewState::Unreviewed,
    }
}

fn action_kind_bits(action: ReviewActionKind) -> u32 {
    match action {
        ReviewActionKind::None => 0,
        ReviewActionKind::Approve => 1,
        ReviewActionKind::Exclude => 2,
        ReviewActionKind::Flag => 3,
    }
}

fn action_kind_from_bits(value: u32) -> ReviewActionKind {
    match value {
        1 => ReviewActionKind::Approve,
        2 => ReviewActionKind::Exclude,
        3 => ReviewActionKind::Flag,
        _ => ReviewActionKind::None,
    }
}

impl ReviewAction {
    fn affected_ids(&self) -> Vec<u64> {
        let mut ids = self.affected.clone();
        ids.extend(decode_affected_ids(&self.affected_ids));
        ids
    }

    fn affected_count(&self) -> usize {
        self.affected.len() + count_encoded_affected_ids(&self.affected_ids)
    }
}

#[derive(Clone, Debug)]
struct ExclusionTarget {
    path: String,
    directory: bool,
    affects: usize,
}

struct ReviewApp {
    session: ReviewSession,
    path: PathBuf,
    visible: Vec<ReviewIndex>,
    unreviewed_sorted: Vec<ReviewIndex>,
    counts: StateCounts,
    targets: Vec<ExclusionTarget>,
    selected: usize,
    target_selected: usize,
    view: ReviewView,
    filter: String,
    entering_filter: bool,
    confirming_apply_on_exit: bool,
    apply_on_exit: bool,
    status: String,
}

#[derive(Default)]
struct StateCounts {
    unreviewed: u64,
    approved: u64,
    excluded: u64,
    flagged: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReviewView {
    Unreviewed,
    Flagged,
    Excluded,
    Approved,
    All,
}

struct TerminalGuard;

#[derive(Clone, Debug, Default)]
struct ReviewApplyMetadata {
    operator: String,
    comment: String,
    applied_at: String,
}

impl ReviewApplyMetadata {
    fn from_options(operator: &Option<String>, comment: &Option<String>) -> Self {
        Self {
            operator: operator
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(default_operator),
            comment: comment
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_default(),
            applied_at: scan_timestamp(),
        }
    }

    fn default_operator() -> Self {
        Self::from_options(&None, &None)
    }
}

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: ReviewOptions,
) -> BatmanResult<u8> {
    if options.list {
        return list_sessions(context, output);
    }

    if let Some(session) = &options.export {
        let source = resolve_session_path(context, Some(session))?;
        if let Some(message) = missing_review_message(context, &source) {
            output.error(message)?;
            return Ok(1);
        }
        let target = options.output.clone().ok_or_else(|| {
            BatmanError::Usage("--output is required when using --export".to_string())
        })?;
        fs::copy(&source, &target).map_err(|error| {
            BatmanError::io(
                format!("copy {} to {}", source.display(), target.display()),
                error,
            )
        })?;
        output.line(
            Style::Success,
            format!("Exported {} to {}", source.display(), target.display()),
        )?;
        return Ok(0);
    }

    if options.apply {
        if !ensure_trusted_config(context, output)? {
            return Ok(1);
        }
        let path = options
            .apply_path
            .clone()
            .unwrap_or_else(|| latest_review_path(context));
        if let Some(message) = missing_review_message(context, &path) {
            output.error(message)?;
            return Ok(1);
        }
        let metadata = ReviewApplyMetadata::from_options(&options.operator, &options.comment);
        return apply_review_file(context, output, &path, options.dry_run, &metadata);
    }

    let path = resolve_session_path(context, options.session.as_deref())?;
    if let Some(message) = missing_review_message(context, &path) {
        output.error(message)?;
        return Ok(1);
    }
    let session = read_session(&path)?;
    if session.findings.is_empty() {
        output.line(Style::Success, clean_review_message(&session))?;
        return Ok(0);
    }
    if !io::stdout().is_terminal() {
        output.error(format!(
            "Error: review TUI requires a terminal. Use 'batman review --apply {}' to apply reviewed actions.",
            path.display()
        ))?;
        return Ok(1);
    }
    run_tui(context, output, path, session)
}

pub fn write_review_from_findings(
    context: &CommandContext,
    config: &BatmanConfig,
    summary: &ReviewSummary,
    findings: Vec<ReviewFinding>,
) -> BatmanResult<PathBuf> {
    let session = ReviewSession::from_findings(context, config, summary, findings);
    let session_path = session_path_for_config(config, &session.session_id);
    write_session(&session_path, &session)?;
    let latest = latest_review_path_for_config(config);
    replace_file_from_existing(&session_path, &latest)?;
    Ok(session_path)
}

pub fn write_review_from_finding_spool(
    context: &CommandContext,
    config: &BatmanConfig,
    summary: &ReviewSummary,
    findings: ReviewFindingSpoolFile,
) -> BatmanResult<PathBuf> {
    let session_id = session_id();
    let session = ReviewSessionFromSpool {
        session_id: session_id.clone(),
        status: if findings.is_empty() {
            "clean"
        } else {
            "in_progress"
        },
        scanned_at: scan_timestamp(),
        host: host_name(),
        config_path: context.local_settings.config_path.display().to_string(),
        baseline_db: config.file_integrity.db_path.display().to_string(),
        summary: summary.clone(),
        findings: &findings,
    };
    let session_path = session_path_for_config(config, &session_id);
    write_serialized_session(&session_path, &session)?;
    let latest = latest_review_path_for_config(config);
    replace_file_from_existing(&session_path, &latest)?;
    Ok(session_path)
}

impl ReviewFindingSpool {
    pub fn create(config: &BatmanConfig) -> BatmanResult<Self> {
        let dir = reviews_dir_for_config(config);
        fs::create_dir_all(&dir)
            .map_err(|error| BatmanError::io(format!("create {}", dir.display()), error))?;
        let path = dir.join(format!(
            ".review-findings-{}-{}.tmp",
            std::process::id(),
            monotonic_nanos()
        ));
        let file = File::create(&path)
            .map_err(|error| BatmanError::io(format!("create {}", path.display()), error))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(FINDING_SPOOL_MAGIC)
            .map_err(|error| BatmanError::io("write review finding spool header", error))?;
        Ok(Self {
            path,
            writer: Some(writer),
            count: 0,
            keep: false,
        })
    }

    pub fn push(&mut self, finding: &ReviewFinding) -> BatmanResult<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| BatmanError::Store("review finding spool is closed".to_string()))?;
        write_review_finding(writer, finding)?;
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> BatmanResult<ReviewFindingSpoolFile> {
        if let Some(mut writer) = self.writer.take() {
            writer
                .flush()
                .map_err(|error| BatmanError::io("flush review finding spool", error))?;
        }
        self.keep = true;
        Ok(ReviewFindingSpoolFile {
            path: self.path.clone(),
            count: self.count,
        })
    }
}

impl Drop for ReviewFindingSpool {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl ReviewFindingSpoolFile {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Drop for ReviewFindingSpoolFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Serialize for ReviewFindingSpoolFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut reader = ReviewFindingSpoolReader::open(&self.path).map_err(S::Error::custom)?;
        let mut sequence = serialize_spool_sequence(serializer, self.count)?;
        while let Some(finding) = reader.next().map_err(S::Error::custom)? {
            sequence.serialize_element(&finding)?;
        }
        sequence.end()
    }
}

struct ReviewSessionFromSpool<'a> {
    session_id: String,
    status: &'static str,
    scanned_at: String,
    host: String,
    config_path: String,
    baseline_db: String,
    summary: ReviewSummary,
    findings: &'a ReviewFindingSpoolFile,
}

impl Serialize for ReviewSessionFromSpool<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ReviewSession", 10)?;
        state.serialize_field("format", FORMAT)?;
        state.serialize_field("session_id", &self.session_id)?;
        state.serialize_field("status", self.status)?;
        state.serialize_field("scanned_at", &self.scanned_at)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("config_path", &self.config_path)?;
        state.serialize_field("baseline_db", &self.baseline_db)?;
        state.serialize_field("summary", &self.summary)?;
        state.serialize_field("findings", self.findings)?;
        state.serialize_field("actions", &Vec::<ReviewAction>::new())?;
        state.end()
    }
}

fn serialize_spool_sequence<S>(
    serializer: S,
    count: u64,
) -> Result<<S as serde::Serializer>::SerializeSeq, <S as serde::Serializer>::Error>
where
    S: serde::Serializer,
{
    let len = usize::try_from(count).ok();
    serializer.serialize_seq(len)
}

struct ReviewFindingSpoolReader {
    reader: BufReader<File>,
}

impl ReviewFindingSpoolReader {
    fn open(path: &Path) -> BatmanResult<Self> {
        let file = File::open(path)
            .map_err(|error| BatmanError::io(format!("open {}", path.display()), error))?;
        let mut reader = BufReader::new(file);
        let mut magic = [0_u8; 8];
        reader
            .read_exact(&mut magic)
            .map_err(|error| BatmanError::io("read review finding spool header", error))?;
        if &magic != FINDING_SPOOL_MAGIC {
            return Err(BatmanError::Store(
                "invalid review finding spool".to_string(),
            ));
        }
        Ok(Self { reader })
    }

    fn next(&mut self) -> BatmanResult<Option<ReviewFinding>> {
        let Some(id) = read_optional_u32(&mut self.reader)? else {
            return Ok(None);
        };
        let kind = finding_kind_from_byte(read_u8(&mut self.reader)?)?;
        let path = read_boxed_str(&mut self.reader)?;
        let size = read_u64(&mut self.reader)?;
        let modified_ns = read_i64(&mut self.reader)?;
        let state = review_state_from_byte(read_u8(&mut self.reader)?)?;
        let action = action_kind_from_byte(read_u8(&mut self.reader)?)?;
        let reason = ReviewReason(read_u16(&mut self.reader)?);
        Ok(Some(ReviewFinding {
            id,
            path,
            size,
            modified_ns,
            flags: finding_flags(kind, state, action, reason),
            change: snapshot_change(
                read_optional_snapshot(&mut self.reader)?,
                read_optional_snapshot(&mut self.reader)?,
            ),
        }))
    }
}

impl ReviewSession {
    fn from_findings(
        context: &CommandContext,
        config: &BatmanConfig,
        summary: &ReviewSummary,
        findings: Vec<ReviewFinding>,
    ) -> Self {
        let session_id = session_id();

        Self {
            format: FORMAT.to_string(),
            session_id,
            status: if findings.is_empty() {
                "clean".to_string()
            } else {
                "in_progress".to_string()
            },
            scanned_at: scan_timestamp(),
            applied_at: String::new(),
            applied_by: String::new(),
            apply_comment: String::new(),
            host: host_name(),
            config_path: context.local_settings.config_path.display().to_string(),
            baseline_db: config.file_integrity.db_path.display().to_string(),
            summary: summary.clone(),
            findings,
            actions: Vec::new(),
        }
    }

    fn visible_indices(&self) -> Vec<ReviewIndex> {
        self.findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| finding.state() == ReviewState::Unreviewed)
            .map(|(index, _)| review_index(index))
            .collect()
    }

    fn next_action_id(&self) -> u64 {
        self.actions.last().map(|action| action.id + 1).unwrap_or(1)
    }

    fn push_action(&mut self, action: ReviewAction) {
        self.actions.push(action);
        if self.actions.len() > UNDO_LIMIT {
            let excess = self.actions.len() - UNDO_LIMIT;
            self.actions.drain(0..excess);
        }
    }

    fn mark_one(
        &mut self,
        index: usize,
        state: ReviewState,
        action_kind: ReviewActionKind,
        target: Box<str>,
    ) {
        let finding = &self.findings[index];
        let previous = PreviousState {
            id: u64::from(finding.id),
            state: finding.state(),
            action: finding.action(),
        };
        let id = self.next_action_id();
        let finding_id = u64::from(self.findings[index].id);
        self.findings[index].set_state_action(state, action_kind);
        self.push_action(ReviewAction {
            id,
            kind: action_kind,
            target,
            affected: vec![finding_id],
            affected_ids: empty_boxed_str(),
            previous: vec![previous],
            applied: false,
        });
    }

    fn exclude_target(&mut self, target: &str) -> usize {
        let id = self.next_action_id();
        let target_path = Path::new(target);
        let mut affected = Vec::new();
        for finding in &mut self.findings {
            if finding.state() != ReviewState::Unreviewed {
                continue;
            }
            let path = Path::new(finding.path_text());
            if path == target_path || path.starts_with(target_path) {
                affected.push(u64::from(finding.id));
                finding.set_state_action(ReviewState::Excluded, ReviewActionKind::Exclude);
            }
        }
        let count = affected.len();
        if count > 0 {
            self.push_action(ReviewAction {
                id,
                kind: ReviewActionKind::Exclude,
                target: target.to_string().into_boxed_str(),
                affected: Vec::new(),
                affected_ids: encode_affected_ids(&affected),
                previous: Vec::new(),
                applied: false,
            });
        }
        count
    }

    fn undo(&mut self) -> Option<usize> {
        let action = self.actions.pop()?;
        if action.previous.is_empty() && action.kind == ReviewActionKind::Exclude {
            let affected = action.affected_ids();
            let count = affected.len();
            for id in affected {
                if let Some(index) = self.finding_index_by_id(id) {
                    self.findings[index]
                        .set_state_action(ReviewState::Unreviewed, ReviewActionKind::None);
                }
            }
            return Some(count);
        }

        let count = action.previous.len();
        for previous in action.previous {
            if let Some(index) = self.finding_index_by_id(previous.id) {
                self.findings[index].set_state_action(previous.state, previous.action);
            }
        }
        Some(count)
    }

    fn finding_index_by_id(&self, id: u64) -> Option<usize> {
        let direct = usize::try_from(id.checked_sub(1)?).ok()?;
        if self
            .findings
            .get(direct)
            .is_some_and(|finding| u64::from(finding.id) == id)
        {
            return Some(direct);
        }
        self.findings
            .iter()
            .position(|finding| u64::from(finding.id) == id)
    }
}

fn list_sessions(context: &CommandContext, output: &mut Output) -> BatmanResult<u8> {
    let dir = reviews_dir(context);
    if !dir.exists() {
        output.line(Style::Warn, "No review sessions found.")?;
        return Ok(0);
    }
    let mut entries = fs::read_dir(&dir)
        .map_err(|error| BatmanError::io(format!("read {}", dir.display()), error))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        output.line(Style::Plain, path.display().to_string())?;
    }
    Ok(0)
}

fn apply_review_file(
    context: &CommandContext,
    output: &mut Output,
    path: &Path,
    dry_run: bool,
    metadata: &ReviewApplyMetadata,
) -> BatmanResult<u8> {
    let mut session = read_session(path)?;
    if session.findings.is_empty() {
        output.line(Style::Success, clean_review_message(&session))?;
        return Ok(0);
    }
    let exclusions = review_exclusions(&session);
    let approvals = review_approvals(&session);

    if dry_run {
        output.line(
            Style::Plain,
            format!(
                "Would apply {} exclusions and {} approvals from {}.",
                format_count(exclusions.len() as u64),
                format_count(approvals.len() as u64),
                path.display()
            ),
        )?;
        return Ok(0);
    }

    if !exclusions.is_empty() {
        update_exclusions(&context.local_settings.config_path, &exclusions)?;
    }
    if !approvals.is_empty() {
        apply_approvals(context, output, &approvals)?;
    }
    for action in &mut session.actions {
        action.applied = true;
    }
    session.status = "applied".to_string();
    session.applied_at = metadata.applied_at.clone();
    session.applied_by = metadata.operator.clone();
    session.apply_comment = metadata.comment.clone();
    write_session(path, &session)?;
    let config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    let mut audit_fields = vec![
        ("review_file", path.display().to_string()),
        ("exclusions", exclusions.len().to_string()),
        ("approvals", approvals.len().to_string()),
        ("approved_add", approvals.add.len().to_string()),
        ("approved_remove", approvals.remove.len().to_string()),
        (
            "config_hash_updated",
            approvals.update_config_hash.to_string(),
        ),
        ("operator", metadata.operator.clone()),
    ];
    if !metadata.comment.is_empty() {
        audit_fields.push(("comment", metadata.comment.clone()));
    }
    append_event(
        &config.file_integrity.db_path,
        "review_apply",
        &audit_fields,
    )?;

    output.line(
        Style::Success,
        format!(
            "Applied review. Exclusions: {} Approvals: {}. Run 'batman baseline' now.",
            format_count(exclusions.len() as u64),
            format_count(approvals.len() as u64)
        ),
    )?;
    Ok(0)
}

fn review_exclusions(session: &ReviewSession) -> Vec<String> {
    session
        .actions
        .iter()
        .filter(|action| action.kind == ReviewActionKind::Exclude)
        .map(|action| action.target.to_string())
        .filter(|target| !target.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Default)]
struct ApprovalPaths {
    add: BTreeSet<PathBuf>,
    remove: BTreeSet<PathBuf>,
    update_config_hash: bool,
}

impl ApprovalPaths {
    fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty() && !self.update_config_hash
    }

    fn len(&self) -> usize {
        self.add.len().max(self.remove.len()) + usize::from(self.update_config_hash)
    }
}

fn review_approvals(session: &ReviewSession) -> ApprovalPaths {
    let mut approvals = ApprovalPaths::default();
    for finding in session
        .findings
        .iter()
        .filter(|finding| finding.action() == ReviewActionKind::Approve)
        .filter(|finding| finding.state() == ReviewState::Approved)
    {
        if finding.reason().0 & REASON_POLICY != 0 {
            approvals.update_config_hash = true;
            continue;
        }
        approvals.add.insert(PathBuf::from(finding.path_text()));
        if let Some(previous_path) = finding.previous_path_text() {
            approvals.remove.insert(PathBuf::from(previous_path));
        } else {
            approvals.remove.insert(PathBuf::from(finding.path_text()));
        }
    }
    approvals
}

fn run_tui(
    context: &CommandContext,
    output: &mut Output,
    path: PathBuf,
    session: ReviewSession,
) -> BatmanResult<u8> {
    let mut app = ReviewApp::new(session, path);

    enable_raw_mode().map_err(|error| BatmanError::io("enable raw mode", error))?;
    let guard = TerminalGuard;
    execute!(io::stdout(), EnterAlternateScreen)
        .map_err(|error| BatmanError::io("enter alternate screen", error))?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|error| BatmanError::io("create review terminal", error))?;

    loop {
        terminal
            .draw(|frame| draw(frame, &app))
            .map_err(|error| BatmanError::io("draw review terminal", error))?;

        if let Event::Key(key) =
            event::read().map_err(|error| BatmanError::io("read terminal event", error))?
        {
            if should_show_working_status(&app, key) {
                app.status = "Excluding selected target; recalculating review list...".to_string();
                terminal
                    .draw(|frame| draw(frame, &app))
                    .map_err(|error| BatmanError::io("draw review terminal", error))?;
            }
            if handle_key(context, output, &mut app, key)? {
                break;
            }
        }
    }
    let apply_on_exit = app.apply_on_exit;
    let review_path = app.path.clone();
    drop(terminal);
    drop(guard);
    if apply_on_exit {
        let metadata = ReviewApplyMetadata::default_operator();
        return apply_review_file(context, output, &review_path, false, &metadata);
    }
    Ok(0)
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

impl ReviewApp {
    fn new(session: ReviewSession, path: PathBuf) -> Self {
        let mut app = Self {
            session,
            path,
            visible: Vec::new(),
            unreviewed_sorted: Vec::new(),
            counts: StateCounts::default(),
            targets: Vec::new(),
            selected: 0,
            target_selected: 0,
            view: ReviewView::Unreviewed,
            filter: String::new(),
            entering_filter: false,
            confirming_apply_on_exit: false,
            apply_on_exit: false,
            status: String::new(),
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.visible = self
            .session
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| self.matches_view(finding))
            .map(|(index, _)| review_index(index))
            .filter(|index| self.matches_filter(&self.session.findings[review_usize(*index)]))
            .collect();
        self.unreviewed_sorted = self.session.visible_indices();
        self.unreviewed_sorted.sort_by(|left, right| {
            self.session.findings[review_usize(*left)]
                .path
                .cmp(&self.session.findings[review_usize(*right)].path)
        });
        self.counts = StateCounts::default();
        for finding in &self.session.findings {
            match finding.state() {
                ReviewState::Approved => self.counts.approved += 1,
                ReviewState::Excluded => self.counts.excluded += 1,
                ReviewState::Flagged => self.counts.flagged += 1,
                ReviewState::Unreviewed => self.counts.unreviewed += 1,
            }
        }
        self.clamp_selection();
        self.refresh_targets();
    }

    fn refresh_targets(&mut self) {
        self.targets = self
            .visible
            .get(self.selected)
            .map(|index| self.exclusion_targets(&self.session.findings[review_usize(*index)]))
            .unwrap_or_default();
        self.clamp_target_selection();
    }

    fn clamp_selection(&mut self) {
        if self.visible.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.visible.len() {
            self.selected = self.visible.len() - 1;
        }
    }

    fn clamp_target_selection(&mut self) {
        if self.targets.is_empty() {
            self.target_selected = 0;
        } else if self.target_selected >= self.targets.len() {
            self.target_selected = self.targets.len() - 1;
        }
    }

    fn move_selection(&mut self, offset: isize) {
        if self.visible.is_empty() {
            self.selected = 0;
            self.target_selected = 0;
            return;
        }
        let last = self.visible.len() - 1;
        self.selected = if offset.is_negative() {
            self.selected.saturating_sub(offset.unsigned_abs())
        } else {
            self.selected.saturating_add(offset as usize).min(last)
        };
        self.target_selected = 0;
        self.refresh_targets();
    }

    fn move_target(&mut self, offset: isize) {
        if self.targets.is_empty() {
            self.target_selected = 0;
            return;
        }
        let last = self.targets.len() - 1;
        self.target_selected = if offset.is_negative() {
            self.target_selected.saturating_sub(offset.unsigned_abs())
        } else {
            self.target_selected
                .saturating_add(offset as usize)
                .min(last)
        };
    }

    fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.selected = 0;
        self.target_selected = 0;
        self.refresh();
    }

    fn matches_filter(&self, finding: &ReviewFinding) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let filter = self.filter.to_ascii_lowercase();
        finding.path_text().to_ascii_lowercase().contains(&filter)
            || finding.kind().as_str().contains(&filter)
            || finding.state().as_str().contains(&filter)
    }

    fn matches_view(&self, finding: &ReviewFinding) -> bool {
        match self.view {
            ReviewView::Unreviewed => finding.state() == ReviewState::Unreviewed,
            ReviewView::Flagged => finding.state() == ReviewState::Flagged,
            ReviewView::Excluded => finding.state() == ReviewState::Excluded,
            ReviewView::Approved => finding.state() == ReviewState::Approved,
            ReviewView::All => true,
        }
    }

    fn cycle_view(&mut self) {
        self.view = self.view.next();
        self.selected = 0;
        self.target_selected = 0;
        self.refresh();
    }

    fn selected_target(&self) -> Option<&ExclusionTarget> {
        self.targets.get(self.target_selected)
    }

    fn has_unapplied_actions(&self) -> bool {
        self.session.actions.iter().any(|action| !action.applied)
    }

    fn exclusion_targets(&self, finding: &ReviewFinding) -> Vec<ExclusionTarget> {
        let mut targets = Vec::new();
        targets.push(ExclusionTarget {
            path: finding.path_text().to_string(),
            directory: false,
            affects: 1,
        });

        let mut current = Path::new(finding.path_text()).parent();
        while let Some(parent) = current {
            if parent.as_os_str().is_empty() || parent == Path::new("/") {
                break;
            }
            targets.push(ExclusionTarget {
                path: parent.display().to_string(),
                directory: true,
                affects: self.count_unreviewed_under(parent),
            });
            current = parent.parent();
        }
        targets
    }

    fn count_unreviewed_under(&self, target: &Path) -> usize {
        let target = target.to_string_lossy();
        let exact = self.find_path_lower_bound(&target);
        let exact_count = self
            .unreviewed_sorted
            .get(exact)
            .filter(|index| self.session.findings[review_usize(**index)].path_text() == target)
            .map(|_| 1)
            .unwrap_or(0);

        let prefix = if target.ends_with('/') {
            target.to_string()
        } else {
            format!("{target}/")
        };
        let lower = self.find_path_lower_bound(&prefix);
        let upper = self.find_path_lower_bound(&format!("{prefix}\u{10ffff}"));
        exact_count + upper.saturating_sub(lower)
    }

    fn find_path_lower_bound(&self, value: &str) -> usize {
        self.unreviewed_sorted.partition_point(|index| {
            self.session.findings[review_usize(*index)].path_text() < value
        })
    }
}

fn empty_boxed_str() -> Box<str> {
    String::new().into_boxed_str()
}

fn box_str_is_empty(value: &str) -> bool {
    value.is_empty()
}

fn encode_affected_ids(ids: &[u64]) -> Box<str> {
    if ids.is_empty() {
        return empty_boxed_str();
    }
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();

    let mut bytes = Vec::with_capacity(ids.len());
    let mut previous = 0_u64;
    for id in ids {
        write_varint(id - previous, &mut bytes);
        previous = id;
    }
    hex_encode(&bytes).into_boxed_str()
}

fn decode_affected_ids(encoded: &str) -> Vec<u64> {
    let bytes = match hex_decode(encoded) {
        Some(bytes) => bytes,
        None => return Vec::new(),
    };
    let mut ids = Vec::new();
    let mut index = 0;
    let mut previous = 0_u64;
    while index < bytes.len() {
        let Some(delta) = read_varint(&bytes, &mut index) else {
            return Vec::new();
        };
        previous = previous.saturating_add(delta);
        ids.push(previous);
    }
    ids
}

fn count_encoded_affected_ids(encoded: &str) -> usize {
    if encoded.is_empty() {
        0
    } else {
        decode_affected_ids(encoded).len()
    }
}

fn write_varint(mut value: u64, bytes: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_varint(bytes: &[u8], index: &mut usize) -> Option<u64> {
    let mut shift = 0;
    let mut value = 0_u64;
    loop {
        let byte = *bytes.get(*index)?;
        *index += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn review_index(index: usize) -> ReviewIndex {
    ReviewIndex::try_from(index).expect("review sessions larger than 4B findings are unsupported")
}

pub fn review_finding_id(id: u64) -> BatmanResult<u32> {
    u32::try_from(id).map_err(|_| {
        BatmanError::Parse("review sessions larger than 4B findings are unsupported".to_string())
    })
}

fn review_usize(index: ReviewIndex) -> usize {
    index as usize
}

impl ReviewView {
    fn label(self) -> &'static str {
        match self {
            ReviewView::Unreviewed => "unreviewed",
            ReviewView::Flagged => "flagged",
            ReviewView::Excluded => "excluded",
            ReviewView::Approved => "approved",
            ReviewView::All => "all",
        }
    }

    fn next(self) -> Self {
        match self {
            ReviewView::Unreviewed => ReviewView::Flagged,
            ReviewView::Flagged => ReviewView::Excluded,
            ReviewView::Excluded => ReviewView::Approved,
            ReviewView::Approved => ReviewView::All,
            ReviewView::All => ReviewView::Unreviewed,
        }
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &ReviewApp) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(5),
        ])
        .split(area);

    draw_header(frame, app, chunks[0]);
    draw_counts(frame, app, chunks[1]);
    draw_body(frame, app, chunks[2]);
    frame.render_widget(
        Paragraph::new(command_lines(app))
            .block(Block::default().borders(Borders::ALL).title("Commands")),
        chunks[3],
    );
}

fn command_lines(app: &ReviewApp) -> Vec<Line<'static>> {
    if app.confirming_apply_on_exit {
        return vec![
            Line::from("Apply reviewed actions before exit?"),
            Line::from("y apply review | n exit without applying | Esc continue reviewing"),
            Line::from(app.status.clone()),
            Line::from("After applying, run batman baseline."),
        ];
    }
    if app.entering_filter {
        return vec![
            Line::from(format!("Filter: {}_", app.filter)),
            Line::from("Enter finish | Esc cancel | Backspace delete"),
            Line::from(app.status.clone()),
        ];
    }
    vec![
        Line::from("q quit | s save | A apply | v view | / filter | Esc clear | Up/Down/PgUp/PgDn"),
        Line::from(
            "Left broader | Right narrower | 1-9 select | x exclude selected target | a approve | f flag | u undo",
        ),
        Line::from(app.status.clone()),
    ]
}

fn draw_header(frame: &mut ratatui::Frame<'_>, app: &ReviewApp, area: Rect) {
    let text = vec![
        Line::from(vec![
            Span::styled(
                "Session: ",
                TuiStyle::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(app.session.session_id.clone()),
            Span::raw("   Status: "),
            Span::raw(app.session.status.clone()),
        ]),
        Line::from(vec![
            Span::raw("Scan: "),
            Span::raw(format_count(app.session.summary.files)),
            Span::raw(" files, "),
            Span::raw(format_bytes(app.session.summary.bytes)),
            Span::raw("   Review: "),
            Span::raw(app.path.display().to_string()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Batman Review"),
        ),
        area,
    );
}

fn draw_counts(frame: &mut ratatui::Frame<'_>, app: &ReviewApp, area: Rect) {
    let visible = app.visible.len() as u64;
    let text = vec![
        Line::from(format!(
            "States  Unreviewed {}   Approved {}   Excluded {}   Flagged {}",
            format_count(app.counts.unreviewed),
            format_count(app.counts.approved),
            format_count(app.counts.excluded),
            format_count(app.counts.flagged),
        )),
        Line::from(format!(
            "Kinds   Modified {}   Added {}   Deleted {}   Moved {}   View {}   Visible {}",
            format_count(app.session.summary.modified),
            format_count(app.session.summary.added),
            format_count(app.session.summary.deleted),
            format_count(app.session.summary.moved),
            app.view.label(),
            format_count(visible),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_body(frame: &mut ratatui::Frame<'_>, app: &ReviewApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);
    draw_findings(frame, app, chunks[0]);
    draw_selected(frame, app, chunks[1]);
}

fn draw_findings(frame: &mut ratatui::Frame<'_>, app: &ReviewApp, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let start = if height == 0 {
        0
    } else {
        app.selected.saturating_sub(height / 2)
    };
    let path_width = area.width.saturating_sub(14) as usize;
    let items = app
        .visible
        .iter()
        .skip(start)
        .take(height)
        .enumerate()
        .map(|(row, index)| {
            let finding = &app.session.findings[review_usize(*index)];
            let marker = if app.selected == start + row {
                "> "
            } else {
                "  "
            };
            let kind = finding.kind();
            let style = match kind {
                ReviewFindingKind::Added => TuiStyle::default().fg(Color::Cyan),
                ReviewFindingKind::Modified => TuiStyle::default().fg(Color::Magenta),
                ReviewFindingKind::Deleted => TuiStyle::default().fg(Color::Red),
                ReviewFindingKind::Moved => TuiStyle::default().fg(Color::Green),
            };
            ListItem::new(format!(
                "{marker}{:<8} {}",
                kind.as_str().to_uppercase(),
                clip_middle(finding.path_text(), path_width)
            ))
            .style(style)
        })
        .collect::<Vec<_>>();
    let title = if app.filter.is_empty() {
        format!("Findings {}", app.view.label())
    } else {
        format!("Findings {} filter '{}'", app.view.label(), app.filter)
    };
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_selected(frame: &mut ratatui::Frame<'_>, app: &ReviewApp, area: Rect) {
    let Some(index) = app.visible.get(app.selected).copied() else {
        frame.render_widget(
            Paragraph::new("No unreviewed findings.").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Selected Finding"),
            ),
            area,
        );
        return;
    };
    let index = review_usize(index);
    let finding = &app.session.findings[index];
    let kind = finding.kind();
    let text_width = area.width.saturating_sub(4) as usize;
    let mut lines = vec![
        Line::from(format!("Kind: {}", kind.as_str().to_uppercase())),
        Line::from(format!(
            "Path: {}",
            clip_middle(finding.path_text(), text_width.saturating_sub(6))
        )),
        Line::from(format!("Size: {}", format_bytes(finding.size))),
        Line::from(format!("Reason: {}", review_reason(finding))),
        Line::from(format!("State: {}", finding.state())),
        Line::from(""),
        Line::from("Exclusion Targets"),
    ];
    if let Some(previous_path) = finding.previous_path_text() {
        lines.insert(
            2,
            Line::from(format!(
                "From: {}",
                clip_middle(previous_path, text_width.saturating_sub(6))
            )),
        );
    }
    let target_rows = area.height.saturating_sub(16).clamp(1, 9) as usize;
    let target_start = app.target_selected.saturating_sub(target_rows / 2);
    for (row, target) in app
        .targets
        .iter()
        .skip(target_start)
        .take(target_rows)
        .enumerate()
    {
        let index = target_start + row;
        let label = if target.directory {
            "directory"
        } else {
            "file"
        };
        if index == app.target_selected {
            lines.push(Line::from(vec![
                Span::styled(
                    " SELECTED ",
                    TuiStyle::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("[{}] {:<9} ", index + 1, label)),
                Span::raw(clip_middle(&target.path, text_width.saturating_sub(39))),
                Span::raw(format!(" affects {}", format_count(target.affects as u64))),
            ]));
        } else {
            lines.push(Line::from(format!(
                "          [{}] {:<9} {} affects {}",
                index + 1,
                label,
                clip_middle(&target.path, text_width.saturating_sub(39)),
                format_count(target.affects as u64)
            )));
        }
    }
    lines.push(Line::from("Recent Actions"));
    for action in app.session.actions.iter().rev().take(4) {
        lines.push(Line::from(format!(
            "  #{} {} {} affected {}",
            action.id,
            action.kind,
            clip_middle(&action.target, text_width.saturating_sub(24)),
            format_count(action.affected_count() as u64)
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selected Finding"),
        ),
        area,
    );
}

fn clip_middle(value: &str, max_chars: usize) -> String {
    let len = value.chars().count();
    if max_chars == 0 || len <= max_chars {
        return value.to_string();
    }
    if max_chars <= 1 {
        return "…".to_string();
    }
    let keep = max_chars - 1;
    let left_len = keep / 2;
    let right_len = keep - left_len;
    let left = value.chars().take(left_len).collect::<String>();
    let right = value
        .chars()
        .rev()
        .take(right_len)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{left}…{right}")
}

fn review_reason(finding: &ReviewFinding) -> Cow<'static, str> {
    match finding.kind() {
        ReviewFindingKind::Added => Cow::Borrowed("new file"),
        ReviewFindingKind::Deleted => Cow::Borrowed("deleted file"),
        ReviewFindingKind::Moved => Cow::Borrowed("moved or renamed file"),
        ReviewFindingKind::Modified if finding.reason().is_empty() => {
            Cow::Borrowed("metadata or content changed")
        }
        ReviewFindingKind::Modified => Cow::Owned(finding.reason().text()),
    }
}

fn handle_key(
    context: &CommandContext,
    output: &mut Output,
    app: &mut ReviewApp,
    key: KeyEvent,
) -> BatmanResult<bool> {
    match key.code {
        _ if app.confirming_apply_on_exit => {
            return handle_apply_confirmation(app, key);
        }
        _ if app.entering_filter => {
            handle_filter_key(app, key);
        }
        KeyCode::Char('q') => {
            if app.has_unapplied_actions() {
                app.confirming_apply_on_exit = true;
                app.status = "Unapplied review actions exist.".to_string();
            } else {
                return Ok(true);
            }
        }
        KeyCode::Down | KeyCode::Enter => {
            app.move_selection(1);
        }
        KeyCode::Up => {
            app.move_selection(-1);
        }
        KeyCode::PageDown => {
            app.move_selection(25);
        }
        KeyCode::PageUp => {
            app.move_selection(-25);
        }
        KeyCode::Left => {
            app.move_target(1);
        }
        KeyCode::Right => {
            app.move_target(-1);
        }
        KeyCode::Char('/') => {
            app.entering_filter = true;
            app.status.clear();
        }
        KeyCode::Esc => {
            if !app.filter.is_empty() {
                app.set_filter(String::new());
                app.status = "Cleared filter".to_string();
            }
        }
        KeyCode::Char('v') => {
            app.cycle_view();
            app.status = format!("View: {}", app.view.label());
        }
        KeyCode::Char('s') => {
            write_session(&app.path, &app.session)?;
            app.status = format!("Saved {}", app.path.display());
        }
        KeyCode::Char('u') => {
            app.status = match app.session.undo() {
                Some(count) => format!("Undid action affecting {}", format_count(count as u64)),
                None => "Nothing to undo".to_string(),
            };
            app.refresh();
        }
        KeyCode::Char('a') => {
            if let Some(index) = app.visible.get(app.selected).copied() {
                let index = review_usize(index);
                let target = app.session.findings[index].path.clone();
                app.session.mark_one(
                    index,
                    ReviewState::Approved,
                    ReviewActionKind::Approve,
                    target,
                );
                app.status = "Approved finding".to_string();
                app.refresh();
            }
        }
        KeyCode::Char('f') => {
            if let Some(index) = app.visible.get(app.selected).copied() {
                let index = review_usize(index);
                let target = app.session.findings[index].path.clone();
                app.session
                    .mark_one(index, ReviewState::Flagged, ReviewActionKind::Flag, target);
                app.status = "Flagged finding".to_string();
                app.refresh();
            }
        }
        KeyCode::Char(ch @ '1'..='9') => {
            let target_index = ch as usize - '1' as usize;
            if target_index < app.targets.len() {
                app.target_selected = target_index;
            }
        }
        KeyCode::Char('x') => {
            if let Some(target) = app.selected_target().cloned() {
                let count = app.session.exclude_target(&target.path);
                app.status = format!(
                    "Excluded {} affecting {} findings",
                    target.path,
                    format_count(count as u64)
                );
                app.refresh();
            }
        }
        KeyCode::Char('A') => {
            write_session(&app.path, &app.session)?;
            let metadata = ReviewApplyMetadata::default_operator();
            let _ = apply_review_file(context, output, &app.path, false, &metadata)?;
            app.status = "Applied reviewed actions. Run batman baseline.".to_string();
        }
        _ => {}
    }
    Ok(false)
}

fn handle_apply_confirmation(app: &mut ReviewApp, key: KeyEvent) -> BatmanResult<bool> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            write_session(&app.path, &app.session)?;
            app.apply_on_exit = true;
            Ok(true)
        }
        KeyCode::Char('n') | KeyCode::Char('N') => Ok(true),
        KeyCode::Esc => {
            app.confirming_apply_on_exit = false;
            app.status = "Continuing review.".to_string();
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn should_show_working_status(app: &ReviewApp, key: KeyEvent) -> bool {
    if app.entering_filter || key.code != KeyCode::Char('x') {
        return false;
    }
    app.selected_target()
        .map(|target| target.affects >= 10_000)
        .unwrap_or(false)
}

fn handle_filter_key(app: &mut ReviewApp, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            app.entering_filter = false;
            app.status = if app.filter.is_empty() {
                "Filter cleared".to_string()
            } else {
                format!("Filter applied: {}", app.filter)
            };
        }
        KeyCode::Esc => {
            app.entering_filter = false;
            app.status = "Filter input cancelled".to_string();
        }
        KeyCode::Backspace => {
            let mut filter = app.filter.clone();
            filter.pop();
            app.set_filter(filter);
        }
        KeyCode::Char(ch) => {
            let mut filter = app.filter.clone();
            filter.push(ch);
            app.set_filter(filter);
        }
        _ => {}
    }
}

fn apply_approvals(
    context: &CommandContext,
    output: &mut Output,
    approved: &ApprovalPaths,
) -> BatmanResult<()> {
    let config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    if !ensure_trusted_data_path(context, output, &config.file_integrity.db_path)? {
        return Ok(());
    }
    let mut reader = BaselineReader::open_with_public_key(
        &config.file_integrity.db_path,
        config.file_integrity.baseline_public_key.as_deref(),
    )?;
    if reader.scan_byte_limit() != config.file_integrity.scan_byte_limit {
        return Err(BatmanError::Store(format!(
            "refusing approvals: baseline scan_byte_limit is {} but config is {}",
            reader.scan_byte_limit(),
            config.file_integrity.scan_byte_limit
        )));
    }

    let accepted_records = scan_approved_paths(&config.file_integrity, &approved.add)?;
    let config_hash = if approved.update_config_hash {
        file_content_hash(&context.local_settings.config_path)?
    } else {
        reader.config_hash()
    };
    let signing_key = super::signing::baseline_signing_key_for_write(
        config.file_integrity.baseline_public_key.as_deref(),
        output,
    )?;
    let mut writer = BaselineWriter::create_with_config_hash_and_signing_key(
        &config.file_integrity.db_path,
        config.file_integrity.scan_byte_limit,
        config_hash,
        signing_key,
    )?;
    while let Some(record) = reader.next_record()? {
        if path_set_contains(&approved.remove, &record.path) {
            continue;
        }
        writer.add_file_with_metadata(&record.path, record.checksum, record.metadata)?;
    }
    for record in accepted_records {
        writer.add_file_with_metadata(&record.path, record.checksum, record.metadata)?;
    }
    let total = writer.finish()?;
    output.line(
        Style::Success,
        format!(
            "Approved baseline records updated. Records: {}",
            format_count(total)
        ),
    )?;
    Ok(())
}

fn scan_approved_paths(
    config: &FileIntegrityConfig,
    approved: &BTreeSet<PathBuf>,
) -> BatmanResult<Vec<BaselineRecord>> {
    let mut paths = approved
        .iter()
        .filter(|path| path.exists())
        .cloned()
        .collect::<Vec<_>>();
    paths.sort();
    let mut scan_config = config.clone();
    scan_config.scan_paths = paths;
    let mut records = Vec::new();
    scan_checksums(&scan_config, |file, _stats| {
        if path_set_contains(approved, &file.path) {
            records.push(BaselineRecord {
                path_hash: path_hash_value(&file.path),
                path: file.path.clone(),
                checksum: file.checksum,
                metadata: file.metadata,
            });
        }
        Ok(())
    })?;
    Ok(records)
}

fn update_exclusions(config_path: &Path, additions: &[String]) -> BatmanResult<()> {
    let content = fs::read_to_string(config_path)
        .map_err(|error| BatmanError::io(format!("read {}", config_path.display()), error))?;
    let mut docs = YamlLoader::load_from_str(&content)
        .map_err(|error| BatmanError::Parse(error.to_string()))?;
    let mut doc = docs
        .drain(..)
        .next()
        .unwrap_or_else(|| Yaml::Hash(Hash::new()));

    let root = ensure_hash(&mut doc, "root YAML document")?;
    let file_integrity = ensure_child_hash(root, "file_integrity")?;
    let exclusions_key = Yaml::String("exclusions".to_string());
    if !file_integrity.contains_key(&exclusions_key) {
        file_integrity.insert(exclusions_key.clone(), Yaml::Array(Vec::new()));
    }
    let exclusions = file_integrity
        .get_mut(&exclusions_key)
        .expect("exclusions key was inserted");
    let Yaml::Array(items) = exclusions else {
        return Err(BatmanError::Config(
            "file_integrity.exclusions must be a YAML list".to_string(),
        ));
    };

    let mut existing = items
        .iter()
        .filter_map(|item| item.as_str())
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    for addition in additions {
        if existing.insert(addition.clone()) {
            items.push(Yaml::String(addition.clone()));
        }
    }

    let mut output = String::new();
    {
        let mut emitter = YamlEmitter::new(&mut output);
        emitter
            .dump(&doc)
            .map_err(|error| BatmanError::Parse(error.to_string()))?;
    }
    write_secure_config_atomic(config_path, &format!("{output}\n"))?;
    secure_config_path(config_path)
}

fn ensure_child_hash<'a>(hash: &'a mut Hash, key: &str) -> BatmanResult<&'a mut Hash> {
    let yaml_key = Yaml::String(key.to_string());
    if !hash.contains_key(&yaml_key) {
        hash.insert(yaml_key.clone(), Yaml::Hash(Hash::new()));
    }
    let value = hash.get_mut(&yaml_key).expect("key was inserted");
    ensure_hash(value, key)
}

fn ensure_hash<'a>(yaml: &'a mut Yaml, name: &str) -> BatmanResult<&'a mut Hash> {
    match yaml {
        Yaml::Hash(hash) => Ok(hash),
        _ => Err(BatmanError::Config(format!("{name} must be a YAML map"))),
    }
}

fn read_session(path: &Path) -> BatmanResult<ReviewSession> {
    match read_generated_session(path) {
        Ok(session) => return Ok(session),
        Err(BatmanError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
            return Err(BatmanError::Config(format!(
                "review session not found: {}",
                path.display()
            )));
        }
        Err(_) => {}
    }

    let file = File::open(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            BatmanError::Config(format!("review session not found: {}", path.display()))
        } else {
            BatmanError::io(format!("read {}", path.display()), error)
        }
    })?;
    let reader = BufReader::new(file);
    let session: ReviewSession =
        serde_yaml::from_reader(reader).map_err(|error| BatmanError::Parse(error.to_string()))?;
    if session.format != FORMAT {
        return Err(BatmanError::Parse(format!(
            "unsupported review format {}",
            session.format
        )));
    }
    Ok(session)
}

pub fn read_review_session(path: &Path) -> BatmanResult<ReviewSession> {
    read_session(path)
}

fn read_generated_session(path: &Path) -> BatmanResult<ReviewSession> {
    let file = File::open(path)
        .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
    let reader = BufReader::new(file);
    let mut session = ReviewSession {
        format: String::new(),
        session_id: String::new(),
        status: String::new(),
        scanned_at: String::new(),
        applied_at: String::new(),
        applied_by: String::new(),
        apply_comment: String::new(),
        host: String::new(),
        config_path: String::new(),
        baseline_db: String::new(),
        summary: ReviewSummary::default(),
        findings: Vec::new(),
        actions: Vec::new(),
    };
    let mut section = FastReviewSection::Top;
    let mut current = None;

    for line in reader.lines() {
        let line = line.map_err(|error| BatmanError::io("read generated review session", error))?;
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }

        match line {
            "summary:" => {
                finish_fast_finding(&mut session.findings, &mut current)?;
                section = FastReviewSection::Summary;
                continue;
            }
            "findings:" => {
                finish_fast_finding(&mut session.findings, &mut current)?;
                section = FastReviewSection::Findings;
                continue;
            }
            "actions: []" => {
                finish_fast_finding(&mut session.findings, &mut current)?;
                section = FastReviewSection::Actions;
                continue;
            }
            "actions:" => {
                return Err(BatmanError::Parse(
                    "review actions require full YAML parser".to_string(),
                ));
            }
            _ => {}
        }

        match section {
            FastReviewSection::Top => parse_fast_top_field(&mut session, line)?,
            FastReviewSection::Summary => parse_fast_summary_field(&mut session.summary, line)?,
            FastReviewSection::Findings => {
                if line.starts_with("- id: ") {
                    finish_fast_finding(&mut session.findings, &mut current)?;
                }
                parse_fast_finding_field(&mut current, line)?;
            }
            FastReviewSection::Actions => {
                if line != "[]" {
                    return Err(BatmanError::Parse(
                        "review actions require full YAML parser".to_string(),
                    ));
                }
            }
        }
    }
    finish_fast_finding(&mut session.findings, &mut current)?;
    if session.format != FORMAT {
        return Err(BatmanError::Parse(format!(
            "unsupported review format {}",
            session.format
        )));
    }
    Ok(session)
}

#[derive(Clone, Copy)]
enum FastReviewSection {
    Top,
    Summary,
    Findings,
    Actions,
}

#[derive(Default)]
struct FastReviewFinding {
    id: Option<u32>,
    kind: Option<ReviewFindingKind>,
    path: Option<Box<str>>,
    previous_path: Option<Box<str>>,
    reason: Option<ReviewReason>,
    size: Option<u64>,
    modified_ns: Option<i64>,
    state: Option<ReviewState>,
    action: Option<ReviewActionKind>,
}

fn parse_fast_top_field(session: &mut ReviewSession, line: &str) -> BatmanResult<()> {
    let Some((key, value)) = fast_key_value(line) else {
        return Err(BatmanError::Parse(format!("invalid review field {line}")));
    };
    match key {
        "format" => session.format = parse_fast_scalar(value)?,
        "session_id" => session.session_id = parse_fast_scalar(value)?,
        "status" => session.status = parse_fast_scalar(value)?,
        "scanned_at" => session.scanned_at = parse_fast_scalar(value)?,
        "applied_at" => session.applied_at = parse_fast_scalar(value)?,
        "applied_by" => session.applied_by = parse_fast_scalar(value)?,
        "apply_comment" => session.apply_comment = parse_fast_scalar(value)?,
        "host" => session.host = parse_fast_scalar(value)?,
        "config_path" => session.config_path = parse_fast_scalar(value)?,
        "baseline_db" => session.baseline_db = parse_fast_scalar(value)?,
        _ => {
            return Err(BatmanError::Parse(format!(
                "unsupported review field {key}"
            )));
        }
    }
    Ok(())
}

fn parse_fast_summary_field(summary: &mut ReviewSummary, line: &str) -> BatmanResult<()> {
    let Some((key, value)) = fast_key_value(line.trim_start()) else {
        return Err(BatmanError::Parse(format!("invalid review summary {line}")));
    };
    match key {
        "files" => summary.files = parse_fast_u64(value)?,
        "bytes" => summary.bytes = parse_fast_u64(value)?,
        "modified" => summary.modified = parse_fast_u64(value)?,
        "added" => summary.added = parse_fast_u64(value)?,
        "deleted" => summary.deleted = parse_fast_u64(value)?,
        "moved" => summary.moved = parse_fast_u64(value)?,
        _ => {
            return Err(BatmanError::Parse(format!(
                "unsupported review summary field {key}"
            )));
        }
    }
    Ok(())
}

fn parse_fast_finding_field(
    current: &mut Option<FastReviewFinding>,
    line: &str,
) -> BatmanResult<()> {
    if let Some(value) = line.strip_prefix("- id: ") {
        if current.is_some() {
            return Err(BatmanError::Parse(
                "previous review finding was not finished".to_string(),
            ));
        }
        *current = Some(FastReviewFinding {
            id: Some(parse_fast_u32(value)?),
            ..FastReviewFinding::default()
        });
        return Ok(());
    }
    let Some(finding) = current.as_mut() else {
        return Err(BatmanError::Parse(
            "review finding field before id".to_string(),
        ));
    };
    let Some((key, value)) = fast_key_value(line.trim_start()) else {
        return Err(BatmanError::Parse(format!("invalid review finding {line}")));
    };
    match key {
        "kind" => finding.kind = Some(parse_fast_finding_kind(value)?),
        "path" => finding.path = Some(parse_fast_scalar(value)?.into()),
        "previous_path" => finding.previous_path = Some(parse_fast_scalar(value)?.into()),
        "reason" => finding.reason = Some(ReviewReason::parse(&parse_fast_scalar(value)?)?),
        "size" => finding.size = Some(parse_fast_u64(value)?),
        "modified_ns" => finding.modified_ns = Some(parse_fast_i64(value)?),
        "state" => finding.state = Some(parse_fast_review_state(value)?),
        "action" => finding.action = Some(parse_fast_action_kind(value)?),
        "target" => {
            let _ = parse_fast_scalar(value)?;
        }
        _ => {
            return Err(BatmanError::Parse(format!(
                "unsupported review finding field {key}"
            )));
        }
    }
    Ok(())
}

fn finish_fast_finding(
    findings: &mut Vec<ReviewFinding>,
    current: &mut Option<FastReviewFinding>,
) -> BatmanResult<()> {
    let Some(finding) = current.take() else {
        return Ok(());
    };
    let kind = finding
        .kind
        .ok_or_else(|| BatmanError::Parse("review finding missing kind".to_string()))?;
    let path = finding
        .path
        .ok_or_else(|| BatmanError::Parse("review finding missing path".to_string()))?;
    let path = if kind == ReviewFindingKind::Moved {
        encode_move_paths(
            &path,
            finding.previous_path.as_deref().ok_or_else(|| {
                BatmanError::Parse("moved finding missing previous_path".to_string())
            })?,
        )
        .into_boxed_str()
    } else {
        path
    };
    let mut review_finding = ReviewFinding::new(
        finding
            .id
            .ok_or_else(|| BatmanError::Parse("review finding missing id".to_string()))?,
        kind,
        path,
        finding.size.unwrap_or(0),
        finding.modified_ns.unwrap_or(0),
        finding.reason.unwrap_or_else(ReviewReason::empty),
    );
    review_finding.set_state_action(
        finding.state.unwrap_or_default(),
        finding.action.unwrap_or_default(),
    );
    findings.push(review_finding);
    Ok(())
}

fn fast_key_value(line: &str) -> Option<(&str, &str)> {
    line.split_once(':')
        .map(|(key, value)| (key.trim(), value.trim_start()))
}

fn parse_fast_scalar(value: &str) -> BatmanResult<String> {
    if value == "''" {
        return Ok(String::new());
    }
    if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|text| text.strip_suffix('\''))
    {
        return Ok(inner.replace("''", "'"));
    }
    if value.starts_with('"') && value.ends_with('"') {
        return serde_yaml::from_str(value).map_err(|error| BatmanError::Parse(error.to_string()));
    }
    Ok(value.to_string())
}

fn parse_fast_u64(value: &str) -> BatmanResult<u64> {
    value
        .parse()
        .map_err(|_| BatmanError::Parse(format!("invalid review number {value}")))
}

fn parse_fast_u32(value: &str) -> BatmanResult<u32> {
    value
        .parse()
        .map_err(|_| BatmanError::Parse(format!("invalid review number {value}")))
}

fn parse_fast_i64(value: &str) -> BatmanResult<i64> {
    value
        .parse()
        .map_err(|_| BatmanError::Parse(format!("invalid review number {value}")))
}

fn parse_fast_finding_kind(value: &str) -> BatmanResult<ReviewFindingKind> {
    match parse_fast_scalar(value)?.as_str() {
        "added" => Ok(ReviewFindingKind::Added),
        "modified" => Ok(ReviewFindingKind::Modified),
        "deleted" => Ok(ReviewFindingKind::Deleted),
        "moved" => Ok(ReviewFindingKind::Moved),
        other => Err(BatmanError::Parse(format!(
            "unknown review finding kind {other}"
        ))),
    }
}

fn parse_fast_review_state(value: &str) -> BatmanResult<ReviewState> {
    match parse_fast_scalar(value)?.as_str() {
        "unreviewed" => Ok(ReviewState::Unreviewed),
        "approved" => Ok(ReviewState::Approved),
        "excluded" => Ok(ReviewState::Excluded),
        "flagged" => Ok(ReviewState::Flagged),
        other => Err(BatmanError::Parse(format!(
            "unknown review finding state {other}"
        ))),
    }
}

fn parse_fast_action_kind(value: &str) -> BatmanResult<ReviewActionKind> {
    match parse_fast_scalar(value)?.as_str() {
        "none" => Ok(ReviewActionKind::None),
        "approve" => Ok(ReviewActionKind::Approve),
        "exclude" => Ok(ReviewActionKind::Exclude),
        "flag" => Ok(ReviewActionKind::Flag),
        other => Err(BatmanError::Parse(format!(
            "unknown review finding action {other}"
        ))),
    }
}

fn write_review_finding<W: Write>(writer: &mut W, finding: &ReviewFinding) -> BatmanResult<()> {
    write_u32(writer, finding.id)?;
    write_u8(writer, finding_kind_to_byte(finding.kind()))?;
    write_boxed_str(writer, &finding.path)?;
    write_u64(writer, finding.size)?;
    write_i64(writer, finding.modified_ns)?;
    write_u8(writer, review_state_to_byte(finding.state()))?;
    write_u8(writer, action_kind_to_byte(finding.action()))?;
    write_u16(writer, finding.reason().0)?;
    write_optional_snapshot(writer, finding.before())?;
    write_optional_snapshot(writer, finding.after())
}

fn snapshot_change(
    before: Option<ReviewSnapshot>,
    after: Option<ReviewSnapshot>,
) -> Option<Box<ReviewChange>> {
    if before.is_none() && after.is_none() {
        None
    } else {
        Some(Box::new(ReviewChange { before, after }))
    }
}

fn write_optional_snapshot<W: Write>(
    writer: &mut W,
    snapshot: Option<&ReviewSnapshot>,
) -> BatmanResult<()> {
    let Some(snapshot) = snapshot else {
        write_u8(writer, 0)?;
        return Ok(());
    };
    write_u8(writer, 1)?;
    write_boxed_str(writer, &snapshot.checksum)?;
    write_boxed_str(writer, &snapshot.kind)?;
    write_optional_u64(writer, snapshot.size)?;
    write_optional_boxed_str(writer, snapshot.permissions_octal.as_deref())?;
    write_optional_u64(writer, snapshot.owner)?;
    write_optional_u64(writer, snapshot.group)?;
    write_optional_i64(writer, snapshot.modified_ns)?;
    write_optional_i64(writer, snapshot.created_ns)?;
    write_optional_i64(writer, snapshot.metadata_changed_ns)?;
    write_optional_boxed_str(writer, snapshot.security_metadata_hash.as_deref())
}

fn read_optional_snapshot<R: Read>(reader: &mut R) -> BatmanResult<Option<ReviewSnapshot>> {
    if read_u8(reader)? == 0 {
        return Ok(None);
    }
    Ok(Some(ReviewSnapshot {
        checksum: read_boxed_str(reader)?,
        kind: read_boxed_str(reader)?,
        size: read_optional_u64_value(reader)?,
        permissions_octal: read_optional_boxed_str(reader)?,
        owner: read_optional_u64_value(reader)?,
        group: read_optional_u64_value(reader)?,
        modified_ns: read_optional_i64_value(reader)?,
        created_ns: read_optional_i64_value(reader)?,
        metadata_changed_ns: read_optional_i64_value(reader)?,
        security_metadata_hash: read_optional_boxed_str(reader)?,
    }))
}

fn write_optional_boxed_str<W: Write>(writer: &mut W, value: Option<&str>) -> BatmanResult<()> {
    let Some(value) = value else {
        write_u8(writer, 0)?;
        return Ok(());
    };
    write_u8(writer, 1)?;
    write_boxed_str(writer, value)
}

fn read_optional_boxed_str<R: Read>(reader: &mut R) -> BatmanResult<Option<Box<str>>> {
    if read_u8(reader)? == 0 {
        return Ok(None);
    }
    Ok(Some(read_boxed_str(reader)?))
}

fn write_optional_u64<W: Write>(writer: &mut W, value: Option<u64>) -> BatmanResult<()> {
    let Some(value) = value else {
        write_u8(writer, 0)?;
        return Ok(());
    };
    write_u8(writer, 1)?;
    write_u64(writer, value)
}

fn read_optional_u64_value<R: Read>(reader: &mut R) -> BatmanResult<Option<u64>> {
    if read_u8(reader)? == 0 {
        return Ok(None);
    }
    Ok(Some(read_u64(reader)?))
}

fn write_optional_i64<W: Write>(writer: &mut W, value: Option<i64>) -> BatmanResult<()> {
    let Some(value) = value else {
        write_u8(writer, 0)?;
        return Ok(());
    };
    write_u8(writer, 1)?;
    write_i64(writer, value)
}

fn read_optional_i64_value<R: Read>(reader: &mut R) -> BatmanResult<Option<i64>> {
    if read_u8(reader)? == 0 {
        return Ok(None);
    }
    Ok(Some(read_i64(reader)?))
}

fn write_boxed_str<W: Write>(writer: &mut W, value: &str) -> BatmanResult<()> {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len())
        .map_err(|_| BatmanError::Store("review finding string is too long".to_string()))?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(|error| BatmanError::io("write review finding string length", error))?;
    writer
        .write_all(bytes)
        .map_err(|error| BatmanError::io("write review finding string", error))
}

fn read_boxed_str<R: Read>(reader: &mut R) -> BatmanResult<Box<str>> {
    let len = read_u32(reader)? as usize;
    let mut bytes = vec![0_u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| BatmanError::io("read review finding string", error))?;
    String::from_utf8(bytes)
        .map(String::into_boxed_str)
        .map_err(|_| BatmanError::Parse("review finding string is not UTF-8".to_string()))
}

fn write_u8<W: Write>(writer: &mut W, value: u8) -> BatmanResult<()> {
    writer
        .write_all(&[value])
        .map_err(|error| BatmanError::io("write review finding byte", error))
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> BatmanResult<()> {
    writer
        .write_all(&value.to_le_bytes())
        .map_err(|error| BatmanError::io("write review finding u64", error))
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> BatmanResult<()> {
    writer
        .write_all(&value.to_le_bytes())
        .map_err(|error| BatmanError::io("write review finding u32", error))
}

fn write_u16<W: Write>(writer: &mut W, value: u16) -> BatmanResult<()> {
    writer
        .write_all(&value.to_le_bytes())
        .map_err(|error| BatmanError::io("write review finding u16", error))
}

fn write_i64<W: Write>(writer: &mut W, value: i64) -> BatmanResult<()> {
    writer
        .write_all(&value.to_le_bytes())
        .map_err(|error| BatmanError::io("write review finding i64", error))
}

fn read_u8<R: Read>(reader: &mut R) -> BatmanResult<u8> {
    let mut byte = [0_u8; 1];
    reader
        .read_exact(&mut byte)
        .map_err(|error| BatmanError::io("read review finding byte", error))?;
    Ok(byte[0])
}

fn read_u32<R: Read>(reader: &mut R) -> BatmanResult<u32> {
    let mut bytes = [0_u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| BatmanError::io("read review finding u32", error))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16<R: Read>(reader: &mut R) -> BatmanResult<u16> {
    let mut bytes = [0_u8; 2];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| BatmanError::io("read review finding u16", error))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_optional_u32<R: Read>(reader: &mut R) -> BatmanResult<Option<u32>> {
    let mut bytes = [0_u8; 4];
    match reader.read_exact(&mut bytes) {
        Ok(()) => Ok(Some(u32::from_le_bytes(bytes))),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(BatmanError::io("read review finding u32", error)),
    }
}

fn read_u64<R: Read>(reader: &mut R) -> BatmanResult<u64> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| BatmanError::io("read review finding u64", error))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_i64<R: Read>(reader: &mut R) -> BatmanResult<i64> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| BatmanError::io("read review finding i64", error))?;
    Ok(i64::from_le_bytes(bytes))
}

fn finding_kind_to_byte(kind: ReviewFindingKind) -> u8 {
    match kind {
        ReviewFindingKind::Added => 1,
        ReviewFindingKind::Modified => 2,
        ReviewFindingKind::Deleted => 3,
        ReviewFindingKind::Moved => 4,
    }
}

fn finding_kind_from_byte(value: u8) -> BatmanResult<ReviewFindingKind> {
    match value {
        1 => Ok(ReviewFindingKind::Added),
        2 => Ok(ReviewFindingKind::Modified),
        3 => Ok(ReviewFindingKind::Deleted),
        4 => Ok(ReviewFindingKind::Moved),
        _ => Err(BatmanError::Parse(format!(
            "unknown review finding kind {value}"
        ))),
    }
}

fn review_state_to_byte(state: ReviewState) -> u8 {
    match state {
        ReviewState::Unreviewed => 1,
        ReviewState::Approved => 2,
        ReviewState::Excluded => 3,
        ReviewState::Flagged => 4,
    }
}

fn review_state_from_byte(value: u8) -> BatmanResult<ReviewState> {
    match value {
        1 => Ok(ReviewState::Unreviewed),
        2 => Ok(ReviewState::Approved),
        3 => Ok(ReviewState::Excluded),
        4 => Ok(ReviewState::Flagged),
        _ => Err(BatmanError::Parse(format!(
            "unknown review finding state {value}"
        ))),
    }
}

fn action_kind_to_byte(kind: ReviewActionKind) -> u8 {
    match kind {
        ReviewActionKind::None => 1,
        ReviewActionKind::Approve => 2,
        ReviewActionKind::Exclude => 3,
        ReviewActionKind::Flag => 4,
    }
}

fn action_kind_from_byte(value: u8) -> BatmanResult<ReviewActionKind> {
    match value {
        1 => Ok(ReviewActionKind::None),
        2 => Ok(ReviewActionKind::Approve),
        3 => Ok(ReviewActionKind::Exclude),
        4 => Ok(ReviewActionKind::Flag),
        _ => Err(BatmanError::Parse(format!(
            "unknown review finding action {value}"
        ))),
    }
}

fn missing_review_message(_context: &CommandContext, path: &Path) -> Option<String> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => None,
        Ok(_) => Some(format!(
            "Review session path is not a file: {}",
            path.display()
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            Some("no review session found. Run 'batman scan' first.".to_string())
        }
        Err(error) => Some(format!(
            "Unable to access review session {}: {error}",
            path.display()
        )),
    }
}

fn write_session(path: &Path, session: &ReviewSession) -> BatmanResult<()> {
    write_serialized_session(path, session)
}

fn write_serialized_session<T: Serialize>(path: &Path, session: &T) -> BatmanResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| BatmanError::io(format!("create {}", parent.display()), error))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let file = File::create(&tmp)
            .map_err(|error| BatmanError::io(format!("write {}", tmp.display()), error))?;
        let mut writer = BufWriter::new(file);
        serde_yaml::to_writer(&mut writer, session)
            .map_err(|error| BatmanError::Parse(error.to_string()))?;
        writer
            .write_all(b"\n")
            .map_err(|error| BatmanError::io(format!("write {}", tmp.display()), error))?;
        writer
            .flush()
            .map_err(|error| BatmanError::io(format!("write {}", tmp.display()), error))?;
    }
    fs::rename(&tmp, path).map_err(|error| {
        BatmanError::io(format!("replace review session {}", path.display()), error)
    })
}

fn replace_file_from_existing(source: &Path, target: &Path) -> BatmanResult<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| BatmanError::io(format!("create {}", parent.display()), error))?;
    }
    let tmp = target.with_extension(format!("tmp.{}", std::process::id()));
    fs::copy(source, &tmp).map_err(|error| {
        BatmanError::io(
            format!("copy {} to {}", source.display(), tmp.display()),
            error,
        )
    })?;
    fs::rename(&tmp, target).map_err(|error| {
        BatmanError::io(
            format!("replace review session {}", target.display()),
            error,
        )
    })
}

fn resolve_session_path(context: &CommandContext, session: Option<&str>) -> BatmanResult<PathBuf> {
    match session {
        None | Some("latest") => Ok(latest_review_path(context)),
        Some(value) => {
            let path = PathBuf::from(value);
            if path.exists() {
                Ok(path)
            } else {
                Ok(session_path(context, value))
            }
        }
    }
}

fn reviews_dir(context: &CommandContext) -> PathBuf {
    BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )
    .map(|config| reviews_dir_for_config(&config))
    .unwrap_or_else(|_| context.local_settings.default_db_path.join(REVIEWS_DIR))
}

fn latest_review_path(context: &CommandContext) -> PathBuf {
    reviews_dir(context).join(LATEST_REVIEW_FILE)
}

fn session_path(context: &CommandContext, session_id: &str) -> PathBuf {
    reviews_dir(context).join(format!("{session_id}.review.yaml"))
}

fn reviews_dir_for_config(config: &BatmanConfig) -> PathBuf {
    config.file_integrity.db_path.join(REVIEWS_DIR)
}

fn latest_review_path_for_config(config: &BatmanConfig) -> PathBuf {
    reviews_dir_for_config(config).join(LATEST_REVIEW_FILE)
}

fn session_path_for_config(config: &BatmanConfig, session_id: &str) -> PathBuf {
    reviews_dir_for_config(config).join(format!("{session_id}.review.yaml"))
}

fn session_id() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("scan-{secs}")
}

fn monotonic_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn scan_timestamp() -> String {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    format!(
        "{:04}/{:02}/{:02} {:02}:{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute()
    )
}

fn clean_review_message(session: &ReviewSession) -> String {
    let scanned_at = if session.scanned_at.is_empty() {
        "unknown"
    } else {
        &session.scanned_at
    };
    format!("No findings to review. Last scan: {scanned_at}.")
}

fn host_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn default_operator() -> String {
    std::env::var("BATMAN_OPERATOR")
        .or_else(|_| std::env::var("SUDO_USER"))
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("USERNAME"))
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn path_set_contains(paths: &BTreeSet<PathBuf>, path: &Path) -> bool {
    paths.contains(path)
        || paths
            .iter()
            .any(|candidate| comparable_path(candidate) == comparable_path(path))
}

fn comparable_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        path.strip_prefix("/private")
            .map(|stripped| Path::new("/").join(stripped))
            .unwrap_or_else(|_| path.to_path_buf())
    }
    #[cfg(not(target_os = "macos"))]
    {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{
        CommandContext, FINDING_SPOOL_MAGIC, ReviewAction, ReviewActionKind, ReviewApp,
        ReviewChange, ReviewFinding, ReviewFindingKind, ReviewFindingSpool,
        ReviewFindingSpoolReader, ReviewReason, ReviewSession, ReviewSnapshot, ReviewState,
        ReviewSummary, ReviewView, decode_affected_ids, draw, empty_boxed_str, encode_affected_ids,
        monotonic_nanos, review_exclusions, review_usize, write_review_finding,
        write_review_from_finding_spool,
    };

    #[test]
    fn directory_exclusion_hides_affected_findings_and_undo_restores_them() {
        let session = test_session();
        let mut app = ReviewApp::new(session, "review.yaml".into());

        assert_eq!(app.visible.len(), 3);
        let affected = app.session.exclude_target("/var/cache/app");
        app.refresh();

        assert_eq!(affected, 2);
        assert_eq!(app.counts.excluded, 2);
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.session.actions.len(), 1);
        assert!(app.session.actions[0].affected.is_empty());
        assert_eq!(
            decode_affected_ids(&app.session.actions[0].affected_ids),
            vec![1, 2]
        );
        assert_eq!(app.session.actions[0].affected_count(), 2);
        assert_eq!(app.session.actions[0].target.as_ref(), "/var/cache/app");
        assert!(app.session.actions[0].previous.is_empty());
        assert_eq!(
            review_exclusions(&app.session),
            vec!["/var/cache/app".to_string()]
        );

        assert_eq!(app.session.undo(), Some(2));
        app.refresh();

        assert_eq!(app.counts.unreviewed, 3);
        assert_eq!(app.visible.len(), 3);
        assert!(app.session.actions.is_empty());
    }

    #[test]
    fn review_finding_stays_compact_for_large_review_sessions() {
        assert!(
            std::mem::size_of::<ReviewFinding>() <= 48,
            "ReviewFinding size affects large review session RSS"
        );
    }

    #[test]
    fn undo_handles_non_positional_finding_ids() {
        let mut session = test_session();
        session.findings[0].id = 100;
        session.mark_one(
            0,
            ReviewState::Flagged,
            ReviewActionKind::Flag,
            "/var/cache/app/a.tmp".into(),
        );

        assert_eq!(session.findings[0].state(), ReviewState::Flagged);
        assert_eq!(session.undo(), Some(1));
        assert_eq!(session.findings[0].state(), ReviewState::Unreviewed);
        assert_eq!(session.findings[0].action(), ReviewActionKind::None);
    }

    #[test]
    fn affected_ids_encode_and_decode_sparse_ids() {
        let ids = vec![100, 1, 1_000_000, 101, 9, 9];
        let encoded = encode_affected_ids(&ids);

        assert!(!encoded.is_empty());
        assert_eq!(
            decode_affected_ids(&encoded),
            vec![1, 9, 100, 101, 1_000_000]
        );
    }

    #[test]
    fn review_exclusions_use_review_actions() {
        let mut session = test_session();
        session.actions.push(ReviewAction {
            id: 1,
            kind: ReviewActionKind::Exclude,
            target: "/var/cache/app".into(),
            affected: Vec::new(),
            affected_ids: empty_boxed_str(),
            previous: Vec::new(),
            applied: false,
        });

        assert_eq!(
            review_exclusions(&session),
            vec!["/var/cache/app".to_string()]
        );
    }

    #[test]
    fn tui_renders_long_paths_and_mixed_review_states() {
        let mut session = test_session();
        session.findings[0].path = "/very/long/path/that/keeps/going/through/a/deep/tree/with/generated/cache/files/and/a/final/file-name-that-is-long.tmp".into();
        session.findings[1].set_state_action(ReviewState::Approved, ReviewActionKind::Approve);
        session.findings[2].set_state_action(ReviewState::Flagged, ReviewActionKind::Flag);
        let mut deleted = ReviewFinding::new(
            4,
            ReviewFindingKind::Deleted,
            "/deleted/path/that/is/also/long/old-binary".into(),
            99,
            0,
            ReviewReason::empty(),
        );
        deleted.set_state_action(ReviewState::Excluded, ReviewActionKind::Exclude);
        session.findings.push(deleted);
        session.actions.push(ReviewAction {
            id: 1,
            kind: ReviewActionKind::Exclude,
            target: "/deleted/path".into(),
            affected: vec![4],
            affected_ids: empty_boxed_str(),
            previous: Vec::new(),
            applied: false,
        });
        let app = ReviewApp::new(session, "/etc/batman/reviews/latest.review.yaml".into());

        for (width, height) in [(80, 24), (140, 36)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains("Batman Review"));
            assert!(rendered.contains("Unreviewed"));
            assert!(rendered.contains("Exclusion Targets"));
            assert!(rendered.contains("Recent Actions"));
            assert!(rendered.contains("SELECTED"));
            assert!(rendered.contains("x exclude selected target"));
        }
    }

    #[test]
    fn exclusion_targets_include_broad_parent_directories() {
        let mut session = test_session();
        session.findings = vec![
            finding(
                1,
                "/var/lib/docker/overlay2/abc/diff/var/lib/apt/lists/packages",
            ),
            finding(2, "/var/lib/docker/overlay2/def/diff/usr/bin/tool"),
            finding(3, "/etc/app.conf"),
        ];
        let app = ReviewApp::new(session, "review.yaml".into());

        let overlay = app
            .targets
            .iter()
            .find(|target| target.path == "/var/lib/docker/overlay2")
            .expect("expected broad docker overlay target");

        assert!(overlay.directory);
        assert_eq!(overlay.affects, 2);
    }

    #[test]
    fn filter_limits_visible_findings() {
        let mut app = ReviewApp::new(test_session(), "review.yaml".into());

        app.set_filter("etc".to_string());
        assert_eq!(app.visible.len(), 1);
        assert_eq!(
            app.session.findings[review_usize(app.visible[0])].path,
            "/etc/app.conf".into()
        );

        app.set_filter(String::new());
        assert_eq!(app.visible.len(), 3);
    }

    #[test]
    fn view_cycle_shows_reviewed_findings() {
        let mut session = test_session();
        session.findings[0].set_state_action(ReviewState::Flagged, ReviewActionKind::Flag);
        session.findings[1].set_state_action(ReviewState::Excluded, ReviewActionKind::Exclude);
        session.findings[2].set_state_action(ReviewState::Approved, ReviewActionKind::Approve);
        let mut app = ReviewApp::new(session, "review.yaml".into());

        assert_eq!(app.view, ReviewView::Unreviewed);
        assert!(app.visible.is_empty());

        app.cycle_view();
        assert_eq!(app.view, ReviewView::Flagged);
        assert_eq!(app.visible.len(), 1);
        assert_eq!(
            app.session.findings[review_usize(app.visible[0])].state(),
            ReviewState::Flagged
        );

        app.cycle_view();
        assert_eq!(app.view, ReviewView::Excluded);
        assert_eq!(app.visible.len(), 1);
        assert_eq!(
            app.session.findings[review_usize(app.visible[0])].state(),
            ReviewState::Excluded
        );

        app.cycle_view();
        assert_eq!(app.view, ReviewView::Approved);
        assert_eq!(app.visible.len(), 1);
        assert_eq!(
            app.session.findings[review_usize(app.visible[0])].state(),
            ReviewState::Approved
        );

        app.cycle_view();
        assert_eq!(app.view, ReviewView::All);
        assert_eq!(app.visible.len(), 3);
    }

    #[test]
    fn review_enums_serialize_as_existing_yaml_strings() {
        let mut session = test_session();
        session.findings[0].set_state_action(ReviewState::Approved, ReviewActionKind::Approve);
        let yaml = serde_yaml::to_string(&session).unwrap();

        assert!(yaml.contains("kind: added"));
        assert!(yaml.contains("state: approved"));
        assert!(yaml.contains("action: approve"));
        assert!(!yaml.contains("target: ''"));

        let decoded: ReviewSession = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(decoded.findings[0].kind(), ReviewFindingKind::Added);
        assert_eq!(decoded.findings[0].state(), ReviewState::Approved);
        assert_eq!(decoded.findings[0].action(), ReviewActionKind::Approve);
    }

    #[test]
    fn review_finding_serializes_snapshot_evidence() {
        let before = ReviewSnapshot {
            checksum: "before-hash".into(),
            kind: "file".into(),
            size: Some(3),
            permissions_octal: Some("100644".into()),
            owner: Some(1000),
            group: Some(1000),
            modified_ns: Some(1),
            created_ns: None,
            metadata_changed_ns: Some(2),
            security_metadata_hash: None,
        };
        let after = ReviewSnapshot {
            checksum: "after-hash".into(),
            kind: "file".into(),
            size: Some(7),
            permissions_octal: Some("100600".into()),
            owner: Some(1000),
            group: Some(1000),
            modified_ns: Some(3),
            created_ns: None,
            metadata_changed_ns: Some(4),
            security_metadata_hash: None,
        };
        let finding = ReviewFinding::new_with_snapshots(
            1,
            ReviewFindingKind::Modified,
            "/etc/app.conf".into(),
            7,
            3,
            ReviewReason::from_names(&["checksum", "permissions"]),
            ReviewChange {
                before: Some(before),
                after: Some(after),
            },
        );

        let yaml = serde_yaml::to_string(&finding).unwrap();

        assert!(yaml.contains("before:"));
        assert!(yaml.contains("after:"));
        assert!(yaml.contains("before-hash"));
        assert!(yaml.contains("after-hash"));

        let spool_path = std::env::temp_dir().join(format!(
            "batman-review-snapshot-test-{}-{}",
            std::process::id(),
            monotonic_nanos()
        ));
        {
            let mut file = File::create(&spool_path).unwrap();
            file.write_all(FINDING_SPOOL_MAGIC).unwrap();
            write_review_finding(&mut file, &finding).unwrap();
        }
        let mut reader = ReviewFindingSpoolReader::open(&spool_path).unwrap();
        let decoded = reader.next().unwrap().unwrap();
        let decoded_yaml = serde_yaml::to_string(&decoded).unwrap();
        let _ = fs::remove_file(&spool_path);

        assert!(decoded_yaml.contains("before:"));
        assert!(decoded_yaml.contains("after:"));
        assert!(decoded_yaml.contains("before-hash"));
        assert!(decoded_yaml.contains("after-hash"));

        let root = std::env::temp_dir().join(format!(
            "batman-review-snapshot-session-test-{}-{}",
            std::process::id(),
            monotonic_nanos()
        ));
        let config_path = root.join("config").join("batman.yaml");
        let db_path = root.join("db");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::create_dir_all(&db_path).unwrap();
        fs::write(&config_path, "file_integrity:\n  scan_paths: []\n").unwrap();
        let config = crate::config::BatmanConfig {
            file_integrity: crate::config::FileIntegrityConfig {
                scan_byte_limit: 0,
                scan_threads: 1,
                scan_buffer_size: 64 * 1024,
                baseline_public_key: None,
                db_path: db_path.clone(),
                scan_paths: Vec::new(),
                exclusions: Vec::new(),
                excluded_filesystems: Vec::new(),
                metadata_directories: Vec::new(),
                metadata_only: Vec::new(),
                registry_paths: Vec::new(),
                settings_dir: root.join("config"),
            },
            email: crate::config::EmailConfig {
                send_on_fail: false,
                send_on_success: false,
                server_host: String::new(),
                server_port: 25,
                from_address: String::new(),
                fail_to_address: String::new(),
                success_to_address: String::new(),
            },
        };
        let context = CommandContext {
            global: crate::cli::GlobalOptions {
                insecure: true,
                quiet: true,
                ..crate::cli::GlobalOptions::default()
            },
            local_settings: crate::config::LocalSettings::for_config_path(config_path),
        };
        let mut spool = ReviewFindingSpool::create(&config).unwrap();
        spool.push(&finding).unwrap();
        let review_path = write_review_from_finding_spool(
            &context,
            &config,
            &ReviewSummary {
                files: 1,
                bytes: 7,
                modified: 1,
                added: 0,
                deleted: 0,
                moved: 0,
            },
            spool.finish().unwrap(),
        )
        .unwrap();
        let review_yaml = fs::read_to_string(review_path).unwrap();
        let _ = fs::remove_dir_all(root);

        assert!(review_yaml.contains("before:"));
        assert!(review_yaml.contains("after:"));
        assert!(review_yaml.contains("before-hash"));
        assert!(review_yaml.contains("after-hash"));
    }

    #[test]
    fn legacy_acl_reason_parses_as_security_metadata() {
        let legacy = ReviewReason::parse("acl").unwrap();
        let current = ReviewReason::parse("security_metadata").unwrap();

        assert_eq!(legacy, current);
        assert_eq!(legacy.text(), "security_metadata");
    }

    fn test_session() -> ReviewSession {
        ReviewSession {
            format: super::FORMAT.to_string(),
            session_id: "test".to_string(),
            status: "in_progress".to_string(),
            scanned_at: "2026/06/28 10:30".to_string(),
            applied_at: String::new(),
            applied_by: String::new(),
            apply_comment: String::new(),
            host: "host".to_string(),
            config_path: "/etc/batman/batman.yaml".to_string(),
            baseline_db: "/var/lib/batman".to_string(),
            summary: ReviewSummary {
                files: 3,
                bytes: 30,
                modified: 1,
                added: 2,
                deleted: 0,
                moved: 0,
            },
            findings: vec![
                finding(1, "/var/cache/app/a.tmp"),
                finding(2, "/var/cache/app/b.tmp"),
                finding(3, "/etc/app.conf"),
            ],
            actions: Vec::new(),
        }
    }

    fn finding(id: u32, path: &str) -> ReviewFinding {
        ReviewFinding::new(
            id,
            ReviewFindingKind::Added,
            path.into(),
            10,
            0,
            ReviewReason::empty(),
        )
    }
}
