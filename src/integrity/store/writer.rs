use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ContentDigest;
use crate::integrity::perf_trace;
use crate::integrity::store::format::{
    IndexEntry, IndexHeader, RECORD_HEADER_LEN, RecordHeader, write_i128, write_index_entry,
    write_index_header, write_record_header, write_u32, write_u64, write_u128,
};
use crate::integrity::store::manifest::{
    BaselineSigningKey, INDEX_BACKUP, INDEX_FILE, INDEX_TMP, MANIFEST_BACKUP, MANIFEST_FILE,
    MANIFEST_TMP, RECORD_BACKUP, RECORD_FILE, RECORD_TMP, baseline_signing_key_from_env,
    write_manifest_tmp,
};
use crate::integrity::store::{
    CurrentScanEntry, CurrentScanSpool, FileMetadata, scan_spool::DEFAULT_CHUNK_LIMIT,
};
use crate::security::{secure_data_directory, secure_data_file};

const IO_BUFFER_SIZE: usize = 1024 * 1024;

pub struct BaselineWriter {
    db_path: PathBuf,
    record_path: PathBuf,
    index_path: PathBuf,
    spool: CurrentScanSpool,
    scan_byte_limit: u64,
    config_hash: [u8; 32],
    records: u64,
    record_bytes: u64,
    signing_key: Option<BaselineSigningKey>,
}

impl BaselineWriter {
    pub fn create(db_path: &Path, scan_byte_limit: u64) -> BatmanResult<Self> {
        Self::create_with_config_hash(db_path, scan_byte_limit, [0; 32])
    }

    pub fn create_with_config_hash(
        db_path: &Path,
        scan_byte_limit: u64,
        config_hash: [u8; 32],
    ) -> BatmanResult<Self> {
        let signing_key = baseline_signing_key_from_env()?;
        Self::create_with_config_hash_and_signing_key(
            db_path,
            scan_byte_limit,
            config_hash,
            signing_key,
        )
    }

    pub fn create_with_config_hash_and_signing_key(
        db_path: &Path,
        scan_byte_limit: u64,
        config_hash: [u8; 32],
        signing_key: Option<BaselineSigningKey>,
    ) -> BatmanResult<Self> {
        Self::with_index_chunk_limit_and_signing_key(
            db_path,
            scan_byte_limit,
            config_hash,
            DEFAULT_CHUNK_LIMIT,
            signing_key,
        )
    }

    pub fn with_index_chunk_limit(
        db_path: &Path,
        scan_byte_limit: u64,
        config_hash: [u8; 32],
        chunk_limit: usize,
    ) -> BatmanResult<Self> {
        let signing_key = baseline_signing_key_from_env()?;
        Self::with_index_chunk_limit_and_signing_key(
            db_path,
            scan_byte_limit,
            config_hash,
            chunk_limit,
            signing_key,
        )
    }

    pub fn with_index_chunk_limit_and_signing_key(
        db_path: &Path,
        scan_byte_limit: u64,
        config_hash: [u8; 32],
        chunk_limit: usize,
        signing_key: Option<BaselineSigningKey>,
    ) -> BatmanResult<Self> {
        fs::create_dir_all(db_path)
            .map_err(|error| BatmanError::io(format!("create {}", db_path.display()), error))?;
        secure_data_directory(db_path)?;

        recover_interrupted_replace(db_path)?;
        remove_stale_tmp(db_path)?;

        let record_path = db_path.join(RECORD_TMP);
        let index_path = db_path.join(INDEX_TMP);

        Ok(Self {
            db_path: db_path.to_path_buf(),
            record_path,
            index_path,
            spool: CurrentScanSpool::with_chunk_limit(db_path, chunk_limit),
            scan_byte_limit,
            config_hash,
            records: 0,
            record_bytes: 0,
            signing_key,
        })
    }

    pub fn add_file(
        &mut self,
        path: &Path,
        checksum: ContentDigest,
        size: u64,
        modified_ns: i128,
    ) -> BatmanResult<()> {
        self.add_file_with_metadata(
            path,
            checksum,
            FileMetadata {
                flags: 0,
                size,
                permissions: 0,
                owner: 0,
                group: 0,
                modified_ns,
                created_ns: 0,
                changed_ns: 0,
                acl_hash: [0; 32],
            },
        )
    }

    pub fn add_file_with_metadata(
        &mut self,
        path: &Path,
        checksum: ContentDigest,
        metadata: FileMetadata,
    ) -> BatmanResult<()> {
        let path_text = path.to_string_lossy();
        let path_bytes = path_text.as_bytes();
        let path_len = u32::try_from(path_bytes.len())
            .map_err(|_| BatmanError::Store(format!("path too long: {}", path.display())))?;

        self.spool.push_with_metadata(path, checksum, metadata)?;
        self.records += 1;
        self.record_bytes += 16 + 32 + metadata_len() + 4 + u64::from(path_len);
        Ok(())
    }

    pub fn progress_counters(&self) -> (u64, u64) {
        let (chunks, chunk_bytes) = self.spool.progress_counters();
        (chunks, self.record_bytes + chunk_bytes)
    }

    pub fn finish(self) -> BatmanResult<u64> {
        self.finish_with_progress(|_| Ok(()))
    }

    pub fn finish_with_progress<F>(self, mut progress: F) -> BatmanResult<u64>
    where
        F: FnMut(BaselineFinishProgress) -> BatmanResult<()>,
    {
        let finish_started = perf_trace::enabled().then(Instant::now);
        let records = self.records;
        progress(BaselineFinishProgress::Preparing { records })?;
        let prepare_started = perf_trace::enabled().then(Instant::now);
        let record_file = File::create(&self.record_path).map_err(|error| {
            BatmanError::io(format!("create {}", self.record_path.display()), error)
        })?;
        let mut record_writer = BufWriter::with_capacity(IO_BUFFER_SIZE, record_file);
        write_record_header(
            &mut record_writer,
            &RecordHeader {
                created: unix_now(),
                scan_byte_limit: self.scan_byte_limit,
                config_hash: self.config_hash,
                records,
            },
        )?;
        let index_file = File::create(&self.index_path).map_err(|error| {
            BatmanError::io(format!("create {}", self.index_path.display()), error)
        })?;
        let mut index_writer = BufWriter::with_capacity(IO_BUFFER_SIZE, index_file);
        write_index_header(&mut index_writer, &IndexHeader { records })?;

        let mut reader = self.spool.into_reader()?;
        if let Some(started) = prepare_started {
            perf_trace::event(
                "baseline-finish-prepare",
                format!("records={records}"),
                started.elapsed(),
            );
        }
        let write_started = perf_trace::enabled().then(Instant::now);
        let mut written = 0_u64;
        let mut record_offset = RECORD_HEADER_LEN;
        while let Some(entry) = reader.next_entry()? {
            let offset = record_offset;
            let written_record = write_baseline_record(&mut record_writer, &entry)?;
            record_offset += written_record.bytes;
            written += 1;
            write_index_entry(
                &mut index_writer,
                &IndexEntry {
                    path_hash: entry.path_hash,
                    offset,
                    path_len: written_record.path_len,
                },
            )?;
            if written == records || written.is_multiple_of(50_000) {
                progress(BaselineFinishProgress::Writing { written, records })?;
            }
        }
        if let Some(started) = write_started {
            perf_trace::event(
                "baseline-finish-write",
                format!("records={records}"),
                started.elapsed(),
            );
        }

        progress(BaselineFinishProgress::Syncing { records })?;
        let sync_started = perf_trace::enabled().then(Instant::now);
        record_writer
            .flush()
            .map_err(|error| BatmanError::io("flush baseline records", error))?;
        record_writer
            .get_ref()
            .sync_all()
            .map_err(|error| BatmanError::io("sync baseline records", error))?;

        index_writer
            .into_inner()
            .map_err(|error| BatmanError::io("flush baseline index", error.into_error()))?
            .sync_all()
            .map_err(|error| BatmanError::io("sync baseline index", error))?;
        if let Some(started) = sync_started {
            perf_trace::event(
                "baseline-finish-sync",
                format!("records={records}"),
                started.elapsed(),
            );
        }
        write_manifest_tmp(
            &self.db_path,
            &self.record_path,
            &self.index_path,
            records,
            self.scan_byte_limit,
            self.config_hash,
            self.signing_key.as_ref(),
        )?;

        progress(BaselineFinishProgress::Replacing { records })?;
        let replace_started = perf_trace::enabled().then(Instant::now);
        replace_baseline_files(&self.db_path, &self.record_path, &self.index_path)?;
        if let Some(started) = replace_started {
            perf_trace::event(
                "baseline-finish-replace",
                format!("records={records}"),
                started.elapsed(),
            );
        }
        if let Some(started) = finish_started {
            perf_trace::event(
                "baseline-finish-total",
                format!("records={records}"),
                started.elapsed(),
            );
        }
        Ok(records)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BaselineFinishProgress {
    Preparing { records: u64 },
    Writing { written: u64, records: u64 },
    Syncing { records: u64 },
    Replacing { records: u64 },
}

struct WrittenBaselineRecord {
    bytes: u64,
    path_len: u32,
}

fn write_baseline_record<W: Write>(
    writer: &mut W,
    entry: &CurrentScanEntry,
) -> BatmanResult<WrittenBaselineRecord> {
    let path_text = entry.path.to_string_lossy();
    let path_bytes = path_text.as_bytes();
    let path_len = u32::try_from(path_bytes.len())
        .map_err(|_| BatmanError::Store(format!("path too long: {}", entry.path.display())))?;
    write_u128(writer, entry.path_hash)?;
    writer
        .write_all(&entry.checksum)
        .map_err(|error| BatmanError::io("write baseline checksum", error))?;
    write_metadata(writer, entry.metadata)?;
    write_u32(writer, path_len)?;
    writer
        .write_all(path_bytes)
        .map_err(|error| BatmanError::io("write baseline path", error))?;
    Ok(WrittenBaselineRecord {
        bytes: 16 + 32 + metadata_len() + 4 + u64::from(path_len),
        path_len,
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn recover_interrupted_replace(db_path: &Path) -> BatmanResult<()> {
    let record = db_path.join(RECORD_FILE);
    let index = db_path.join(INDEX_FILE);
    let record_tmp = db_path.join(RECORD_TMP);
    let index_tmp = db_path.join(INDEX_TMP);
    let manifest_tmp = db_path.join(MANIFEST_TMP);
    let record_backup = db_path.join(RECORD_BACKUP);
    let index_backup = db_path.join(INDEX_BACKUP);
    let manifest_backup = db_path.join(MANIFEST_BACKUP);

    if record_backup.exists() || index_backup.exists() || manifest_backup.exists() {
        let final_pair = record.exists() && index.exists() && db_path.join(MANIFEST_FILE).exists();
        let backup_pair =
            record_backup.exists() && index_backup.exists() && manifest_backup.exists();
        if final_pair && backup_pair {
            remove_if_exists(&record_backup)?;
            remove_if_exists(&index_backup)?;
            remove_if_exists(&manifest_backup)?;
            remove_if_exists(&record_tmp)?;
            remove_if_exists(&index_tmp)?;
            remove_if_exists(&manifest_tmp)?;
            return Ok(());
        }

        if record_backup.exists() {
            remove_if_exists(&record)?;
            fs::rename(&record_backup, &record).map_err(|error| {
                BatmanError::io("restore interrupted baseline record file", error)
            })?;
        }
        if index_backup.exists() {
            remove_if_exists(&index)?;
            fs::rename(&index_backup, &index).map_err(|error| {
                BatmanError::io("restore interrupted baseline index file", error)
            })?;
        }
        if manifest_backup.exists() {
            let manifest = db_path.join(MANIFEST_FILE);
            remove_if_exists(&manifest)?;
            fs::rename(&manifest_backup, &manifest).map_err(|error| {
                BatmanError::io("restore interrupted baseline manifest file", error)
            })?;
        }
        remove_if_exists(&record_tmp)?;
        remove_if_exists(&index_tmp)?;
        remove_if_exists(&manifest_tmp)?;
        sync_dir(db_path)?;
        return Ok(());
    }

    let partial_first_baseline = (record.exists()
        && (!index.exists() || !db_path.join(MANIFEST_FILE).exists()))
        || (index.exists() && (!record.exists() || !db_path.join(MANIFEST_FILE).exists()));
    if partial_first_baseline {
        remove_if_exists(&record)?;
        remove_if_exists(&index)?;
        remove_if_exists(&db_path.join(MANIFEST_FILE))?;
        remove_if_exists(&record_tmp)?;
        remove_if_exists(&index_tmp)?;
        remove_if_exists(&manifest_tmp)?;
        sync_dir(db_path)?;
    }
    Ok(())
}

fn remove_stale_tmp(db_path: &Path) -> BatmanResult<()> {
    remove_if_exists(&db_path.join(RECORD_TMP))?;
    remove_if_exists(&db_path.join(INDEX_TMP))?;
    remove_if_exists(&db_path.join(MANIFEST_TMP))
}

fn replace_baseline_files(db_path: &Path, record_tmp: &Path, index_tmp: &Path) -> BatmanResult<()> {
    recover_interrupted_replace(db_path)?;

    let record = db_path.join(RECORD_FILE);
    let index = db_path.join(INDEX_FILE);
    let manifest = db_path.join(MANIFEST_FILE);
    let manifest_tmp = db_path.join(MANIFEST_TMP);
    let record_backup = db_path.join(RECORD_BACKUP);
    let index_backup = db_path.join(INDEX_BACKUP);
    let manifest_backup = db_path.join(MANIFEST_BACKUP);

    remove_if_exists(&record_backup)?;
    remove_if_exists(&index_backup)?;
    remove_if_exists(&manifest_backup)?;

    let existing_pair = record.exists() && index.exists();
    if existing_pair {
        fs::rename(&record, &record_backup)
            .map_err(|error| BatmanError::io("backup baseline record file", error))?;
        fs::rename(&index, &index_backup)
            .map_err(|error| BatmanError::io("backup baseline index file", error))?;
        if manifest.exists() {
            fs::rename(&manifest, &manifest_backup)
                .map_err(|error| BatmanError::io("backup baseline manifest file", error))?;
        }
    }

    fs::rename(record_tmp, &record)
        .map_err(|error| BatmanError::io("replace baseline record file", error))?;
    fs::rename(index_tmp, &index)
        .map_err(|error| BatmanError::io("replace baseline index file", error))?;
    fs::rename(&manifest_tmp, &manifest)
        .map_err(|error| BatmanError::io("replace baseline manifest file", error))?;
    secure_data_file(&record)?;
    secure_data_file(&index)?;
    secure_data_file(&manifest)?;

    remove_if_exists(&record_backup)?;
    remove_if_exists(&index_backup)?;
    remove_if_exists(&manifest_backup)?;
    sync_dir(db_path)
}

fn write_metadata<W: Write>(writer: &mut W, metadata: FileMetadata) -> BatmanResult<()> {
    write_u32(writer, metadata.flags)?;
    write_u64(writer, metadata.size)?;
    write_u64(writer, metadata.permissions)?;
    write_u64(writer, metadata.owner)?;
    write_u64(writer, metadata.group)?;
    write_i128(writer, metadata.modified_ns)?;
    write_i128(writer, metadata.created_ns)?;
    write_i128(writer, metadata.changed_ns)?;
    writer
        .write_all(&metadata.acl_hash)
        .map_err(|error| BatmanError::io("write baseline metadata acl hash", error))
}

fn metadata_len() -> u64 {
    4 + 8 + 8 + 8 + 8 + 16 + 16 + 16 + 32
}

fn remove_if_exists(path: &Path) -> BatmanResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BatmanError::io(format!("remove {}", path.display()), error)),
    }
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> BatmanResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| BatmanError::io(format!("sync {}", path.display()), error))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> BatmanResult<()> {
    Ok(())
}
