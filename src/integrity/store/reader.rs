use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ContentDigest;
use crate::integrity::store::SeenSet;
use crate::integrity::store::format::{
    INDEX_ENTRY_LEN, INDEX_HEADER_LEN, IndexEntry, RecordHeader, read_i128, read_index_entry,
    read_index_header, read_record_header, read_u32, read_u64, read_u128,
};
use crate::integrity::store::hash::path_hash;
use crate::integrity::store::manifest::{
    BaselineManifestInfo, INDEX_FILE, RECORD_FILE, verify_manifest_values_with_public_key,
};
use crate::integrity::store::metadata::FileMetadata;
use crate::integrity::store::writer::recover_interrupted_replace;

const INDEX_PAGE_ENTRIES: u64 = 16_384;
const INDEX_CACHE_PAGES: usize = 64;
const RECORD_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct BaselineRecord {
    pub path_hash: u128,
    pub path: PathBuf,
    pub checksum: ContentDigest,
    pub metadata: FileMetadata,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum LookupResult {
    Found {
        ordinal: u64,
        record: BaselineRecord,
    },
    Missing,
}

pub struct BaselineReader {
    records: BufReader<File>,
    index: File,
    index_records: u64,
    index_cache: IndexPageCache,
    record_header: RecordHeader,
    manifest_info: BaselineManifestInfo,
    stream_ordinal: u64,
}

struct IndexPageCache {
    pages: Vec<IndexPage>,
}

struct IndexPage {
    start: u64,
    entries: Vec<IndexEntry>,
}

impl BaselineReader {
    pub fn open(db_path: &Path) -> BatmanResult<Self> {
        Self::open_with_public_key(db_path, None)
    }

    pub fn open_with_public_key(
        db_path: &Path,
        configured_public_key: Option<&str>,
    ) -> BatmanResult<Self> {
        recover_interrupted_replace(db_path)?;
        let record_path = db_path.join(RECORD_FILE);
        let index_path = db_path.join(INDEX_FILE);
        if !record_path.exists() || !index_path.exists() {
            return Err(BatmanError::Store(format!(
                "no baseline exists. Expected {} and {}. Run 'batman baseline' first",
                record_path.display(),
                index_path.display()
            )));
        }
        let record_file = File::open(&record_path)
            .map_err(|error| BatmanError::io(format!("open {}", record_path.display()), error))?;
        let mut records = BufReader::with_capacity(RECORD_BUFFER_SIZE, record_file);
        let index_file = File::open(&index_path)
            .map_err(|error| BatmanError::io(format!("open {}", index_path.display()), error))?;
        let mut index_reader = BufReader::new(index_file);
        let record_header = read_record_header(&mut records)?;
        let index_header = read_index_header(&mut index_reader)?;
        if record_header.records != index_header.records {
            return Err(BatmanError::Store(
                "baseline record and index counts differ".to_string(),
            ));
        }
        let manifest_info = verify_manifest_values_with_public_key(
            db_path,
            record_header.records,
            record_header.scan_byte_limit,
            record_header.config_hash,
            configured_public_key,
        )?;
        let mut index = index_reader.into_inner();
        index
            .seek(SeekFrom::Start(INDEX_HEADER_LEN))
            .map_err(|error| BatmanError::io("seek baseline index", error))?;
        Ok(Self {
            records,
            index,
            index_records: index_header.records,
            index_cache: IndexPageCache::new(),
            record_header,
            manifest_info,
            stream_ordinal: 0,
        })
    }

    pub fn record_count(&self) -> u64 {
        self.index_records
    }

    pub fn scan_byte_limit(&self) -> u64 {
        self.record_header.scan_byte_limit
    }

    pub fn config_hash(&self) -> [u8; 32] {
        self.record_header.config_hash
    }

    pub fn manifest_info(&self) -> BaselineManifestInfo {
        self.manifest_info
    }

    pub fn path_hash_at(&mut self, ordinal: u64) -> BatmanResult<u128> {
        Ok(self.read_index_at(ordinal)?.path_hash)
    }

    pub fn record_at(&mut self, ordinal: u64) -> BatmanResult<BaselineRecord> {
        let entry = self.read_index_at(ordinal)?;
        self.read_record(&entry)
    }

    pub fn next_record(&mut self) -> BatmanResult<Option<BaselineRecord>> {
        if self.stream_ordinal >= self.record_count() {
            return Ok(None);
        }
        let record = self.read_record_at_current()?;
        self.stream_ordinal += 1;
        Ok(Some(record))
    }

    pub fn lookup(&mut self, path: &Path) -> BatmanResult<LookupResult> {
        let path_text = path.to_string_lossy();
        let path_bytes = path_text.as_bytes();
        let hash = path_hash(path_bytes);
        let mut ordinal = self.lower_bound(hash)?;

        while ordinal < self.record_count() {
            let entry = self.read_index_at(ordinal)?;
            if entry.path_hash != hash {
                break;
            }
            let record = self.read_record(&entry)?;
            if record.path.to_string_lossy().as_bytes() == path_bytes {
                return Ok(LookupResult::Found { ordinal, record });
            }
            ordinal += 1;
        }

        Ok(LookupResult::Missing)
    }

    pub fn visit_unseen_paths<F>(&mut self, seen: &SeenSet, mut visitor: F) -> BatmanResult<()>
    where
        F: FnMut(PathBuf) -> BatmanResult<()>,
    {
        for ordinal in 0..self.record_count() {
            if !seen.contains(ordinal) {
                let entry = self.read_index_at(ordinal)?;
                visitor(self.read_record(&entry)?.path)?;
            }
        }
        Ok(())
    }

    fn lower_bound(&mut self, hash: u128) -> BatmanResult<u64> {
        let mut low = 0;
        let mut high = self.record_count();
        while low < high {
            let mid = low + (high - low) / 2;
            let entry = self.read_index_at(mid)?;
            if entry.path_hash < hash {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        Ok(low)
    }

    fn read_index_at(&mut self, ordinal: u64) -> BatmanResult<IndexEntry> {
        if ordinal >= self.index_records {
            return Err(BatmanError::Store(format!(
                "baseline index ordinal out of range: {ordinal}"
            )));
        }
        let page_start = (ordinal / INDEX_PAGE_ENTRIES) * INDEX_PAGE_ENTRIES;
        if let Some(entry) = self.index_cache.entry(page_start, ordinal) {
            return Ok(entry);
        }
        self.load_index_page(page_start)?;
        self.index_cache.entry(page_start, ordinal).ok_or_else(|| {
            BatmanError::Store(format!("baseline index ordinal out of range: {ordinal}"))
        })
    }

    fn load_index_page(&mut self, start: u64) -> BatmanResult<()> {
        let remaining = self.index_records.saturating_sub(start);
        let count = remaining.min(INDEX_PAGE_ENTRIES);
        let offset = INDEX_HEADER_LEN + start * INDEX_ENTRY_LEN;
        self.index
            .seek(SeekFrom::Start(offset))
            .map_err(|error| BatmanError::io("seek baseline index", error))?;
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            entries.push(read_index_entry(&mut self.index)?);
        }
        self.index_cache.insert(IndexPage { start, entries });
        Ok(())
    }

    fn read_record(&mut self, entry: &IndexEntry) -> BatmanResult<BaselineRecord> {
        self.records
            .seek(SeekFrom::Start(entry.offset))
            .map_err(|error| BatmanError::io("seek baseline record", error))?;
        let record = self.read_record_at_current()?;
        if record.path_hash != entry.path_hash {
            return Err(BatmanError::Store(
                "baseline path hash mismatch".to_string(),
            ));
        }
        let path_len = record.path.to_string_lossy().len() as u32;
        if path_len != entry.path_len {
            return Err(BatmanError::Store(
                "baseline path length mismatch".to_string(),
            ));
        }
        Ok(record)
    }

    fn read_record_at_current(&mut self) -> BatmanResult<BaselineRecord> {
        let path_hash = read_u128(&mut self.records)?;
        let mut checksum = [0_u8; 32];
        self.records
            .read_exact(&mut checksum)
            .map_err(|error| BatmanError::io("read baseline checksum", error))?;
        let metadata = read_metadata(&mut self.records)?;
        let path_len = read_u32(&mut self.records)?;
        let mut path_bytes = vec![0_u8; path_len as usize];
        self.records
            .read_exact(&mut path_bytes)
            .map_err(|error| BatmanError::io("read baseline path", error))?;
        let path = String::from_utf8(path_bytes)
            .map_err(|_| BatmanError::Store("baseline path is not UTF-8".to_string()))?;
        Ok(BaselineRecord {
            path_hash,
            path: PathBuf::from(path),
            checksum,
            metadata,
        })
    }
}

fn read_metadata<R: Read>(reader: &mut R) -> BatmanResult<FileMetadata> {
    let mut acl_hash = [0_u8; 32];
    let flags = read_u32(reader)?;
    let size = read_u64(reader)?;
    let permissions = read_u64(reader)?;
    let owner = read_u64(reader)?;
    let group = read_u64(reader)?;
    let modified_ns = read_i128(reader)?;
    let created_ns = read_i128(reader)?;
    let changed_ns = read_i128(reader)?;
    reader
        .read_exact(&mut acl_hash)
        .map_err(|error| BatmanError::io("read baseline metadata acl hash", error))?;
    Ok(FileMetadata {
        flags,
        size,
        permissions,
        owner,
        group,
        modified_ns,
        created_ns,
        changed_ns,
        acl_hash,
    })
}

impl IndexPageCache {
    fn new() -> Self {
        Self { pages: Vec::new() }
    }

    fn entry(&mut self, start: u64, ordinal: u64) -> Option<IndexEntry> {
        let index = self.pages.iter().position(|page| page.start == start)?;
        let page = self.pages.remove(index);
        let entry = page.entries.get((ordinal - start) as usize).cloned();
        self.pages.push(page);
        entry
    }

    fn insert(&mut self, page: IndexPage) {
        if self.pages.len() >= INDEX_CACHE_PAGES {
            self.pages.remove(0);
        }
        self.pages.push(page);
    }
}
