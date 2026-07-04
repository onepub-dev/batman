use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ContentDigest;
use crate::integrity::perf_trace;
use crate::integrity::store::format::{
    read_i128, read_u32, read_u64, read_u128, write_i128, write_u32, write_u64, write_u128,
};
use crate::integrity::store::hash::path_hash;
use crate::integrity::store::metadata::FileMetadata;

pub(crate) const DEFAULT_CHUNK_LIMIT: usize = 16_384;
const CHUNK_WRITE_BUFFER_SIZE: usize = 256 * 1024;
const CHUNK_READ_BUFFER_SIZE: usize = 32 * 1024;

#[derive(Clone, Debug)]
pub struct CurrentScanEntry {
    pub path_hash: u128,
    pub path: PathBuf,
    pub checksum: ContentDigest,
    pub metadata: FileMetadata,
}

pub struct CurrentScanSpool {
    db_path: PathBuf,
    chunk_limit: usize,
    entries: Vec<CurrentScanEntry>,
    chunks: Vec<Chunk>,
    chunk_bytes: u64,
}

pub struct CurrentScanReader {
    memory: Vec<CurrentScanEntry>,
    memory_index: usize,
    readers: Vec<ChunkReader>,
    heap: BinaryHeap<HeapEntry>,
}

struct Chunk {
    path: PathBuf,
    count: u64,
}

struct ChunkReader {
    path: PathBuf,
    reader: BufReader<File>,
    remaining: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeapEntry {
    entry: CurrentScanEntry,
    chunk_index: usize,
}

impl CurrentScanSpool {
    pub fn new(db_path: &Path) -> Self {
        Self::with_chunk_limit(db_path, DEFAULT_CHUNK_LIMIT)
    }

    pub fn with_chunk_limit(db_path: &Path, chunk_limit: usize) -> Self {
        Self {
            db_path: db_path.to_path_buf(),
            chunk_limit: chunk_limit.max(1),
            entries: Vec::new(),
            chunks: Vec::new(),
            chunk_bytes: 0,
        }
    }

    pub fn progress_counters(&self) -> (u64, u64) {
        (self.chunks.len() as u64, self.chunk_bytes)
    }

    pub fn record_count(&self) -> u64 {
        self.entries.len() as u64 + self.chunks.iter().map(|chunk| chunk.count).sum::<u64>()
    }

    pub fn push(
        &mut self,
        path: &Path,
        checksum: ContentDigest,
        size: u64,
        modified_ns: i128,
    ) -> BatmanResult<()> {
        self.push_with_metadata(
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

    pub fn push_with_metadata(
        &mut self,
        path: &Path,
        checksum: ContentDigest,
        metadata: FileMetadata,
    ) -> BatmanResult<()> {
        let path_text = path.to_string_lossy();
        self.push_with_sort_key(path_hash(path_text.as_bytes()), path, checksum, metadata)
    }

    pub(crate) fn push_with_sort_key(
        &mut self,
        sort_key: u128,
        path: &Path,
        checksum: ContentDigest,
        metadata: FileMetadata,
    ) -> BatmanResult<()> {
        self.entries.push(CurrentScanEntry {
            path_hash: sort_key,
            path: path.to_path_buf(),
            checksum,
            metadata,
        });
        if self.entries.len() >= self.chunk_limit {
            self.flush_chunk()?;
        }
        Ok(())
    }

    pub fn into_reader(mut self) -> BatmanResult<CurrentScanReader> {
        if self.chunks.is_empty() {
            sort_entries(&mut self.entries);
            return Ok(CurrentScanReader::from_memory(self.entries));
        }

        self.flush_chunk()?;
        let mut readers = self.open_chunk_readers()?;
        let mut heap = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            if let Some(entry) = reader.next_entry()? {
                heap.push(HeapEntry {
                    entry,
                    chunk_index: index,
                });
            }
        }
        Ok(CurrentScanReader {
            memory: Vec::new(),
            memory_index: 0,
            readers,
            heap,
        })
    }

    fn flush_chunk(&mut self) -> BatmanResult<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let started = perf_trace::enabled().then(Instant::now);
        let entry_count = self.entries.len();
        let chunk_index = self.chunks.len();
        sort_entries(&mut self.entries);
        let path = self
            .db_path
            .join(format!("current_scan.chunk.{}", self.chunks.len()));
        let file = File::create(&path)
            .map_err(|error| BatmanError::io(format!("create {}", path.display()), error))?;
        let mut writer = BufWriter::with_capacity(CHUNK_WRITE_BUFFER_SIZE, file);
        for entry in &self.entries {
            write_entry(&mut writer, entry)?;
        }
        writer
            .into_inner()
            .map_err(|error| BatmanError::io("flush current scan chunk", error.into_error()))?;
        self.chunks.push(Chunk {
            path,
            count: self.entries.len() as u64,
        });
        self.chunk_bytes += self.entries.iter().map(current_scan_entry_len).sum::<u64>();
        self.entries.clear();
        if let Some(started) = started {
            perf_trace::event(
                "spool-flush",
                format!("chunk={chunk_index} entries={entry_count}"),
                started.elapsed(),
            );
        }
        Ok(())
    }

    fn open_chunk_readers(&self) -> BatmanResult<Vec<ChunkReader>> {
        self.chunks
            .iter()
            .map(|chunk| {
                let file = File::open(&chunk.path).map_err(|error| {
                    BatmanError::io(format!("open {}", chunk.path.display()), error)
                })?;
                Ok(ChunkReader {
                    path: chunk.path.clone(),
                    reader: BufReader::with_capacity(CHUNK_READ_BUFFER_SIZE, file),
                    remaining: chunk.count,
                })
            })
            .collect()
    }
}

impl CurrentScanReader {
    fn from_memory(memory: Vec<CurrentScanEntry>) -> Self {
        Self {
            memory,
            memory_index: 0,
            readers: Vec::new(),
            heap: BinaryHeap::new(),
        }
    }

    pub fn next_entry(&mut self) -> BatmanResult<Option<CurrentScanEntry>> {
        if self.readers.is_empty() {
            let entry = self.memory.get(self.memory_index).cloned();
            if entry.is_some() {
                self.memory_index += 1;
            }
            return Ok(entry);
        }

        let Some(heap_entry) = self.heap.pop() else {
            return Ok(None);
        };
        if let Some(next) = self.readers[heap_entry.chunk_index].next_entry()? {
            self.heap.push(HeapEntry {
                entry: next,
                chunk_index: heap_entry.chunk_index,
            });
        }
        Ok(Some(heap_entry.entry))
    }
}

impl Drop for CurrentScanReader {
    fn drop(&mut self) {
        for reader in &self.readers {
            let _ = fs::remove_file(reader.chunk_path());
        }
    }
}

impl ChunkReader {
    fn next_entry(&mut self) -> BatmanResult<Option<CurrentScanEntry>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        match read_entry(&mut self.reader) {
            Ok(entry) => {
                self.remaining -= 1;
                Ok(Some(entry))
            }
            Err(BatmanError::Io { source, .. }) if source.kind() == ErrorKind::UnexpectedEof => {
                Err(BatmanError::Store(
                    "truncated current scan chunk".to_string(),
                ))
            }
            Err(error) => Err(error),
        }
    }

    fn chunk_path(&self) -> &Path {
        &self.path
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .entry
            .path_hash
            .cmp(&self.entry.path_hash)
            .then_with(|| other.entry.path.cmp(&self.entry.path))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CurrentScanEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path_hash
            .cmp(&other.path_hash)
            .then_with(|| self.path.cmp(&other.path))
    }
}

impl PartialOrd for CurrentScanEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CurrentScanEntry {
    fn eq(&self, other: &Self) -> bool {
        self.path_hash == other.path_hash && self.path == other.path
    }
}

impl Eq for CurrentScanEntry {}

fn sort_entries(entries: &mut [CurrentScanEntry]) {
    entries.sort();
}

fn write_entry<W: Write>(writer: &mut W, entry: &CurrentScanEntry) -> BatmanResult<()> {
    let path_text = entry.path.to_string_lossy();
    let path_bytes = path_text.as_bytes();
    let path_len = u32::try_from(path_bytes.len())
        .map_err(|_| BatmanError::Store(format!("path too long: {}", entry.path.display())))?;
    write_u128(writer, entry.path_hash)?;
    writer
        .write_all(&entry.checksum)
        .map_err(|error| BatmanError::io("write current scan checksum", error))?;
    write_metadata(writer, entry.metadata)?;
    write_u32(writer, path_len)?;
    writer
        .write_all(path_bytes)
        .map_err(|error| BatmanError::io("write current scan path", error))
}

fn current_scan_entry_len(entry: &CurrentScanEntry) -> u64 {
    let path_len = entry.path.to_string_lossy().len() as u64;
    16 + 32 + metadata_len() + 4 + path_len
}

fn read_entry<R: Read>(reader: &mut R) -> BatmanResult<CurrentScanEntry> {
    let path_hash = read_u128(reader)?;
    let mut checksum = [0_u8; 32];
    reader
        .read_exact(&mut checksum)
        .map_err(|error| BatmanError::io("read current scan checksum", error))?;
    let metadata = read_metadata(reader)?;
    let path_len = read_u32(reader)?;
    let mut path_bytes = vec![0_u8; path_len as usize];
    reader
        .read_exact(&mut path_bytes)
        .map_err(|error| BatmanError::io("read current scan path", error))?;
    let path = String::from_utf8(path_bytes)
        .map_err(|_| BatmanError::Store("current scan path is not UTF-8".to_string()))?;
    Ok(CurrentScanEntry {
        path_hash,
        path: PathBuf::from(path),
        checksum,
        metadata,
    })
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
        .map_err(|error| BatmanError::io("write current scan metadata acl hash", error))
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
        .map_err(|error| BatmanError::io("read current scan metadata acl hash", error))?;
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

fn metadata_len() -> u64 {
    4 + 8 + 8 + 8 + 8 + 16 + 16 + 16 + 32
}

#[cfg(test)]
mod tests {
    use super::{CHUNK_READ_BUFFER_SIZE, DEFAULT_CHUNK_LIMIT};

    #[test]
    fn merge_reader_buffer_stays_small_for_many_chunks() {
        const { assert!(DEFAULT_CHUNK_LIMIT <= 16_384) };
        const { assert!(CHUNK_READ_BUFFER_SIZE <= 32 * 1024) };
    }
}
