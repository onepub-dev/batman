use std::io::{Read, Write};

use crate::errors::{BatmanError, BatmanResult};

pub const RECORD_MAGIC: &[u8; 8] = b"BATBFI\0\x01";
pub const INDEX_MAGIC: &[u8; 8] = b"BATIDX\0\x01";
pub const VERSION: u16 = 1;
pub const RECORD_HEADER_LEN: u64 = 68;
pub const INDEX_HEADER_LEN: u64 = 20;
pub const INDEX_ENTRY_LEN: u64 = 28;

#[derive(Clone, Debug)]
pub struct RecordHeader {
    pub created: i64,
    pub scan_byte_limit: u64,
    pub config_hash: [u8; 32],
    pub records: u64,
}

#[derive(Clone, Debug)]
pub struct IndexHeader {
    pub records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexEntry {
    pub path_hash: u128,
    pub offset: u64,
    pub path_len: u32,
}

pub fn write_record_header<W: Write>(writer: &mut W, header: &RecordHeader) -> BatmanResult<()> {
    writer.write_all(RECORD_MAGIC).map_err(write_error)?;
    write_u16(writer, VERSION)?;
    write_u16(writer, 0)?;
    write_i64(writer, header.created)?;
    write_u64(writer, header.scan_byte_limit)?;
    writer.write_all(&header.config_hash).map_err(write_error)?;
    write_u64(writer, header.records)
}

pub fn read_record_header<R: Read>(reader: &mut R) -> BatmanResult<RecordHeader> {
    let mut magic = [0_u8; 8];
    reader.read_exact(&mut magic).map_err(read_error)?;
    if &magic != RECORD_MAGIC {
        return Err(BatmanError::Store(
            "invalid baseline record file".to_string(),
        ));
    }
    let version = read_u16(reader)?;
    if version != VERSION {
        return Err(BatmanError::Store(format!(
            "unsupported baseline version {version}"
        )));
    }
    let _flags = read_u16(reader)?;
    Ok(RecordHeader {
        created: read_i64(reader)?,
        scan_byte_limit: read_u64(reader)?,
        config_hash: {
            let mut hash = [0_u8; 32];
            reader.read_exact(&mut hash).map_err(read_error)?;
            hash
        },
        records: read_u64(reader)?,
    })
}

pub fn write_index_header<W: Write>(writer: &mut W, header: &IndexHeader) -> BatmanResult<()> {
    writer.write_all(INDEX_MAGIC).map_err(write_error)?;
    write_u16(writer, VERSION)?;
    write_u16(writer, 0)?;
    write_u64(writer, header.records)
}

pub fn read_index_header<R: Read>(reader: &mut R) -> BatmanResult<IndexHeader> {
    let mut magic = [0_u8; 8];
    reader.read_exact(&mut magic).map_err(read_error)?;
    if &magic != INDEX_MAGIC {
        return Err(BatmanError::Store(
            "invalid baseline index file".to_string(),
        ));
    }
    let version = read_u16(reader)?;
    if version != VERSION {
        return Err(BatmanError::Store(format!(
            "unsupported index version {version}"
        )));
    }
    let _fanout = read_u16(reader)?;
    Ok(IndexHeader {
        records: read_u64(reader)?,
    })
}

pub fn write_index_entry<W: Write>(writer: &mut W, entry: &IndexEntry) -> BatmanResult<()> {
    write_u128(writer, entry.path_hash)?;
    write_u64(writer, entry.offset)?;
    write_u32(writer, entry.path_len)
}

pub fn read_index_entry<R: Read>(reader: &mut R) -> BatmanResult<IndexEntry> {
    Ok(IndexEntry {
        path_hash: read_u128(reader)?,
        offset: read_u64(reader)?,
        path_len: read_u32(reader)?,
    })
}

pub fn write_u32<W: Write>(writer: &mut W, value: u32) -> BatmanResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(write_error)
}

pub fn write_u64<W: Write>(writer: &mut W, value: u64) -> BatmanResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(write_error)
}

pub fn write_i64<W: Write>(writer: &mut W, value: i64) -> BatmanResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(write_error)
}

pub fn write_i128<W: Write>(writer: &mut W, value: i128) -> BatmanResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(write_error)
}

pub fn write_u128<W: Write>(writer: &mut W, value: u128) -> BatmanResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(write_error)
}

pub fn read_u32<R: Read>(reader: &mut R) -> BatmanResult<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn read_u64<R: Read>(reader: &mut R) -> BatmanResult<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn read_i64<R: Read>(reader: &mut R) -> BatmanResult<i64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(i64::from_le_bytes(bytes))
}

pub fn read_i128<R: Read>(reader: &mut R) -> BatmanResult<i128> {
    let mut bytes = [0_u8; 16];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(i128::from_le_bytes(bytes))
}

fn read_u16<R: Read>(reader: &mut R) -> BatmanResult<u16> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(u16::from_le_bytes(bytes))
}

pub fn read_u128<R: Read>(reader: &mut R) -> BatmanResult<u128> {
    let mut bytes = [0_u8; 16];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(u128::from_le_bytes(bytes))
}

fn write_u16<W: Write>(writer: &mut W, value: u16) -> BatmanResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(write_error)
}

fn read_error(error: std::io::Error) -> BatmanError {
    BatmanError::io("read baseline store", error)
}

fn write_error(error: std::io::Error) -> BatmanError {
    BatmanError::io("write baseline store", error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_header_len_matches_serialized_header() {
        let mut bytes = Vec::new();
        write_record_header(
            &mut bytes,
            &RecordHeader {
                created: 1,
                scan_byte_limit: 0,
                config_hash: [3; 32],
                records: 2,
            },
        )
        .unwrap();
        assert_eq!(bytes.len() as u64, RECORD_HEADER_LEN);
    }
}
