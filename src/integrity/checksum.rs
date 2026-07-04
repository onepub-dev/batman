use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ContentDigest;
use crate::integrity::perf_trace;

pub(crate) const DEFAULT_BUFFER_SIZE: usize = 256 * 1024;

pub fn content_checksum(path: &Path, byte_limit: u64) -> BatmanResult<ContentDigest> {
    let mut buffer = vec![0_u8; DEFAULT_BUFFER_SIZE];
    content_checksum_with_buffer(path, byte_limit, &mut buffer)
}

pub(crate) fn content_checksum_with_buffer(
    path: &Path,
    byte_limit: u64,
    buffer: &mut [u8],
) -> BatmanResult<ContentDigest> {
    content_checksum_with_buffer_and_trace_detail(path, byte_limit, buffer, path.display())
}

pub(crate) fn content_checksum_with_buffer_and_trace_detail(
    path: &Path,
    byte_limit: u64,
    buffer: &mut [u8],
    trace_detail: impl fmt::Display,
) -> BatmanResult<ContentDigest> {
    let started = perf_trace::enabled().then(Instant::now);
    let mut file = File::open(path)
        .map_err(|error| BatmanError::io(format!("open {}", path.display()), error))?;
    let mut hasher = blake3::Hasher::new();

    hash_file_content(&mut file, path, byte_limit, buffer, &mut hasher)?;
    hash_platform_extra_streams(path, byte_limit, buffer, &mut hasher)?;

    let checksum = *hasher.finalize().as_bytes();
    if let Some(started) = started {
        perf_trace::event("hash", trace_detail, started.elapsed());
    }
    Ok(checksum)
}

fn hash_file_content(
    file: &mut File,
    path: &Path,
    byte_limit: u64,
    buffer: &mut [u8],
    hasher: &mut blake3::Hasher,
) -> BatmanResult<bool> {
    let mut remaining = if byte_limit == 0 {
        u64::MAX
    } else {
        byte_limit
    };
    let mut read_any = false;
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..read_limit])
            .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
        if read == 0 {
            break;
        }
        read_any = true;
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(read_any)
}

#[cfg(not(windows))]
fn hash_platform_extra_streams(
    _path: &Path,
    _byte_limit: u64,
    _buffer: &mut [u8],
    _hasher: &mut blake3::Hasher,
) -> BatmanResult<()> {
    Ok(())
}

#[cfg(windows)]
fn hash_platform_extra_streams(
    path: &Path,
    byte_limit: u64,
    buffer: &mut [u8],
    hasher: &mut blake3::Hasher,
) -> BatmanResult<()> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };

    let mut wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide_path.push(0);
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let handle = unsafe {
        FindFirstStreamW(
            wide_path.as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Ok(());
    }

    loop {
        let name = stream_name(&data.cStreamName);
        if !is_default_data_stream(&name) {
            hasher.update(b"BATMAN:ADS");
            let stream_name = name
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            hasher.update(&(stream_name.len() as u64).to_le_bytes());
            hasher.update(&stream_name);

            let mut stream_path = path.as_os_str().to_os_string();
            stream_path.push(&name);
            let mut stream = File::open(&stream_path).map_err(|error| {
                BatmanError::io(
                    format!("open ADS {}", Path::new(&stream_path).display()),
                    error,
                )
            })?;
            hash_file_content(
                &mut stream,
                Path::new(&stream_path),
                byte_limit,
                buffer,
                hasher,
            )?;
        }

        let ok =
            unsafe { FindNextStreamW(handle, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            unsafe {
                FindClose(handle);
            }
            if error == ERROR_HANDLE_EOF {
                return Ok(());
            }
            return Err(BatmanError::io(
                format!("enumerate ADS {}", path.display()),
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
    }

    fn stream_name(wide: &[u16]) -> OsString {
        let len = wide
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(wide.len());
        OsString::from_wide(&wide[..len])
    }
}

#[cfg(windows)]
fn is_default_data_stream(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().eq_ignore_ascii_case("::$DATA")
}

pub fn processed_byte_count(size: u64, byte_limit: u64) -> u64 {
    if byte_limit == 0 {
        size
    } else {
        size.min(byte_limit)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::time::Instant;

    use super::{content_checksum, content_checksum_with_buffer, processed_byte_count};

    #[test]
    fn checksum_hashes_bytes_up_to_limit() {
        let path = std::env::temp_dir().join(format!("batman-checksum-{}", std::process::id()));
        fs::write(&path, [1_u8, 2, 3, 4]).unwrap();

        let prefix_hash = content_checksum(&path, 2).unwrap();
        let full_hash = content_checksum(&path, 100).unwrap();

        assert_eq!(prefix_hash, *blake3::hash(&[1_u8, 2]).as_bytes());
        assert_eq!(full_hash, *blake3::hash(&[1_u8, 2, 3, 4]).as_bytes());
        assert_eq!(content_checksum(&path, 0).unwrap(), full_hash);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn zero_scan_limit_means_whole_file_for_progress() {
        assert_eq!(processed_byte_count(123, 0), 123);
        assert_eq!(processed_byte_count(123, 50), 50);
        assert_eq!(processed_byte_count(123, 500), 123);
    }

    #[test]
    #[ignore = "large checksum buffer benchmark"]
    fn synthetic_large_file_checksum_buffer_experiment() {
        let bytes = std::env::var("BATMAN_CHECKSUM_BENCH_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(256 * 1024 * 1024);
        let path = std::env::temp_dir().join(format!(
            "batman-checksum-buffer-bench-{}",
            std::process::id()
        ));

        let mut file = File::create(&path).unwrap();
        let chunk = vec![0_u8; 1024 * 1024];
        let mut written = 0_u64;
        while written < bytes {
            let write_len = (bytes - written).min(chunk.len() as u64) as usize;
            file.write_all(&chunk[..write_len]).unwrap();
            written += write_len as u64;
        }
        file.sync_all().unwrap();
        drop(file);

        for buffer_size in [64 * 1024, 256 * 1024, 1024 * 1024] {
            let mut buffer = vec![0_u8; buffer_size];
            let started = Instant::now();
            let checksum = content_checksum_with_buffer(&path, 0, &mut buffer).unwrap();
            let elapsed = started.elapsed();
            let mbps = bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
            println!(
                "bytes={bytes} buffer={buffer_size} elapsed={elapsed:?} throughput={mbps:.1}MiB/s checksum_prefix={:02x}{:02x}",
                checksum[0], checksum[1]
            );
        }

        fs::remove_file(path).unwrap();
    }
}
