use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::{BatmanError, BatmanResult};
use crate::security::{env_flag_enabled, secure_data_file};

const AUDIT_FILE: &str = "audit.log";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const AUDIT_TCP_ENV: &str = "BATMAN_AUDIT_TCP";
pub const AUDIT_SYSLOG_ENV: &str = "BATMAN_AUDIT_SYSLOG";
pub const AUDIT_SINK_REQUIRED_ENV: &str = "BATMAN_AUDIT_SINK_REQUIRED";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditVerification {
    pub events: u64,
    pub last_hash: String,
}

pub fn audit_path(db_path: &Path) -> PathBuf {
    db_path.join(AUDIT_FILE)
}

pub fn append_event(db_path: &Path, action: &str, fields: &[(&str, String)]) -> BatmanResult<()> {
    fs::create_dir_all(db_path)
        .map_err(|error| BatmanError::io(format!("create {}", db_path.display()), error))?;
    let path = audit_path(db_path);
    let previous_hash = verify_audit_log(&path)
        .map(|verification| verification.last_hash)
        .or_else(|error| {
            if path.exists() {
                Err(error)
            } else {
                Ok(GENESIS_HASH.to_string())
            }
        })?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| BatmanError::io(format!("open {}", path.display()), error))?;
    secure_data_file(&path)?;
    let mut line = String::new();
    line.push('{');
    push_field(
        &mut line,
        "timestamp_unix_ms",
        unix_millis().to_string(),
        false,
        false,
    );
    push_field(&mut line, "action", action.to_string(), true, true);
    push_field(
        &mut line,
        "pid",
        std::process::id().to_string(),
        false,
        true,
    );
    push_field(&mut line, "previous_hash", previous_hash, true, true);
    for (key, value) in fields {
        push_field(&mut line, key, value.clone(), true, true);
    }
    line.push('}');
    let event_hash = hash_hex(line.as_bytes());
    line.pop();
    push_field(&mut line, "hash", event_hash, true, true);
    line.push_str("}\n");
    file.write_all(line.as_bytes())
        .map_err(|error| BatmanError::io(format!("write {}", path.display()), error))?;
    file.flush()
        .map_err(|error| BatmanError::io(format!("flush {}", path.display()), error))?;
    forward_event(&line)
}

pub fn verify_audit_log(path: &Path) -> BatmanResult<AuditVerification> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuditVerification {
                events: 0,
                last_hash: GENESIS_HASH.to_string(),
            });
        }
        Err(error) => return Err(BatmanError::io(format!("open {}", path.display()), error)),
    };
    let reader = BufReader::new(file);
    let mut previous_hash = GENESIS_HASH.to_string();
    let mut events = 0_u64;
    for (index, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
        if line.trim().is_empty() {
            continue;
        }
        let previous = json_string_field(&line, "previous_hash").ok_or_else(|| {
            BatmanError::Store(format!(
                "audit log line {} is missing previous_hash",
                index + 1
            ))
        })?;
        if previous != previous_hash {
            return Err(BatmanError::Store(format!(
                "audit log chain mismatch on line {}",
                index + 1
            )));
        }
        let hash = json_string_field(&line, "hash").ok_or_else(|| {
            BatmanError::Store(format!("audit log line {} is missing hash", index + 1))
        })?;
        let payload = audit_payload_without_hash(&line).ok_or_else(|| {
            BatmanError::Store(format!(
                "audit log line {} has an unsupported hash layout",
                index + 1
            ))
        })?;
        let expected = hash_hex(payload.as_bytes());
        if hash != expected {
            return Err(BatmanError::Store(format!(
                "audit log hash mismatch on line {}",
                index + 1
            )));
        }
        previous_hash = hash;
        events += 1;
    }
    Ok(AuditVerification {
        events,
        last_hash: previous_hash,
    })
}

fn push_field(line: &mut String, key: &str, value: String, quote_value: bool, comma: bool) {
    if comma {
        line.push(',');
    }
    line.push('"');
    line.push_str(&escape_json(key));
    line.push_str("\":");
    if quote_value {
        line.push('"');
        line.push_str(&escape_json(&value));
        line.push('"');
    } else {
        line.push_str(&value);
    }
}

fn escape_json(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", ch as u32);
            }
            ch => output.push(ch),
        }
    }
    output
}

fn audit_payload_without_hash(line: &str) -> Option<String> {
    let marker = ",\"hash\":\"";
    let index = line.rfind(marker)?;
    if !line.ends_with("\"}") {
        return None;
    }
    let mut payload = String::with_capacity(index + 1);
    payload.push_str(&line[..index]);
    payload.push('}');
    Some(payload)
}

fn json_string_field(line: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let start = line.find(&marker)? + marker.len();
    let mut output = String::new();
    let mut chars = line[start..].chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Some(output),
            '\\' => match chars.next()? {
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                other => output.push(other),
            },
            ch => output.push(ch),
        }
    }
    None
}

fn hash_hex(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    let mut output = String::with_capacity(64);
    for byte in hash.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn forward_event(line: &str) -> BatmanResult<()> {
    let mut errors = Vec::new();
    if env_flag_enabled(AUDIT_SYSLOG_ENV)
        && let Err(error) = send_syslog(line.trim_end())
    {
        errors.push(error.to_string());
    }
    if let Ok(address) = std::env::var(AUDIT_TCP_ENV) {
        let address = address.trim();
        if !address.is_empty()
            && let Err(error) = send_tcp(address, line)
        {
            errors.push(error.to_string());
        }
    }
    if !errors.is_empty() && env_flag_enabled(AUDIT_SINK_REQUIRED_ENV) {
        return Err(BatmanError::Config(format!(
            "audit forwarding failed: {}",
            errors.join("; ")
        )));
    }
    Ok(())
}

fn send_tcp(address: &str, line: &str) -> BatmanResult<()> {
    let mut addrs = address
        .to_socket_addrs()
        .map_err(|error| BatmanError::io(format!("resolve audit sink {address}"), error))?;
    let Some(addr) = addrs.next() else {
        return Err(BatmanError::Config(format!(
            "audit sink {address} did not resolve"
        )));
    };
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|error| BatmanError::io(format!("connect audit sink {address}"), error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| BatmanError::io("set audit sink write timeout", error))?;
    stream
        .write_all(line.as_bytes())
        .map_err(|error| BatmanError::io("write audit sink event", error))
}

#[cfg(unix)]
fn send_syslog(line: &str) -> BatmanResult<()> {
    use std::ffi::CString;

    let ident = CString::new("batman").expect("static syslog ident has no NUL");
    let message = CString::new(line).map_err(|error| {
        BatmanError::Config(format!("audit syslog message contains NUL byte: {error}"))
    })?;
    unsafe {
        libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_AUTH);
        libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), message.as_ptr());
        libc::closelog();
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_syslog(_line: &str) -> BatmanResult<()> {
    Err(BatmanError::Config(
        "BATMAN_AUDIT_SYSLOG is only supported on Unix".to_string(),
    ))
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    use crate::test_support::env_lock;

    use super::{
        AUDIT_SINK_REQUIRED_ENV, AUDIT_TCP_ENV, append_event, audit_path, verify_audit_log,
    };

    #[test]
    fn audit_events_are_json_lines_with_escaped_values() {
        let _guard = env_lock();
        clear_audit_env();
        let dir = std::env::temp_dir().join(format!("batman-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        append_event(
            &dir,
            "test",
            &[("path", "C:\\tmp\\quoted\"file\n.txt".to_string())],
        )
        .unwrap();
        let content = fs::read_to_string(audit_path(&dir)).unwrap();
        assert!(content.contains("\"action\":\"test\""));
        assert!(content.contains("\"previous_hash\":"));
        assert!(content.contains("\"hash\":"));
        assert!(content.contains("C:\\\\tmp\\\\quoted\\\"file\\n.txt"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        clear_audit_env();
        let dir = std::env::temp_dir().join(format!("batman-audit-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        append_event(&dir, "test", &[]).unwrap();
        assert_eq!(
            fs::metadata(audit_path(&dir)).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_events_are_hash_chained() {
        let _guard = env_lock();
        clear_audit_env();
        let dir = std::env::temp_dir().join(format!("batman-audit-chain-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        append_event(&dir, "first", &[]).unwrap();
        append_event(&dir, "second", &[("result", "ok".to_string())]).unwrap();

        let verification = verify_audit_log(&audit_path(&dir)).unwrap();
        assert_eq!(verification.events, 2);
        assert_ne!(
            verification.last_hash,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let _guard = env_lock();
        clear_audit_env();
        let dir = std::env::temp_dir().join(format!("batman-audit-tamper-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        append_event(&dir, "first", &[]).unwrap();
        let path = audit_path(&dir);
        let mut content = fs::read_to_string(&path).unwrap();
        content = content.replace("\"action\":\"first\"", "\"action\":\"other\"");
        fs::write(&path, content).unwrap();

        assert!(verify_audit_log(&path).is_err());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires local TCP sockets; covered by production path and can be run manually"]
    fn audit_event_can_be_forwarded_to_tcp_sink() {
        let _guard = env_lock();
        clear_audit_env();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = String::new();
            stream.read_to_string(&mut received).unwrap();
            received
        });
        unsafe {
            std::env::set_var(AUDIT_TCP_ENV, address);
            std::env::set_var(AUDIT_SINK_REQUIRED_ENV, "1");
        }

        let dir = std::env::temp_dir().join(format!("batman-audit-tcp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        append_event(&dir, "forwarded", &[("answer", "42".to_string())]).unwrap();

        unsafe {
            std::env::remove_var(AUDIT_TCP_ENV);
            std::env::remove_var(AUDIT_SINK_REQUIRED_ENV);
        }
        let received = handle.join().unwrap();
        assert!(received.contains("\"action\":\"forwarded\""));
        assert!(received.contains("\"answer\":\"42\""));

        fs::remove_dir_all(dir).unwrap();
    }

    fn clear_audit_env() {
        unsafe {
            std::env::remove_var(AUDIT_TCP_ENV);
            std::env::remove_var(super::AUDIT_SYSLOG_ENV);
            std::env::remove_var(AUDIT_SINK_REQUIRED_ENV);
        }
    }
}
