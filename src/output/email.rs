use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::config::EmailConfig;
use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::ScanStats;
use crate::logscan::{LogScanSummary, LogSource};
use crate::output::{Output, Style};

pub fn notify_integrity_result(
    email: &EmailConfig,
    output: &mut Output,
    action_name: &str,
    success: bool,
    stats: &ScanStats,
    failed: u64,
    details: &[String],
) -> BatmanResult<()> {
    if success && !email.send_on_success {
        return Ok(());
    }
    if !success && !email.send_on_fail {
        return Ok(());
    }

    let Some(to_address) = recipient(email, success) else {
        output.error("Unable to send email: no recipient address is configured")?;
        return Ok(());
    };
    if email.from_address.is_empty() {
        output.error("Unable to send email: email_from_address is not configured")?;
        return Ok(());
    }

    let subject = if success {
        "File Integrity Monitor Succeeded"
    } else {
        "ALERT: File Integrity Monitor detected problems"
    };
    let body = build_body(action_name, success, stats, failed, details);
    match send_email(email, to_address, subject, &body) {
        Ok(()) => output.line(Style::Info, format!("Message sent to {to_address}"))?,
        Err(error) => output.error(format!("Message not sent. {error}"))?,
    }
    Ok(())
}

pub fn notify_log_result(
    email: &EmailConfig,
    output: &mut Output,
    source: &LogSource,
    summary: &LogScanSummary,
) -> BatmanResult<()> {
    let success = summary.match_count == 0;
    if success && !email.send_on_success {
        return Ok(());
    }
    if !success && !email.send_on_fail {
        return Ok(());
    }

    let Some(to_address) = log_recipient(email, source, success) else {
        output.error("Unable to send email: no recipient address is configured")?;
        return Ok(());
    };
    if email.from_address.is_empty() {
        output.error("Unable to send email: email_from_address is not configured")?;
        return Ok(());
    }

    let subject = if success {
        format!("Log scan succeeded: {}", source.name)
    } else {
        format!("ALERT: Log scan detected problems: {}", source.name)
    };
    let body = build_log_body(source, summary);
    match send_email(email, to_address, &subject, &body) {
        Ok(()) => output.line(Style::Info, format!("Message sent to {to_address}"))?,
        Err(error) => output.error(format!("Message not sent. {error}"))?,
    }
    Ok(())
}

fn recipient(email: &EmailConfig, success: bool) -> Option<&str> {
    if success {
        if email.success_to_address.is_empty() {
            non_empty(&email.fail_to_address)
        } else {
            Some(email.success_to_address.as_str())
        }
    } else {
        non_empty(&email.fail_to_address)
    }
}

fn log_recipient<'a>(
    email: &'a EmailConfig,
    source: &'a LogSource,
    success: bool,
) -> Option<&'a str> {
    source
        .report_to
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| recipient(email, success))
}

fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

fn build_body(
    action_name: &str,
    success: bool,
    stats: &ScanStats,
    failed: u64,
    details: &[String],
) -> String {
    let mut body = format!(
        "The file Integrity monitor {action_name} scanned {} directories and {} files.\n",
        stats.directories, stats.files
    );
    if !success {
        body.push_str(&format!(
            "\nDetected {failed} problems with the following files.\n\n"
        ));
        for detail in details {
            body.push_str(detail);
            body.push('\n');
        }
    }
    body
}

fn build_log_body(source: &LogSource, summary: &LogScanSummary) -> String {
    let mut body = format!(
        "The log scan '{}' checked {} log lines and matched {} problems.\n\nSource: {}\n",
        source.name,
        summary.line_count,
        summary.match_count,
        source.source_label()
    );
    if summary.match_count == 0 {
        body.push_str("\nNo problems found.\n");
    } else {
        body.push('\n');
        body.push_str(&summary.report);
    }
    body
}

fn send_email(
    config: &EmailConfig,
    to_address: &str,
    subject: &str,
    body: &str,
) -> BatmanResult<()> {
    let mut stream = TcpStream::connect((config.server_host.as_str(), config.server_port))
        .map_err(|error| BatmanError::io("connect to SMTP server", error))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| BatmanError::io("set SMTP read timeout", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| BatmanError::io("set SMTP write timeout", error))?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|error| BatmanError::io("clone SMTP stream", error))?,
    );

    expect_response(&mut reader)?;
    send_command(&mut stream, &mut reader, "HELO localhost\r\n")?;
    send_command(
        &mut stream,
        &mut reader,
        &format!("MAIL FROM:<{}>\r\n", config.from_address),
    )?;
    send_command(
        &mut stream,
        &mut reader,
        &format!("RCPT TO:<{to_address}>\r\n"),
    )?;
    send_command(&mut stream, &mut reader, "DATA\r\n")?;
    write!(
        stream,
        "From: <{}>\r\nTo: <{}>\r\nSubject: {}\r\n\r\n",
        config.from_address, to_address, subject
    )
    .map_err(|error| BatmanError::io("write SMTP message", error))?;
    write_smtp_body(&mut stream, body)?;
    stream
        .write_all(b".\r\n")
        .map_err(|error| BatmanError::io("write SMTP terminator", error))?;
    expect_response(&mut reader)?;
    send_command(&mut stream, &mut reader, "QUIT\r\n")?;
    Ok(())
}

fn send_command<W: Write, R: BufRead>(
    stream: &mut W,
    reader: &mut R,
    command: &str,
) -> BatmanResult<()> {
    stream
        .write_all(command.as_bytes())
        .map_err(|error| BatmanError::io("write SMTP command", error))?;
    stream
        .flush()
        .map_err(|error| BatmanError::io("flush SMTP command", error))?;
    expect_response(reader)
}

fn expect_response<R: BufRead>(reader: &mut R) -> BatmanResult<()> {
    let mut first_line = String::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|error| BatmanError::io("read SMTP response", error))?;
        if line.is_empty() {
            return Err(BatmanError::Config(
                "SMTP server closed connection".to_string(),
            ));
        }
        if first_line.is_empty() {
            first_line = line.clone();
        }
        let bytes = line.as_bytes();
        if bytes.len() >= 4 && bytes[3] == b' ' {
            return if matches!(bytes.first(), Some(b'2' | b'3')) {
                Ok(())
            } else {
                Err(BatmanError::Config(format!(
                    "SMTP server rejected command: {}",
                    first_line.trim()
                )))
            };
        }
    }
}

fn write_smtp_body<W: Write>(stream: &mut W, body: &str) -> BatmanResult<()> {
    for line in body.lines() {
        if line.starts_with('.') {
            stream
                .write_all(b".")
                .map_err(|error| BatmanError::io("write SMTP dot escape", error))?;
        }
        stream
            .write_all(line.as_bytes())
            .map_err(|error| BatmanError::io("write SMTP body", error))?;
        stream
            .write_all(b"\r\n")
            .map_err(|error| BatmanError::io("write SMTP body newline", error))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};
    use std::path::PathBuf;

    use crate::config::EmailConfig;
    use crate::logscan::{LogScanSummary, LogSource, SourceKind};

    use super::{build_log_body, expect_response, log_recipient, write_smtp_body};

    #[test]
    fn smtp_response_accepts_multiline_success() {
        let content = b"220-first line\r\n220 ready\r\n";
        let mut reader = BufReader::new(Cursor::new(content));

        expect_response(&mut reader).unwrap();
    }

    #[test]
    fn smtp_response_rejects_failure() {
        let content = b"550 rejected\r\n";
        let mut reader = BufReader::new(Cursor::new(content));

        assert!(expect_response(&mut reader).is_err());
    }

    #[test]
    fn smtp_body_dot_stuffs_lines() {
        let mut body = Vec::new();

        write_smtp_body(&mut body, "normal\n.dot\n..double").unwrap();

        assert_eq!(
            String::from_utf8(body).unwrap(),
            "normal\r\n..dot\r\n...double\r\n"
        );
    }

    #[test]
    fn log_notification_prefers_source_report_to() {
        let email = EmailConfig {
            send_on_fail: true,
            send_on_success: true,
            server_host: "localhost".to_string(),
            server_port: 25,
            from_address: "scanner@example.com".to_string(),
            fail_to_address: "global-fail@example.com".to_string(),
            success_to_address: "global-ok@example.com".to_string(),
        };
        let source = log_source(Some("source@example.com"));

        assert_eq!(
            log_recipient(&email, &source, false),
            Some("source@example.com")
        );
        assert_eq!(
            log_recipient(&email, &source, true),
            Some("source@example.com")
        );
    }

    #[test]
    fn log_notification_body_contains_report_details() {
        let source = log_source(None);
        let summary = LogScanSummary {
            line_count: 12,
            match_count: 1,
            report: "Rule: errors\nline 4: Error\n".to_string(),
        };

        let body = build_log_body(&source, &summary);

        assert!(body.contains("checked 12 log lines"));
        assert!(body.contains("matched 1 problems"));
        assert!(body.contains("Rule: errors"));
    }

    fn log_source(report_to: Option<&str>) -> LogSource {
        LogSource {
            kind: SourceKind::File,
            name: "app".to_string(),
            description: "App log".to_string(),
            top: 1000,
            rule_names: vec!["errors".to_string()],
            path: Some(PathBuf::from("/var/log/app.log")),
            container: None,
            since: None,
            args: None,
            trim_prefix: None,
            reset: None,
            group_by: None,
            report_to: report_to.map(str::to_string),
            override_source: None,
        }
    }
}
