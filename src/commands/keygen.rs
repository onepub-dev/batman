use ed25519_dalek::SigningKey;

use crate::cli::KeygenOptions;
use crate::commands::CommandContext;
use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::store::{BASELINE_PRIVATE_KEY_ENV, BASELINE_PUBLIC_KEY_ENV};
use crate::output::{Output, Style};

pub fn run(
    _context: &CommandContext,
    output: &mut Output,
    _options: KeygenOptions,
) -> BatmanResult<u8> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| BatmanError::Config(format!("generate random signing key: {error}")))?;
    write_key_pair(output, &seed)?;
    Ok(0)
}

fn write_key_pair(output: &mut Output, seed: &[u8; 32]) -> BatmanResult<()> {
    let signing_key = SigningKey::from_bytes(seed);
    output.line(
        Style::Warn,
        "Store the private key in a password manager, vault, or offline location.",
    )?;
    output.line(
        Style::Warn,
        "Do not store the private key in batman.yaml, shell history, scheduler configuration, or service environment.",
    )?;
    output.line(
        Style::Info,
        "Batman will prompt for the private key when creating or updating a signed baseline.",
    )?;
    output.line(
        Style::Plain,
        format!("{BASELINE_PRIVATE_KEY_ENV}={}", hex_bytes(seed)),
    )?;
    output.line(
        Style::Plain,
        format!(
            "{BASELINE_PUBLIC_KEY_ENV}={}",
            hex_bytes(signing_key.verifying_key().as_bytes())
        ),
    )?;
    output.line(
        Style::Info,
        "Put the public key in batman.yaml as file_integrity.baseline_public_key.",
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::cli::GlobalOptions;
    use crate::config::LocalSettings;
    use crate::output::Output;

    use super::write_key_pair;

    #[test]
    fn key_pair_output_uses_manifest_environment_names() {
        let dir = std::env::temp_dir().join(format!("batman-keygen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let logfile = dir.join("keygen.log");
        let global = GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        };
        let mut output = Output::new(&global).unwrap();

        write_key_pair(&mut output, &[3; 32]).unwrap();

        let content = std::fs::read_to_string(logfile).unwrap();
        assert!(content.contains("BATMAN_BASELINE_PRIVATE_KEY="));
        assert!(content.contains("BATMAN_BASELINE_PUBLIC_KEY="));
        assert!(content.contains(&"03".repeat(32)));
        assert!(content.contains("password manager"));
        assert!(content.contains("file_integrity.baseline_public_key"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keygen_command_runs_with_test_context() {
        let dir = std::env::temp_dir().join(format!("batman-keygen-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let logfile = dir.join("keygen.log");
        let global = GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        };
        let context = crate::commands::CommandContext {
            global,
            local_settings: LocalSettings::for_config_path(dir.join("batman.yaml")),
        };
        let mut output = Output::new(&context.global).unwrap();

        let code = super::run(&context, &mut output, Default::default()).unwrap();

        assert_eq!(code, 0);
        let content = std::fs::read_to_string(logfile).unwrap();
        assert!(content.contains("BATMAN_BASELINE_PRIVATE_KEY="));
        assert!(content.contains("BATMAN_BASELINE_PUBLIC_KEY="));
        assert!(content.contains("Do not store the private key"));
        assert!(content.contains("shell history"));

        std::fs::remove_dir_all(dir).unwrap();
    }
}
