use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::store::{
    BaselineSigningKey, REQUIRE_SIGNED_BASELINE_ENV, baseline_signing_key_from_env,
    ensure_baseline_can_be_signed_if_required_with_private_key, parse_baseline_private_key,
};
use crate::output::{Output, Style};
use crate::system::read_secret;

pub fn baseline_signing_key_for_write(
    configured_public_key: Option<&str>,
    output: &mut Output,
) -> BatmanResult<Option<BaselineSigningKey>> {
    if let Some(key) = baseline_signing_key_from_env()? {
        ensure_baseline_can_be_signed_if_required_with_private_key(
            configured_public_key,
            Some(&key),
        )?;
        return Ok(Some(key));
    }
    if !should_prompt_for_private_key(configured_public_key) {
        ensure_baseline_can_be_signed_if_required_with_private_key(configured_public_key, None)?;
        return Ok(None);
    }

    output.line(
        Style::Warn,
        "A signed baseline is configured, but no private signing key was provided.",
    )?;
    output.line(
        Style::Plain,
        "If you have already run 'batman keygen', retrieve the private key from your password manager, vault, or offline storage.",
    )?;
    output.line(
        Style::Plain,
        "If you have not generated signing keys yet, press Ctrl-C and run 'batman keygen' first.",
    )?;
    if !signed_baseline_required() {
        output.line(
            Style::Plain,
            "To intentionally create an unsigned baseline instead, rerun 'batman baseline --unsigned'.",
        )?;
    }

    let value = read_secret(
        "Private key from batman keygen (64 hex chars, input hidden; Ctrl-C to abort): ",
    )?;
    if value.is_empty() {
        return Err(BatmanError::Config(
            "no private key entered; rerun with the private key, or use 'batman baseline --unsigned' if you intentionally want an unsigned baseline".to_string(),
        ));
    }
    let key = parse_baseline_private_key(&value)?;
    ensure_baseline_can_be_signed_if_required_with_private_key(configured_public_key, Some(&key))?;
    Ok(Some(key))
}

fn should_prompt_for_private_key(configured_public_key: Option<&str>) -> bool {
    configured_public_key.is_some() || signed_baseline_required()
}

pub fn signed_baseline_required() -> bool {
    std::env::var(REQUIRE_SIGNED_BASELINE_ENV)
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}
