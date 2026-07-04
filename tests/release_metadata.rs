use std::fs;
use std::path::Path;

#[test]
fn changelog_top_section_matches_cargo_package_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let changelog = fs::read_to_string(root.join("CHANGELOG.md")).unwrap();

    let version = cargo_toml
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("version = ")
                .and_then(|value| value.trim_matches('"').split('"').next())
        })
        .expect("Cargo.toml package version");
    let first_heading = changelog
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("CHANGELOG.md first heading")
        .trim();

    assert_eq!(first_heading, format!("# {version}"));
}

#[test]
fn cargo_package_include_list_is_release_scoped() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let include = package_include_entries(&cargo_toml);

    for required in [
        "/Cargo.toml",
        "/Cargo.lock",
        "/README.md",
        "/CHANGELOG.md",
        "/LICENSE",
        "/src/**",
        "/tests/**",
        "/docs/**",
        "/resource/batman_linux.yaml",
        "/resource/batman_macos.yaml",
        "/resource/batman_windows.yaml",
    ] {
        assert!(
            include.iter().any(|entry| entry == required),
            "Cargo package include list is missing {required}"
        );
    }

    for forbidden in [
        "/dart/**",
        "/bin/**",
        "/lib/**",
        "/tool/**",
        "/resource/batman_local.yaml",
        "/resource/batman_docker.yaml",
    ] {
        assert!(
            include.iter().all(|entry| entry != forbidden),
            "Cargo package include list must not include {forbidden}"
        );
    }
}

fn package_include_entries(cargo_toml: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut in_include = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "include = [" {
            in_include = true;
            continue;
        }
        if in_include && trimmed == "]" {
            break;
        }
        if in_include {
            let entry = trimmed.trim_end_matches(',').trim_matches('"');
            if !entry.is_empty() {
                entries.push(entry.to_string());
            }
        }
    }
    entries
}
