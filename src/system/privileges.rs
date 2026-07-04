#[cfg(unix)]
pub fn is_privileged() -> bool {
    proc_status_effective_uid() == 0
}

pub fn required_privilege_description() -> &'static str {
    #[cfg(unix)]
    {
        "root"
    }
    #[cfg(windows)]
    {
        "an elevated Administrator session"
    }
    #[cfg(not(any(unix, windows)))]
    {
        "elevated privileges"
    }
}

#[cfg(unix)]
fn proc_status_effective_uid() -> u32 {
    // The effective UID is exposed by procfs on Linux, which is Batman's target
    // deployment environment, so this avoids direct libc FFI.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_proc_status_effective_uid(&status))
        .unwrap_or(u32::MAX)
}

#[cfg(unix)]
fn parse_proc_status_effective_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:").and_then(|uids| {
            uids.split_whitespace()
                .nth(1)
                .and_then(|uid| uid.parse::<u32>().ok())
        })
    })
}

#[cfg(windows)]
pub fn is_privileged() -> bool {
    use std::ptr::null_mut;

    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SID_IDENTIFIER_AUTHORITY,
    };

    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x20;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x220;

    let nt_authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 5],
    };
    let mut admin_group = null_mut();
    let allocated = unsafe {
        AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admin_group,
        )
    };
    if allocated == 0 {
        return false;
    }

    let mut is_member = 0;
    let checked = unsafe { CheckTokenMembership(null_mut(), admin_group, &mut is_member) };
    unsafe {
        FreeSid(admin_group);
    }
    checked != 0 && is_member != 0
}

#[cfg(not(any(unix, windows)))]
pub fn is_privileged() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::required_privilege_description;

    #[cfg(unix)]
    #[test]
    fn parses_linux_effective_uid_from_proc_status() {
        let status = "Name:\tbatman\nUid:\t1000\t0\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";

        assert_eq!(super::parse_proc_status_effective_uid(status), Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn unix_privilege_label_is_root() {
        assert_eq!(required_privilege_description(), "root");
    }

    #[cfg(windows)]
    #[test]
    fn windows_privilege_label_mentions_administrator() {
        assert!(required_privilege_description().contains("Administrator"));
    }
}
