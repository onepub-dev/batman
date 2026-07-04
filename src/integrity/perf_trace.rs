use std::sync::OnceLock;
use std::time::Duration;

pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("BATMAN_PERF_TRACE")
            .map(|value| !value.is_empty() && value != "0" && value != "false")
            .unwrap_or(false)
    })
}

pub fn threshold() -> Duration {
    static THRESHOLD: OnceLock<Duration> = OnceLock::new();
    *THRESHOLD.get_or_init(|| {
        let millis = std::env::var("BATMAN_PERF_TRACE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(250);
        Duration::from_millis(millis)
    })
}

pub fn event(label: &str, detail: impl std::fmt::Display, elapsed: Duration) {
    if enabled() && elapsed >= threshold() {
        eprintln!("perf {label}: {}ms {detail}", elapsed.as_millis());
    }
}
