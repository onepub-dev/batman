pub mod app;
pub mod audit;
pub mod cli;
pub mod commands;
pub mod config;
pub mod errors;
pub mod integrity;
pub mod logscan;
pub mod output;
pub mod security;
pub mod system;

pub use app::App;
pub use errors::{BatmanError, BatmanResult};

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
