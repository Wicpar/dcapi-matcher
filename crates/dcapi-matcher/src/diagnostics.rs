extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use android_credman::{
    CredentialEntry, CredentialSet, CredmanRender, InlineIssuanceEntry, StringIdEntry,
};
use crate::error::format_error_chain;
use core::sync::atomic::{AtomicU64, Ordering};
use core::error::Error as CoreError;
use serde::{Deserialize, Serialize};
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        }
    }
}

#[derive(Debug, Clone)]
struct LogEntry {
    level: LogLevel,
    message: String,
}

static LOGS: Mutex<Vec<LogEntry>> = Mutex::new(Vec::new());
static LOG_LEVEL: Mutex<Option<LogLevel>> = Mutex::new(Some(LogLevel::Error));
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn begin() {
    LOGS.lock().clear();
}

pub fn set_level(level: Option<LogLevel>) {
    *LOG_LEVEL.lock() = level;
}

pub fn debug(message: impl AsRef<str>) {
    push(LogLevel::Debug, message.as_ref());
}

pub fn trace(message: impl AsRef<str>) {
    push(LogLevel::Trace, message.as_ref());
}

pub fn info(message: impl AsRef<str>) {
    push(LogLevel::Info, message.as_ref());
}

pub fn warn(message: impl AsRef<str>) {
    push(LogLevel::Warn, message.as_ref());
}

pub fn error(message: impl AsRef<str>) {
    push(LogLevel::Error, message.as_ref());
}

/// Helper methods that log errors and convert `Result` into `Option`.
pub trait ResultExt<T, E> {
    fn ok_error(self) -> Option<T>;
    fn ok_warn(self) -> Option<T>;
    fn ok_info(self) -> Option<T>;
    fn ok_debug(self) -> Option<T>;
    fn ok_trace(self) -> Option<T>;
}

impl<T, E> ResultExt<T, E> for Result<T, E>
where
    E: CoreError,
{
    fn ok_error(self) -> Option<T> {
        self.inspect_err(|err| err.error()).ok()
    }

    fn ok_warn(self) -> Option<T> {
        self.inspect_err(|err| err.warn()).ok()
    }

    fn ok_info(self) -> Option<T> {
        self.inspect_err(|err| err.info()).ok()
    }

    fn ok_debug(self) -> Option<T> {
        self.inspect_err(|err| err.debug()).ok()
    }

    fn ok_trace(self) -> Option<T> {
        self.inspect_err(|err| err.trace()).ok()
    }
}

/// Helper methods that log an error chain at a chosen level.
pub trait ErrorExt {
    fn error(&self);
    fn warn(&self);
    fn info(&self);
    fn debug(&self);
    fn trace(&self);
}

impl<E> ErrorExt for E
where
    E: CoreError + ?Sized,
{
    fn error(&self) {
        error(format_error_chain(&self));
    }

    fn warn(&self) {
        warn(format_error_chain(&self));
    }

    fn info(&self) {
        info(format_error_chain(&self));
    }

    fn debug(&self) {
        debug(format_error_chain(&self));
    }

    fn trace(&self) {
        trace(format_error_chain(&self));
    }
}

pub fn take() -> Vec<String> {
    let entries = take_entries();
    entries.into_iter().map(format_entry).collect()
}

fn take_entries() -> Vec<LogEntry> {
    let mut logs = LOGS.lock();
    core::mem::take(&mut *logs)
}

pub fn flush_and_apply() {
    let entries = take_entries();
    if entries.is_empty() {
        return;
    }

    let set = CredentialSet::new("dcapi:logs").add_entries(entries.iter().map(|entry| {
        let id = next_id();
        let cred_id = format!("dcapi:log:{id}");
        let mut cred = StringIdEntry::new(cred_id, entry.level.as_str());
        if !entry.message.is_empty() {
            cred.disclaimer = Some(entry.message.as_str().into());
        }
        CredentialEntry::StringId(cred)
    }));
    set.render();

    for entry in &entries {
        let id = next_id();
        let cred_id = format!("dcapi:log-inline:{id}");
        let mut inline = InlineIssuanceEntry::new(cred_id, entry.level.as_str());
        if !entry.message.is_empty() {
            inline.subtitle = Some(entry.message.as_str().into());
        }
        inline.render();
    }
}

fn push(level: LogLevel, message: &str) {
    if !enabled(level) {
        return;
    }
    LOGS.lock().push(LogEntry {
        level,
        message: message.to_string(),
    });
}

fn enabled(level: LogLevel) -> bool {
    let Some(threshold) = *LOG_LEVEL.lock() else {
        return false;
    };
    level <= threshold
}


fn format_entry(entry: LogEntry) -> String {
    if entry.message.is_empty() {
        entry.level.as_str().to_string()
    } else {
        format!("{}: {}", entry.level.as_str(), entry.message)
    }
}

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}
