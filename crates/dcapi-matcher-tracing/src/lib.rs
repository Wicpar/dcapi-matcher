#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use android_credman::{CredmanApplyExt, StringIdEntry};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use tracing_core::field::{Field, Visit};
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::{Event, Level, Metadata, Subscriber};
use tracing_core::dispatcher::Dispatch;

#[derive(Debug, Clone)]
struct LogEntry {
    message: String,
}

static LOGS: Mutex<Vec<LogEntry>> = Mutex::new(Vec::new());
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);
static LOG_LEVEL: Mutex<Option<Level>> = Mutex::new(None);

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl FieldVisitor {
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }

    fn into_message(self, level: Level) -> String {
        let mut out = String::new();
        let _ = write!(&mut out, "{}", level.as_str());
        let _ = write!(&mut out, ": ");
        if let Some(message) = self.message {
            let _ = write!(&mut out, "{}", message);
            return out;
        }
        if self.fields.is_empty() {
            return out;
        }
        for (idx, (key, value)) in self.fields.iter().enumerate() {
            if idx > 0 {
                let _ = write!(&mut out, " ");
            }
            let _ = write!(&mut out, "{}={}", key, value);
        }
        out
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        self.record_value(field, alloc::format!("{:?}", value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }
}

struct Collector;

impl Subscriber for Collector {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
        let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
        Id::from_u64(id)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if let Some(level) = *LOG_LEVEL.lock() {
            if event.metadata().level() > &level {
                return;
            }
        } else {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let entry = LogEntry {
            message: visitor.into_message(*event.metadata().level()),
        };
        LOGS.lock().push(entry);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Clears collected logs for a new matcher invocation.
pub fn begin() {
    LOGS.lock().clear();
}

/// Sets the active log level. `None` disables logging.
pub fn set_level(level: Option<Level>) {
    *LOG_LEVEL.lock() = level;
}

/// Installs the tracing collector as the global default.
///
/// This should be called once at program start. Subsequent calls are ignored.
pub fn set_global_default() {
    let _ = tracing_core::dispatcher::set_global_default(Dispatch::new(Collector));
}

/// Returns and clears collected logs.
pub fn take() -> Vec<String> {
    let mut logs = LOGS.lock();
    let entries = core::mem::take(&mut *logs);
    entries.into_iter().map(|entry| entry.message).collect()
}

/// Renders collected logs as a single credential entry and emits them to Credman.
///
/// Each log entry is rendered as a field name, with an empty value.
pub fn flush_and_apply() {
    let entries = take();
    if entries.is_empty() {
        return;
    }

    let mut entry = StringIdEntry::new("dcapi:logs", "");
    for item in entries.iter() {
        entry = entry.add_field(item.as_str(), "");
    }
    entry.apply();
}
