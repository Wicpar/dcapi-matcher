use android_credman::test_shim::{self, DisplayEvent};
use dcapi_matcher_tracing as matcher_tracing;

fn take_events() -> Vec<DisplayEvent> {
    test_shim::take_display().events
}

#[test]
fn tracing_logs_are_rendered_as_fields() {
    let _ = test_shim::take_display();
    matcher_tracing::begin();
    matcher_tracing::with_collector(|| {
        tracing::warn!("warning one");
        tracing::error!("error two");
    });
    matcher_tracing::flush_and_apply();

    let events = take_events();
    assert!(events.iter().any(|event| matches!(
        event,
        DisplayEvent::AddStringIdEntry { cred_id, .. } if cred_id == "dcapi:logs"
    )));
    let field_names = events
        .iter()
        .filter_map(|event| match event {
            DisplayEvent::AddFieldForStringIdEntry { display_name, .. } => {
                Some(display_name.as_str())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(field_names.iter().any(|name| name.contains("warn")));
    assert!(field_names.iter().any(|name| name.contains("error")));
}

#[test]
fn tracing_flush_is_noop_when_empty() {
    let _ = test_shim::take_display();
    matcher_tracing::begin();
    matcher_tracing::flush_and_apply();
    let events = take_events();
    assert!(events.is_empty());
}
