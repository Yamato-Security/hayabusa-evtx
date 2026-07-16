mod fixtures;
use fixtures::*;

use evtx::{EvtxParser, ParserSettings};
use serde_json::Value;

/// Regression test for `<ComplexData Name="X">Y</ComplexData>` serialization (issue #1520).
///
/// `ComplexData` elements are keyed by their `Name` attribute exactly like `<Data>`
/// elements. Before the fix they went through the generic attributed-node path, which
/// under `--separate-json-attributes` (the mode Hayabusa uses) mangled them badly:
/// the two `Name` attributes collapsed into a `"Name": ["IdleState", "PerfState"]`
/// array, and the `"01"` value was dropped entirely, leaving a bogus `"ComplexData": ""`.
///
/// The sample is a Kernel-Processor-Power EventID-26 record whose `EventData` contains
/// `<ComplexData Name="IdleState">01</ComplexData>` and an empty
/// `<ComplexData Name="PerfState"/>`.
fn find_eid26(records: &[Value]) -> &Value {
    records
        .iter()
        .find(|v| {
            let eid = &v["Event"]["System"]["EventID"];
            (eid.as_str() == Some("26") || eid.as_u64() == Some(26))
                && v["Event"]["EventData"].get("IdleState").is_some()
        })
        .expect("a Kernel-Processor-Power EID 26 record with ComplexData to exist in the sample")
}

fn parse_all(separate_attributes: bool) -> Vec<Value> {
    let evtx_file = include_bytes!("../samples/kernel_processor_power_complexdata.evtx");
    let mut parser = EvtxParser::from_buffer(evtx_file.to_vec())
        .unwrap()
        .with_configuration(
            ParserSettings::new()
                .num_threads(1)
                .separate_json_attributes(separate_attributes),
        );
    parser
        .records_json()
        .filter_map(Result::ok)
        .filter_map(|r| serde_json::from_str::<Value>(&r.data).ok())
        .collect()
}

#[test]
fn test_complexdata_keyed_by_name_separate_attributes() {
    ensure_env_logger_initialized();
    let records = parse_all(true);
    let event_data = &find_eid26(&records)["Event"]["EventData"];

    // The value must survive and be keyed by the `Name` attribute.
    assert_eq!(
        event_data["IdleState"].as_str(),
        Some("01"),
        "<ComplexData Name=\"IdleState\">01</ComplexData> must render as \"IdleState\": \"01\", got {event_data:?}"
    );
    // A present-but-empty ComplexData must render as "" (present), not null (absent).
    assert_eq!(
        event_data["PerfState"].as_str(),
        Some(""),
        "empty <ComplexData Name=\"PerfState\"/> must render as \"PerfState\": \"\", got {event_data:?}"
    );

    // None of the pre-fix mangling must remain: no raw `ComplexData*` key and no
    // bare `Name` key holding the collapsed attribute values.
    assert!(
        event_data
            .as_object()
            .unwrap()
            .keys()
            .all(|k| !k.starts_with("ComplexData")),
        "no ComplexData* key should remain, got {event_data:?}"
    );
    assert!(
        event_data.get("Name").is_none(),
        "the ComplexData `Name` attributes must not leak into a bare `Name` field, got {event_data:?}"
    );
}

#[test]
fn test_complexdata_keyed_by_name_default_attributes() {
    ensure_env_logger_initialized();
    // The `Name`-keyed result must be identical in the default (non-separate) mode too.
    let records = parse_all(false);
    let event_data = &find_eid26(&records)["Event"]["EventData"];

    assert_eq!(event_data["IdleState"].as_str(), Some("01"));
    assert_eq!(event_data["PerfState"].as_str(), Some(""));
    assert!(event_data.get("ComplexData").is_none());
}
