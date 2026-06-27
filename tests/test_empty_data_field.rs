mod fixtures;
use fixtures::*;

use evtx::{EvtxParser, ParserSettings};
use serde_json::Value;

/// Regression test for empty named `<Data>` serialization.
///
/// A `<Data Name="X"></Data>` element that is *present but empty* must serialize
/// to `""` (present, empty), not `null` (which this serializer uses for an
/// *absent* field). Consumers that distinguish the two — e.g. Sigma
/// `field: null` matching, which should match only an absent field — otherwise
/// get wrong results.
///
/// The sample is a Windows Firewall EventID-2004 ("a rule has been added") event
/// for an OpenSSH *service* rule, whose `ApplicationPath` / `ServiceName`
/// elements are present but empty.
#[test]
fn test_empty_named_data_renders_as_empty_string_not_null() {
    ensure_env_logger_initialized();
    let evtx_file = include_bytes!("../samples/win_firewall_as_2004_empty_data.evtx");
    let mut parser = EvtxParser::from_buffer(evtx_file.to_vec())
        .unwrap()
        .with_configuration(ParserSettings::new().num_threads(1));

    let record = parser
        .records_json()
        .filter_map(Result::ok)
        .find(|r| {
            serde_json::from_str::<Value>(&r.data)
                .ok()
                .map(|v| {
                    let eid = &v["Event"]["System"]["EventID"];
                    eid.as_str() == Some("2004") || eid.as_u64() == Some(2004)
                })
                .unwrap_or(false)
        })
        .expect("an EventID 2004 firewall-rule-added record to exist in the sample");

    let value: Value = serde_json::from_str(&record.data).expect("record JSON to parse");
    let event_data = &value["Event"]["EventData"];

    // A present-but-empty named `<Data>` must render as `""`, NOT `null` (which
    // would make the field look absent to a `field: null` consumer).
    assert_eq!(
        event_data["ApplicationPath"].as_str(),
        Some(""),
        "empty <Data Name=\"ApplicationPath\"> must render as \"\", got {:?}",
        event_data["ApplicationPath"]
    );
    assert_eq!(
        event_data["ServiceName"].as_str(),
        Some(""),
        "empty <Data Name=\"ServiceName\"> must render as \"\", got {:?}",
        event_data["ServiceName"]
    );

    // A non-empty named `<Data>` keeps its concrete value (sanity guard that the
    // fix only rewrites the empty case).
    assert!(
        event_data["ModifyingApplication"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "a non-empty <Data> should keep its value, got {:?}",
        event_data["ModifyingApplication"]
    );
}
