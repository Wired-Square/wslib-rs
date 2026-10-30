//! The JSON of every `OtaEvent`.

use std::collections::BTreeMap;

use wslib_framelink::{DeviceId, OtaEvent, UploadProgress};

fn progress(json: &str) -> UploadProgress {
    serde_json::from_str(json).unwrap()
}

fn produced() -> BTreeMap<&'static str, String> {
    let json = |event: OtaEvent| serde_json::to_string(&event).unwrap();
    BTreeMap::from([
        ("session_opened", json(OtaEvent::SessionOpened)),
        (
            "upload_progress",
            json(OtaEvent::UploadProgress(progress(
                r#"{"bytes_sent":512,"total_bytes":1024,"resumed_from":256}"#,
            ))),
        ),
        (
            "upload_progress_final",
            json(OtaEvent::UploadProgress(progress(
                r#"{"bytes_sent":1024,"total_bytes":1024,"image_hash":[171,205]}"#,
            ))),
        ),
        ("activating", json(OtaEvent::Activating)),
        (
            "activated",
            json(OtaEvent::Activated {
                hash: vec![0xAB, 0xCD],
            }),
        ),
        ("resetting", json(OtaEvent::Resetting)),
        ("reset_sent", json(OtaEvent::ResetSent)),
        (
            "reconnecting",
            json(OtaEvent::Reconnecting {
                name: "WFL-1234".into(),
            }),
        ),
        (
            "reconnected",
            json(OtaEvent::Reconnected {
                device_id: DeviceId::new("mdns:udp:wfl-1234._mcumgr._udp.local."),
            }),
        ),
        (
            "verified",
            json(OtaEvent::Verified {
                active_hash: vec![0xAB, 0xCD],
            }),
        ),
        ("confirming", json(OtaEvent::Confirming)),
        ("confirmed", json(OtaEvent::Confirmed)),
    ])
}

#[test]
fn every_ota_event_serialises_as_pinned() {
    let fixtures: BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/ota_goldens.json")).unwrap();
    let produced = produced();
    assert_eq!(produced.len(), fixtures.len());
    for (name, json) in produced {
        assert_eq!(json, fixtures[name], "{name}");
    }
}
