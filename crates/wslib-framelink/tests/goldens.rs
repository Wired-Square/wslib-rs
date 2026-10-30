//! Every serialised shape against what the source this crate was moved from
//! produced for the same inputs, and the registry file it wrote read back.

use wslib_framelink as s;

include!("fixtures/golden_inputs.rs");

fn fixtures() -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(include_str!("fixtures/goldens.json")).unwrap()
}

#[test]
fn every_golden_is_unchanged() {
    let fixtures = fixtures();
    let goldens = session_goldens();
    assert_eq!(goldens.len(), fixtures.len());
    for (name, produced) in goldens {
        assert_eq!(produced, fixtures[name], "{name}");
    }
}

#[test]
fn every_golden_reads_back() {
    let fixtures = fixtures();
    let event: s::DiscoveryEvent = serde_json::from_str(&fixtures["event_seen"]).unwrap();
    assert_eq!(
        event,
        s::DiscoveryEvent::Seen {
            device: ble_device()
        }
    );
    let device: s::Device = serde_json::from_str(&fixtures["device_mdns"]).unwrap();
    assert_eq!(device, mdns_device());
    let set: s::CapabilitySet = serde_json::from_str(&fixtures["capability_set"]).unwrap();
    assert!(set.contains(s::CapabilitySet::from(s::Capability::Other(9))));
}

#[test]
fn a_registry_file_the_source_wrote_opens() {
    let dir = std::env::temp_dir().join(format!("wslib-framelink-golden-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("framelink.json");
    std::fs::write(&path, &fixtures()["registry_file"]).unwrap();

    let registry = s::registry::DeviceRegistry::open_at(&path).unwrap();

    let pinned = registry
        .get("WiredFlexLink-4CD4")
        .expect("the manual record");
    assert_eq!(pinned.host, Some("10.0.52.162".parse().unwrap()));
    assert_eq!(registry.list().count(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}
