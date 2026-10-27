//! The systemd unit, and a `.sample` in its drop-in directory saying how to
//! change it without editing it.

use crate::model::{Checked, MANDATORY_ADDRESS_FAMILIES, MANDATORY_CAPABILITIES};
use crate::render::{Artefact, RenderError, fill};

const UNIT: &str = include_str!("../templates/unit.service");
/// `.sample` rather than `.conf`, so systemd ignores it.
const DROPIN: &str = include_str!("../templates/unit-dropin.conf.sample");

pub fn unit(checked: &Checked) -> Result<Artefact, RenderError> {
    let app = &checked.appliance;
    let dirs = &checked.dirs;

    let values = vec![
        ("name", app.name.clone()),
        ("binary", app.binary.clone()),
        ("env_prefix", app.env_prefix.clone()),
        ("user", app.user.clone()),
        ("group", app.group.clone()),
        ("config_dir_name", dirs.config.clone()),
        ("state_dir_name", dirs.state.clone()),
        ("runtime_dir_name", dirs.runtime.clone()),
        (
            "address_families",
            merged(&MANDATORY_ADDRESS_FAMILIES, &app.address_families),
        ),
        (
            "capabilities",
            merged(&MANDATORY_CAPABILITIES, &app.capabilities),
        ),
    ];

    Ok(Artefact {
        path: format!("systemd/{}.service", app.name).into(),
        body: fill("unit.service", UNIT, &values)?,
    })
}

pub fn sample(checked: &Checked) -> Result<Artefact, RenderError> {
    let app = &checked.appliance;
    Ok(Artefact {
        path: format!("systemd/{}.service.d/00-example.conf.sample", app.name).into(),
        body: fill(
            "unit-dropin.conf.sample",
            DROPIN,
            &[("name", app.name.clone()), ("binary", app.binary.clone())],
        )?,
    })
}

/// The mandatory entries in their order, then whatever else the product asked
/// for.
fn merged(mandatory: &[&str], asked: &[String]) -> String {
    let mut entries = mandatory.to_vec();
    for entry in asked {
        if !entries.contains(&entry.as_str()) {
            entries.push(entry);
        }
    }
    entries.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EXAMPLE, checked};

    fn directive<'a>(unit: &'a str, key: &str) -> Option<&'a str> {
        unit.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
    }

    fn unit_for(text: &str) -> String {
        unit(&checked(text)).expect("renders").body
    }

    /// `wslib-appliance-config` defaults its paths from what systemd exports
    /// for these directives.
    #[test]
    fn the_units_directories_are_the_paths_the_file_named() {
        let checked = checked(EXAMPLE);
        let unit = &unit_for(EXAMPLE);

        for (key, root, path) in [
            (
                "ConfigurationDirectory",
                "/etc",
                &checked.appliance.config_dir,
            ),
            ("StateDirectory", "/var/lib", &checked.appliance.state_dir),
            ("RuntimeDirectory", "/run", &checked.appliance.runtime_dir),
        ] {
            let name = directive(unit, key).unwrap_or_else(|| panic!("{key} is set"));
            assert_eq!(
                std::path::Path::new(root).join(name),
                **path,
                "{key} does not spell the path wslib-appliance-config will default from"
            );
        }
    }

    #[test]
    fn the_units_only_environment_names_the_package_file() {
        let unit = unit_for(EXAMPLE);
        let environment: Vec<&str> = unit
            .lines()
            .filter_map(|line| line.strip_prefix("Environment="))
            .collect();
        assert_eq!(
            environment,
            ["MYAPPLIANCE_PACKAGE_CONFIG=/usr/share/myappliance/config.toml"]
        );
    }

    #[test]
    fn the_directory_modes_are_the_two_halves_of_the_socket_grant() {
        let unit = unit_for(EXAMPLE);
        assert_eq!(directive(&unit, "RuntimeDirectoryMode"), Some("0750"));
        assert_eq!(directive(&unit, "StateDirectoryMode"), Some("0700"));
        assert_eq!(directive(&unit, "ConfigurationDirectoryMode"), Some("0751"));
    }

    #[test]
    fn the_appliance_runs_as_itself_and_is_granted_what_it_binds() {
        let unit = unit_for(EXAMPLE);

        assert_eq!(directive(&unit, "User"), Some("myappliance"));
        assert_eq!(directive(&unit, "Group"), Some("myappliance"));
        assert_eq!(
            directive(&unit, "ExecStart"),
            Some("/usr/bin/myappliance-server")
        );
        assert_eq!(directive(&unit, "ProtectHostname"), Some("yes"));
        assert_eq!(
            directive(&unit, "AmbientCapabilities"),
            Some("CAP_NET_BIND_SERVICE")
        );
        assert_eq!(
            directive(&unit, "CapabilityBoundingSet"),
            Some("CAP_NET_BIND_SERVICE")
        );
    }

    #[test]
    fn the_mandatory_families_are_there_whatever_the_product_asked_for() {
        let bare = unit_for(EXAMPLE);
        assert_eq!(
            directive(&bare, "RestrictAddressFamilies"),
            Some("AF_UNIX AF_INET AF_INET6 AF_NETLINK")
        );

        let widened = EXAMPLE.replace(
            "address_families = []",
            r#"address_families = ["AF_PACKET", "AF_UNIX"]"#,
        );
        assert_eq!(
            directive(&unit_for(&widened), "RestrictAddressFamilies"),
            Some("AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET")
        );
    }

    #[test]
    fn a_listed_capability_joins_the_one_every_unit_holds() {
        for (asked, expected) in [
            (r#"["CAP_NET_BIND_SERVICE"]"#, "CAP_NET_BIND_SERVICE"),
            (
                r#"["CAP_NET_RAW", "CAP_NET_BIND_SERVICE"]"#,
                "CAP_NET_BIND_SERVICE CAP_NET_RAW",
            ),
        ] {
            let text = EXAMPLE.replace("capabilities = []", &format!("capabilities = {asked}"));
            let unit = unit_for(&text);
            assert_eq!(directive(&unit, "AmbientCapabilities"), Some(expected));
            assert_eq!(directive(&unit, "CapabilityBoundingSet"), Some(expected));
        }
    }

    #[test]
    fn the_drop_in_example_is_not_itself_a_drop_in() {
        let sample = sample(&checked(EXAMPLE)).expect("renders");

        assert_eq!(
            sample.path.to_str(),
            Some("systemd/myappliance.service.d/00-example.conf.sample")
        );
        assert!(!sample.path.to_str().expect("utf-8").ends_with(".conf"));
        assert!(
            sample
                .body
                .lines()
                .all(|l| l.is_empty() || l.starts_with('#')),
            "the sample has a live directive in it"
        );
    }
}
