//! The image a console runs: `targets/docker/Dockerfile`, and
//! `packaging/make-image.sh`, which builds it into a tarball for `docker load`.
//!
//! The binary is built outside the image and copied in. A declared capability
//! is set by `setcap` in a stage of its own, so that build needs network.

use wslib_appliance_types::manifest::{AppLabel, MANIFEST_LABEL};

use crate::model::{Checked, Docker};
use crate::packaging::bundle_blocks;
use crate::render::{Artefact, RenderError, fixed};

const DOCKERFILE: &str = include_str!("../templates/docker/Dockerfile");
const MAKE_IMAGE: &str = include_str!("../templates/packaging/make-image.sh");
const CAPABILITIES_BASE: &str =
    "debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f";

pub fn artefacts(
    checked: &Checked,
    docker: &Docker,
    label: &AppLabel,
) -> Result<Vec<Artefact>, RenderError> {
    let app = &checked.appliance;
    let binary = &app.binary;
    let arches = label
        .arches
        .iter()
        .map(wire_name)
        .collect::<Vec<_>>()
        .join(" ");
    let plain_copy = format!("COPY --chmod=0755 bin/{binary} /usr/bin/{binary}");
    let (capabilities_stage, binary_copy) = if label.capabilities.is_empty() {
        (String::new(), plain_copy)
    } else {
        let mut names: Vec<_> = label
            .capabilities
            .iter()
            .map(|c| format!("cap_{}", wire_name(c).to_lowercase()))
            .collect();
        names.sort();
        names.dedup();
        (
            format!(
                "# buildx's transfer of the context drops a file capability, so it is set here.\n\
                 FROM --platform=$BUILDPLATFORM {CAPABILITIES_BASE} AS capabilities\n\
                 RUN apt-get -o APT::Update::Error-Mode=any update \
                 && apt-get install -y --no-install-recommends libcap2-bin\n\
                 {plain_copy}\n\
                 RUN setcap {}+ep /usr/bin/{binary}\n\n",
                names.join(",")
            ),
            format!("COPY --from=capabilities /usr/bin/{binary} /usr/bin/{binary}"),
        )
    };
    let state_dir = label
        .volumes
        .iter()
        .find(|v| v.name == "data")
        .expect("the model refuses a label with no data volume")
        .at
        .clone();
    let (volumes, volume_dirs): (Vec<_>, Vec<_>) = label
        .volumes
        .iter()
        .map(|v| {
            let (parent, entry) = v.at.rsplit_once('/').expect("an absolute path");
            let copy = format!(
                "COPY --chown=10001:0 --chmod=0770 vol/{}/ {parent}/",
                v.name
            );
            let copies = if parent.is_empty() {
                copy
            } else {
                format!("COPY empty/ {parent}/\n{copy}")
            };
            (copies, format!("\"$CONTEXT/vol/{}/{entry}\"", v.name))
        })
        .unzip();
    let volume_paths: Vec<&str> = label.volumes.iter().map(|v| v.at.as_str()).collect();
    let labels = [
        (
            MANIFEST_LABEL,
            serde_json::to_string(label).expect("a label"),
        ),
        ("org.opencontainers.image.version", label.version.clone()),
        ("org.opencontainers.image.source", docker.source.clone()),
    ]
    .map(|(key, value)| format!("{key}='{value}'"))
    .join(" \\\n      ");

    let ui_dist = app.package.ui_dist.as_deref();
    let (ui_copy, ui_staging) = if ui_dist.is_some() {
        (
            format!("COPY ui/ /usr/share/{}/ui/", app.name),
            "# The browser bundle, 0755 and 0644 flat whatever the build left.\n\
             mkdir \"$CONTEXT/ui\"\n\
             cp -R \"$UI_DIST/.\" \"$CONTEXT/ui\"\n\
             find \"$CONTEXT/ui\" -type d -exec chmod 0755 {} +\n\
             find \"$CONTEXT/ui\" -type f -exec chmod 0644 {} +"
                .to_string(),
        )
    } else {
        (
            "# No browser bundle: appliance.toml names no ui_dist.".to_string(),
            "# Nothing to stage for /usr/share: this product has no browser half.".to_string(),
        )
    };

    let values = vec![
        ("name", app.name.clone()),
        ("binary", binary.clone()),
        ("capabilities_stage", capabilities_stage),
        ("binary_copy", binary_copy),
        ("repository", docker.repository.clone()),
        ("version", label.version.clone()),
        ("arches", arches),
        ("ui_checks", bundle_blocks(ui_dist).0),
        ("ui_staging", ui_staging),
        ("ui_copy", ui_copy),
        ("volumes", volumes.join("\n")),
        ("volume_dirs", volume_dirs.join(" ")),
        ("config_dir", app.config_dir.display().to_string()),
        ("state_dir", state_dir),
        ("env_prefix", app.env_prefix.clone()),
        (
            "volume_paths",
            serde_json::to_string(&volume_paths).expect("paths"),
        ),
        ("labels", labels),
    ];
    fixed(
        &[
            ("packaging/make-image.sh", MAKE_IMAGE),
            ("targets/docker/Dockerfile", DOCKERFILE),
        ],
        &values,
    )
}

fn wire_name(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value)
        .expect("a unit variant")
        .replace('"', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EXAMPLE, LABEL, checked, with_docker, without_ui_dist};
    use crate::render::{body, commands};
    use wslib_appliance_types::manifest::AppCapability;

    fn rendered(text: &str) -> Vec<Artefact> {
        let checked = checked(&with_docker(text));
        let (docker, label) = checked.docker().expect("an image");
        artefacts(&checked, docker, label).expect("renders")
    }

    fn dockerfile(text: &str) -> String {
        commands(&body(&rendered(text), "targets/docker/Dockerfile"))
    }

    fn make_image(text: &str) -> String {
        commands(&body(&rendered(text), "packaging/make-image.sh"))
    }

    fn dockerfile_declaring(capabilities: &[AppCapability]) -> String {
        let checked = checked(&with_docker(EXAMPLE));
        let (docker, label) = checked.docker().expect("an image");
        let mut label = label.clone();
        label.capabilities = capabilities.to_vec();
        body(
            &artefacts(&checked, docker, &label).expect("renders"),
            "targets/docker/Dockerfile",
        )
    }

    /// Each `key='value'` the LABEL instruction sets.
    fn labels(dockerfile: &str) -> Vec<(String, String)> {
        let (_, rest) = dockerfile.split_once("LABEL ").expect("a LABEL");
        let mut labels = Vec::new();
        for line in rest.lines() {
            let pair = line.trim().trim_end_matches('\\').trim();
            let (key, quoted) = pair.split_once('=').expect("key=value");
            let value = quoted
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
                .unwrap_or_else(|| panic!("not single-quoted: {pair}"));
            assert!(!value.contains('\''), "{pair}");
            labels.push((key.to_string(), value.to_string()));
            if !line.ends_with('\\') {
                break;
            }
        }
        labels
    }

    #[test]
    fn the_image_is_labelled_with_the_manifest_its_version_and_its_source() {
        let labels = labels(&dockerfile(EXAMPLE));
        let keys: Vec<&str> = labels.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                MANIFEST_LABEL,
                "org.opencontainers.image.version",
                "org.opencontainers.image.source"
            ]
        );
        let label: AppLabel = serde_json::from_str(&labels[0].1).expect("the label parses");
        assert_eq!(label, serde_json::from_str::<AppLabel>(LABEL).unwrap());
        assert!(!labels[0].1.contains('\n') && !labels[0].1.contains(": "));
        assert_eq!(labels[1].1, label.version);
        assert_eq!(labels[2].1, "https://github.com/example/myappliance");
    }

    #[test]
    fn the_image_serves_the_app_socket_as_any_uid_in_group_0() {
        let file = dockerfile(EXAMPLE);
        let from = file.lines().next().expect("a FROM");
        assert!(
            from.starts_with("FROM gcr.io/distroless/static-debian13@sha256:")
                && !from.contains("nonroot"),
            "{from}"
        );
        for line in [
            "COPY --chmod=0755 bin/myappliance-server /usr/bin/myappliance-server",
            "COPY --chown=10001:0 --chmod=0770 vol/data/ /",
            "COPY --chown=10001:0 --chmod=0770 vol/spool/ /var/spool/",
            "COPY --chown=10001:0 --chmod=0770 sock/ /run/",
            "ENV CONFIGURATION_DIRECTORY=/etc/myappliance \\",
            "STATE_DIRECTORY=/data \\",
            "TMPDIR=/data \\",
            "MYAPPLIANCE_APP_SOCKET=/run/appliance/app.sock \\",
            "MYAPPLIANCE_HOOKS_SOCKET=/run/appliance/hooks.sock \\",
            "MYAPPLIANCE_CONSOLE_UID=0 \\",
            "MYAPPLIANCE_BASE_PATH=/apps/myappliance/",
            r#"VOLUME ["/data","/var/spool/x"]"#,
            "USER 10001:0",
            "WORKDIR /",
            r#"ENTRYPOINT ["/usr/bin/myappliance-server"]"#,
        ] {
            assert!(file.lines().any(|l| l == line), "no `{line}` in: {file}");
        }
        assert!(file.contains(
            "COPY empty/ /var/spool/\nCOPY --chown=10001:0 --chmod=0770 vol/spool/ /var/spool/"
        ));
        for absent in ["EXPOSE", "HEALTHCHECK", "RUN ", "CMD", "COPY empty/ /\n"] {
            assert!(!file.contains(absent), "{absent}: {file}");
        }
    }

    #[test]
    fn an_image_declaring_no_capability_has_one_stage_and_runs_nothing() {
        let raw = dockerfile_declaring(&[]);
        assert!(raw.contains("over app.sock.\n#\n# distroless"), "{raw}");
        let file = commands(&raw);
        assert_eq!(file.matches("FROM ").count(), 1, "{file}");
        for absent in ["AS capabilities", "setcap", "apt-get", "--from", "debian:"] {
            assert!(!file.contains(absent), "{absent}: {file}");
        }
    }

    #[test]
    fn a_declared_capability_is_set_on_the_binary_in_a_stage_and_copied_with_it() {
        use AppCapability::{NetBindService, NetRaw};
        let file = commands(&dockerfile_declaring(&[NetRaw, NetBindService, NetRaw]));
        let lines: Vec<&str> = file.lines().collect();
        assert_eq!(
            lines[..6],
            [
                "FROM --platform=$BUILDPLATFORM debian:trixie-slim@sha256:\
                 a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS capabilities",
                "RUN apt-get -o APT::Update::Error-Mode=any update \
                 && apt-get install -y --no-install-recommends libcap2-bin",
                "COPY --chmod=0755 bin/myappliance-server /usr/bin/myappliance-server",
                "RUN setcap cap_net_bind_service,cap_net_raw+ep /usr/bin/myappliance-server",
                "FROM gcr.io/distroless/static-debian13@sha256:\
                 58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0",
                "COPY --from=capabilities /usr/bin/myappliance-server /usr/bin/myappliance-server",
            ],
            "{file}"
        );
        for line in &lines[4..] {
            assert!(
                !line.starts_with("RUN ") && !line.contains(" bin/"),
                "{line}"
            );
        }
    }

    /// The bundle goes where `wslib-appliance-config` looks, asked of the crate.
    #[test]
    fn the_bundle_is_copied_where_the_daemon_looks_and_a_headless_image_has_none() {
        let ui = wslib_appliance_config::default_ui_dir("myappliance");
        let copy = format!("COPY ui/ {}/", ui.display());
        assert!(dockerfile(EXAMPLE).contains(&copy));
        assert!(make_image(EXAMPLE).contains(r#"cp -R "$UI_DIST/." "$CONTEXT/ui""#));

        let headless = without_ui_dist(EXAMPLE);
        assert!(!dockerfile(&headless).contains("COPY ui/"));
        for absent in ["UI_DIST", "$CONTEXT/ui"] {
            assert!(!make_image(&headless).contains(absent), "{absent}");
        }
    }

    #[test]
    fn make_image_checks_before_it_builds_and_writes_one_tarball_per_arch() {
        let script = make_image(EXAMPLE);
        let order = [
            r#"DOCKERFILE="$SCAFFOLD/targets/docker/Dockerfile""#,
            r#"[ "$VERSION" = "$CRATE_VERSION" ]"#,
            r#". "$HERE/build-binary.sh""#,
            r#"[ -f "$UI_DIST/index.html" ]"#,
            "binary_arch",
            r#"*" $ARCH "*) ;;"#,
            "build_binary",
            r#"cp "$BIN" "$CONTEXT/bin/$BINARY""#,
            "docker buildx create --name \"$BUILDER\" --driver docker-container",
            r#"--output "type=docker,dest=$IMAGE.part" "$CONTEXT""#,
            r#"mv "$IMAGE.part" "$IMAGE""#,
        ]
        .map(|step| {
            script
                .find(step)
                .unwrap_or_else(|| panic!("{step}: {script}"))
        });
        assert!(order.is_sorted(), "{order:?}: {script}");
        for line in [
            "ARCHES='arm64 amd64'",
            "VERSION='1.2.3'",
            "REPOSITORY='ghcr.io/example/myappliance'",
            r#"OUT="target/docker""#,
            r#"IMAGE="$OUT/$NAME-$VERSION-$ARCH.tar""#,
            r#"trap 'rm -rf "$CONTEXT" "$IMAGE.part"' EXIT"#,
            r#"mkdir -p "$CONTEXT/vol/data/data" "$CONTEXT/vol/spool/x" "$CONTEXT/sock/appliance" "$CONTEXT/empty""#,
            "BUILDER=appliance-image",
            r#"docker buildx build --builder "$BUILDER" --platform "linux/$ARCH" --file "$DOCKERFILE" \"#,
            r#"--tag "$REPOSITORY:$VERSION" --output "type=docker,dest=$IMAGE.part" "$CONTEXT""#,
        ] {
            assert!(
                script.lines().any(|l| l == line),
                "no `{line}` in: {script}"
            );
        }
    }

    #[test]
    fn an_image_alone_renders_nothing_of_the_package() {
        let paths: Vec<_> = crate::chassis_owned(&checked(&crate::model::docker_only()))
            .expect("renders")
            .into_iter()
            .map(|a| a.path.display().to_string().replace('\\', "/"))
            .collect();
        assert_eq!(
            paths,
            [
                "packaging/build-binary.sh",
                "packaging/build-id.sh",
                "packaging/make-image.sh",
                "targets/docker/Dockerfile"
            ]
        );
    }
}
