use std::fmt;

const MAX_REPOSITORY_LEN: usize = 255;
const MAX_TAG_LEN: usize = 128;

/// An image named as `docker pull` takes it: `repository`, `repository:tag` or `repository@sha256:…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub repository: String,
    pub pin: Pin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    Tag(String),
    Digest(String),
}

impl ImageReference {
    /// `None` unless every part is one the engine takes; no tag is `latest`, as
    /// the engine reads it. Digests are sha256 alone, and a tag with a digest is refused.
    pub fn parse(reference: &str) -> Option<Self> {
        let (repository, pin) = match reference.split_once('@') {
            Some((named, digest)) => (named, Pin::Digest(digest.to_string())),
            None => match reference.rsplit_once(':') {
                Some((named, tag)) if !tag.contains('/') => (named, Pin::Tag(tag.to_string())),
                _ => (reference, Pin::Tag("latest".to_string())),
            },
        };
        let pinned = match &pin {
            Pin::Tag(tag) => is_tag(tag),
            Pin::Digest(digest) => is_digest(digest),
        };
        (pinned && is_repository(repository)).then(|| Self {
            repository: repository.to_string(),
            pin,
        })
    }

    /// The registry the engine pulls it from: the repository's first part where
    /// that names a host, else Docker Hub.
    pub fn registry(&self) -> &str {
        match self.repository.split_once('/') {
            Some((first, _)) if names_a_host(first) => first,
            _ => "docker.io",
        }
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.pin {
            Pin::Tag(tag) => write!(f, "{}:{tag}", self.repository),
            Pin::Digest(digest) => write!(f, "{}@{digest}", self.repository),
        }
    }
}

fn names_a_host(first: &str) -> bool {
    first.contains(['.', ':']) || first == "localhost"
}

fn is_repository(repository: &str) -> bool {
    let (first, rest) = repository.split_once('/').unwrap_or(("", repository));
    let first_holds = if !names_a_host(first) {
        first.is_empty() || is_path_component(first)
    } else {
        match first.split_once(':') {
            None => is_domain(first),
            Some((host, port)) => {
                is_domain(host)
                    && port.bytes().all(|b| b.is_ascii_digit())
                    && port.parse::<u16>().is_ok_and(|port| port > 0)
            }
        }
    };
    repository.len() <= MAX_REPOSITORY_LEN && first_holds && rest.split('/').all(is_path_component)
}

/// The engine's, lowercase: labels of letters, digits and inner `-`, joined by `.`.
fn is_domain(host: &str) -> bool {
    host.split('.').all(|label| {
        let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
        label.starts_with(alphanumeric)
            && label.ends_with(alphanumeric)
            && label.chars().all(|c| alphanumeric(c) || c == '-')
    })
}

/// The engine's: lowercase letters and digits, separated by `.`, `_`, `__` or a run of `-`.
fn is_path_component(part: &str) -> bool {
    let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    part.starts_with(alphanumeric)
        && part.ends_with(alphanumeric)
        && part.split(alphanumeric).all(|separator| {
            matches!(separator, "" | "." | "_" | "__") || separator.bytes().all(|b| b == b'-')
        })
}

fn is_tag(tag: &str) -> bool {
    tag.len() <= MAX_TAG_LEN
        && tag.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn is_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_is_a_repository_and_a_tag_or_digest_and_nothing_else() {
        let digest = format!("sha256:{}", "a".repeat(64));
        for (reference, repository, pin) in [
            ("busybox", "busybox", Pin::Tag("latest".into())),
            ("busybox:1.37", "busybox", Pin::Tag("1.37".into())),
            (
                "10.0.50.56:5000/tests/hello:v2",
                "10.0.50.56:5000/tests/hello",
                Pin::Tag("v2".into()),
            ),
            (
                "localhost:5000/hello",
                "localhost:5000/hello",
                Pin::Tag("latest".into()),
            ),
            (
                &format!("ghcr.io/a/b@{digest}"),
                "ghcr.io/a/b",
                Pin::Digest(digest.clone()),
            ),
        ] {
            let parsed = ImageReference::parse(reference).expect(reference);
            assert_eq!(
                (parsed.repository.as_str(), &parsed.pin),
                (repository, &pin)
            );
        }
        assert_eq!(
            ImageReference::parse("busybox").unwrap().to_string(),
            "busybox:latest"
        );
        for refused in [
            "",
            "Busybox",
            "busybox:",
            "busybox:-x",
            "busybox@sha256:short",
            &format!("busybox@sha512:{}", "a".repeat(128)),
            &format!("busybox@sha256:{}", "A".repeat(64)),
            "busybox?x=1",
            "busybox&tag=x",
            "busy box",
            "busybox:1.0@sha256:x",
            "a//b",
            "host:0/a",
            &"a".repeat(MAX_REPOSITORY_LEN + 1),
            &format!("busybox:{}", "a".repeat(MAX_TAG_LEN + 1)),
        ] {
            assert_eq!(ImageReference::parse(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn the_registry_is_the_first_part_where_it_names_a_host_else_docker_hub() {
        for (reference, registry) in [
            ("10.0.2.2:5443/tests/hello", "10.0.2.2:5443"),
            ("localhost/hello", "localhost"),
            ("ghcr.io/a/b", "ghcr.io"),
            ("wired-square/hello", "docker.io"),
            ("busybox", "docker.io"),
        ] {
            let parsed = ImageReference::parse(reference).unwrap();
            assert_eq!(parsed.registry(), registry, "{reference}");
        }
    }
}
