use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::resolver::join;
use crate::{HickoryOptions, HickoryResolver, LookupError, Resolver};

/// A public recursive resolver, asked over UDP port 53.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicResolver {
    pub name: &'static str,
    pub address: IpAddr,
}

/// The resolvers [`probe_public`] asks.
pub const PUBLIC_RESOLVERS: &[PublicResolver] = &[
    PublicResolver {
        name: "Cloudflare",
        address: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    },
    PublicResolver {
        name: "Google",
        address: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    },
    PublicResolver {
        name: "Quad9",
        address: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    },
];

/// What each public resolver says about a name's existence.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicProbe {
    pub name: String,
    /// In [`PUBLIC_RESOLVERS`] order.
    pub answers: Vec<PublicAnswer>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicAnswer {
    pub resolver: String,
    pub exists: Result<bool, LookupError>,
}

impl PublicProbe {
    /// Some resolver answers for the name.
    pub fn seen(&self) -> bool {
        self.answers.iter().any(|answer| answer.exists == Ok(true))
    }

    /// Every resolver answered, and none has the name.
    pub fn unseen(&self) -> bool {
        self.answers.iter().all(|answer| answer.exists == Ok(false))
    }
}

/// Asks every public resolver, concurrently, whether `name` exists.
pub async fn probe_public(name: &str, options: HickoryOptions) -> PublicProbe {
    let [cloudflare, google, quad9] = PUBLIC_RESOLVERS else {
        unreachable!("three public resolvers");
    };
    let (first, (second, third)) = join(
        ask(*cloudflare, name, options),
        join(ask(*google, name, options), ask(*quad9, name, options)),
    )
    .await;
    PublicProbe {
        name: crate::normalise(name),
        answers: vec![first, second, third],
    }
}

async fn ask(resolver: PublicResolver, name: &str, options: HickoryOptions) -> PublicAnswer {
    let exists =
        match HickoryResolver::from_nameservers([SocketAddr::new(resolver.address, 53)], options) {
            Ok(dns) => dns.exists(name).await,
            Err(error) => Err(error),
        };
    PublicAnswer {
        resolver: resolver.name.to_owned(),
        exists,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(answers: &[Result<bool, LookupError>]) -> PublicProbe {
        PublicProbe {
            name: "example.com".into(),
            answers: answers
                .iter()
                .zip(PUBLIC_RESOLVERS)
                .map(|(exists, resolver)| PublicAnswer {
                    resolver: resolver.name.to_owned(),
                    exists: exists.clone(),
                })
                .collect(),
        }
    }

    #[test]
    fn seen_needs_one_yes_and_unseen_needs_every_no() {
        assert!(probe(&[Ok(false), Ok(true), Err(LookupError::Timeout)]).seen());
        assert!(probe(&[Ok(false), Ok(false), Ok(false)]).unseen());
        let undecided = probe(&[Ok(false), Err(LookupError::Timeout), Ok(false)]);
        assert!(!undecided.seen() && !undecided.unseen());
    }
}
