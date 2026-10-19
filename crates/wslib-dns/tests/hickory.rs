use std::net::UdpSocket;
use std::time::Duration;

use wslib_dns::{HickoryOptions, HickoryResolver, LookupError, Resolver};

#[tokio::test]
async fn a_server_that_never_answers_is_a_timeout() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns = HickoryResolver::from_nameservers([silent.local_addr().unwrap()], {
        let mut options = HickoryOptions::default();
        options.timeout = Duration::from_millis(200);
        options.attempts = 1;
        options
    })
    .unwrap();
    assert_eq!(dns.a("example.com").await, Err(LookupError::Timeout));
    assert_eq!(dns.txt("example.com").await, Err(LookupError::Timeout));
}

#[tokio::test]
async fn debug_shows_the_options_not_the_internals() {
    let dns = HickoryResolver::from_nameservers(
        ["192.0.2.53:53".parse().unwrap()],
        HickoryOptions::default(),
    )
    .unwrap();
    assert!(format!("{dns:?}").starts_with("HickoryResolver { options:"));
}

mod local {
    use std::net::SocketAddr;

    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::Record;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    /// A nameserver on one local port that answers every query with
    /// `records` for the queried name: over TCP in full, and over UDP in
    /// full or, when `truncate_udp`, empty with TC set.
    pub async fn server(
        truncate_udp: bool,
        records: fn(&hickory_resolver::proto::rr::Name) -> Vec<Record>,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).await.unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buffer).await {
                let response = if truncate_udp {
                    let mut empty = answer(&buffer[..len], |_| Vec::new());
                    empty.metadata.truncation = true;
                    empty
                } else {
                    answer(&buffer[..len], records)
                };
                udp.send_to(&response.to_vec().unwrap(), peer).await.ok();
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    loop {
                        let mut length = [0u8; 2];
                        if stream.read_exact(&mut length).await.is_err() {
                            return;
                        }
                        let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                        stream.read_exact(&mut query).await.unwrap();
                        let response = answer(&query, records).to_vec().unwrap();
                        let length = u16::try_from(response.len()).unwrap().to_be_bytes();
                        stream.write_all(&length).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                    }
                });
            }
        });
        address
    }

    fn answer(
        query: &[u8],
        records: impl Fn(&hickory_resolver::proto::rr::Name) -> Vec<Record>,
    ) -> Message {
        let query = Message::from_vec(query).unwrap();
        let name = query.queries[0].name().clone();
        let mut response = query.into_response();
        for record in records(&name) {
            response.add_answer(record);
        }
        response
    }
}

#[tokio::test]
async fn a_truncated_answer_retries_over_tcp_with_several_servers() {
    use hickory_resolver::proto::rr::rdata::TXT;
    use hickory_resolver::proto::rr::{RData, Record};
    fn sixty(name: &hickory_resolver::proto::rr::Name) -> Vec<Record> {
        (0..60)
            .map(|n| {
                let txt = TXT::new(vec![format!(
                    "verification-token-{n:03}-{}",
                    "x".repeat(40)
                )]);
                Record::from_rdata(name.clone(), 300, RData::TXT(txt))
            })
            .collect()
    }
    let servers = [
        local::server(true, sixty).await,
        local::server(true, sixty).await,
    ];
    let dns = HickoryResolver::from_nameservers(servers, HickoryOptions::default()).unwrap();
    assert_eq!(dns.txt("example.com").await.unwrap().records.len(), 60);
}

#[tokio::test]
async fn an_answer_through_a_cname_reports_its_canonical_name() {
    use hickory_resolver::proto::rr::rdata::{A, CNAME};
    use hickory_resolver::proto::rr::{Name, RData, Record};
    fn aliased(name: &Name) -> Vec<Record> {
        let target = Name::from_ascii("host.example.net.").unwrap();
        vec![
            Record::from_rdata(name.clone(), 300, RData::CNAME(CNAME(target.clone()))),
            Record::from_rdata(target, 300, RData::A(A::new(192, 0, 2, 25))),
        ]
    }
    let dns = HickoryResolver::from_nameservers(
        [local::server(false, aliased).await],
        HickoryOptions::default(),
    )
    .unwrap();
    let answer = dns.a("mail.example.com").await.unwrap();
    assert_eq!(
        answer.records,
        ["192.0.2.25".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    assert_eq!(answer.canonical_name.as_deref(), Some("host.example.net"));
}
