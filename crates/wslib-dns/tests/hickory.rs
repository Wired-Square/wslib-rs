use std::net::UdpSocket;
use std::time::Duration;

use wslib_dns::{HickoryOptions, HickoryResolver, LookupError, Resolver};

#[tokio::test]
async fn a_server_that_never_answers_is_a_timeout() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns = HickoryResolver::from_nameservers(
        [silent.local_addr().unwrap()],
        HickoryOptions {
            timeout: Duration::from_millis(200),
            attempts: 1,
        },
    )
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

mod truncating {
    use std::net::SocketAddr;

    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::rdata::TXT;
    use hickory_resolver::proto::rr::{RData, Record};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    /// A nameserver that answers every UDP query truncated and every TCP
    /// query in full with `records` TXT strings, on one local port.
    pub async fn server(records: usize) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).await.unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buffer).await {
                let mut response = answer(&buffer[..len], 0);
                response.metadata.truncation = true;
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

    fn answer(query: &[u8], records: usize) -> Message {
        let query = Message::from_vec(query).unwrap();
        let name = query.queries[0].name().clone();
        let mut response = query.into_response();
        for n in 0..records {
            let txt = TXT::new(vec![format!(
                "verification-token-{n:03}-{}",
                "x".repeat(40)
            )]);
            response.add_answer(Record::from_rdata(name.clone(), 300, RData::TXT(txt)));
        }
        response
    }
}

#[tokio::test]
async fn a_truncated_answer_retries_over_tcp_with_several_servers() {
    let servers = [truncating::server(60).await, truncating::server(60).await];
    let dns = HickoryResolver::from_nameservers(servers, HickoryOptions::default()).unwrap();
    let answer = dns.txt("example.com").await.unwrap();
    assert_eq!(answer.records.len(), 60);
}
