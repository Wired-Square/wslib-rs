use std::{future::Future, net::SocketAddr, time::Duration};

use tokio::{
    net::{TcpSocket, TcpStream},
    time::timeout,
};

/// A loopback address a connect hangs on, as against a host that drops the SYN:
/// a listener that never accepts, with its backlog full. Keep the
/// returned guard alive for as long as the address must stay silent.
pub async fn silent_addr() -> (impl Sized, SocketAddr) {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    let listener = socket.listen(1).unwrap();
    let mut filler = Vec::new();
    let silent = loop {
        match timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => filler.push(stream),
            Ok(Err(_)) => break unaliased_loopback(addr.port()).await,
            Err(_) => break addr,
        }
        assert!(filler.len() < 64, "the backlog never filled");
    };
    ((listener, filler), silent)
}

/// macOS (seen on Darwin 27) resets a connect to a full backlog, but leaves a
/// SYN to an unconfigured loopback address unanswered. Linux answers all of 127/8.
async fn unaliased_loopback(port: u16) -> SocketAddr {
    let addr = SocketAddr::from(([127, 0, 0, 2], port));
    let answered = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await;
    assert!(
        answered.is_err(),
        "no silent address here: {addr} answered {answered:?}"
    );
    addr
}

/// Every test runs under this, so a hang fails instead of stalling the suite.
pub async fn within<F: Future>(test: F) -> F::Output {
    timeout(Duration::from_secs(5), test)
        .await
        .expect("test timed out")
}
