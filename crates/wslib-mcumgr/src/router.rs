//! One task per session reads every frame and hands it to whoever sent the
//! request with that sequence number.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tracing::debug;

use crate::header::Header;
use crate::{Error, Transport};

type Route = mpsc::UnboundedSender<Result<Vec<u8>, Error>>;

pub(crate) struct Router {
    transport: Arc<dyn Transport>,
    routes: Mutex<Routes>,
    reader: OnceLock<AbortHandle>,
}

struct Routes {
    open: bool,
    next_seq: u8,
    by_seq: HashMap<u8, Route>,
}

impl Router {
    /// Spawns the reader, so it must be called within a tokio runtime.
    pub(crate) fn start(transport: Arc<dyn Transport>) -> Arc<Self> {
        let router = Arc::new(Self {
            transport: Arc::clone(&transport),
            routes: Mutex::new(Routes {
                open: true,
                next_seq: 0,
                by_seq: HashMap::new(),
            }),
            reader: OnceLock::new(),
        });
        let reader = tokio::spawn(read(transport, Arc::downgrade(&router)));
        let _ = router.reader.set(reader.abort_handle());
        router
    }

    pub(crate) fn transport(&self) -> &dyn Transport {
        &*self.transport
    }

    /// Runs as a task of its own, so a caller dropped mid-write still leaves
    /// whole frames on the link.
    pub(crate) async fn send(&self, frame: Vec<u8>) -> Result<(), Error> {
        let transport = Arc::clone(&self.transport);
        tokio::spawn(async move { transport.send(frame).await })
            .await
            .unwrap_or(Err(Error::LinkClosed))
    }

    pub(crate) fn is_open(&self) -> bool {
        self.lock().open
    }

    pub(crate) fn replies(self: &Arc<Self>) -> Replies {
        let (tx, rx) = mpsc::unbounded_channel();
        Replies {
            sequences: Sequences {
                router: Arc::clone(self),
                tx,
            },
            inbox: Inbox(rx),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.routes.lock().expect("SMP routes lock")
    }

    fn deliver(&self, frame: Vec<u8>) {
        let seq = match Header::decode(&frame) {
            Ok(header) => header.seq,
            Err(e) => return debug!("dropping an undecodable SMP frame: {e}"),
        };
        match self.lock().by_seq.remove(&seq) {
            Some(route) => drop(route.send(Ok(frame))),
            None => debug!(seq, "dropping an SMP reply no request awaits"),
        }
    }

    fn close(&self) {
        let mut routes = self.lock();
        routes.open = false;
        for (_, route) in routes.by_seq.drain() {
            let _ = route.send(Err(Error::LinkClosed));
        }
    }

    #[cfg(test)]
    pub(crate) fn awaited(&self) -> usize {
        self.lock().by_seq.len()
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.get() {
            reader.abort();
        }
    }
}

/// Holds no strong reference while it waits, so the router's drop ends it.
async fn read(transport: Arc<dyn Transport>, router: Weak<Router>) {
    let error = loop {
        match transport.receive().await {
            Ok(frame) => match router.upgrade() {
                Some(router) => router.deliver(frame),
                None => return,
            },
            Err(e) => break e,
        }
    };
    debug!("SMP transport closed: {error}");
    if let Some(router) = router.upgrade() {
        router.close();
    }
}

/// The replies to the requests sent under the sequence numbers it hands
/// out. Its halves can be used apart, one task sending and one receiving.
pub(crate) struct Replies {
    pub(crate) sequences: Sequences,
    pub(crate) inbox: Inbox,
}

/// Dropping it forgets the replies still due.
pub(crate) struct Sequences {
    router: Arc<Router>,
    tx: Route,
}

pub(crate) struct Inbox(mpsc::UnboundedReceiver<Result<Vec<u8>, Error>>);

impl Replies {
    pub(crate) fn expect(&self) -> Result<u8, Error> {
        self.sequences.expect()
    }

    pub(crate) async fn next(&mut self) -> Result<Vec<u8>, Error> {
        self.inbox.next().await
    }

    pub(crate) fn forget(&self) {
        self.sequences.forget();
    }
}

impl Sequences {
    /// A sequence number no other request awaits, routed here.
    pub(crate) fn expect(&self) -> Result<u8, Error> {
        let mut routes = self.router.lock();
        if !routes.open {
            return Err(Error::LinkClosed);
        }
        for _ in 0..=u8::MAX {
            let seq = routes.next_seq;
            routes.next_seq = seq.wrapping_add(1);
            if let Entry::Vacant(slot) = routes.by_seq.entry(seq) {
                slot.insert(self.tx.clone());
                return Ok(seq);
            }
        }
        Err(Error::Encode("every sequence number awaits a reply".into()))
    }

    /// Stops waiting for every reply still due.
    pub(crate) fn forget(&self) {
        self.router
            .lock()
            .by_seq
            .retain(|_, route| !route.same_channel(&self.tx));
    }
}

impl Drop for Sequences {
    fn drop(&mut self) {
        self.forget();
    }
}

impl Inbox {
    /// The next reply, in the order they arrive.
    pub(crate) async fn next(&mut self) -> Result<Vec<u8>, Error> {
        self.0.recv().await.unwrap_or(Err(Error::LinkClosed))
    }
}
