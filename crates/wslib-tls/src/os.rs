use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rustls::RootCertStore;
use rustls_native_certs::CertificateResult;

pub(crate) type ReadOs = Arc<dyn Fn() -> CertificateResult + Send + Sync>;

/// The operating system's roots, read in the background.
pub(crate) struct OsRoots {
    read: ReadOs,
    state: Mutex<State>,
    landed: Condvar,
}

#[derive(Default)]
struct State {
    roots: Option<Arc<RootCertStore>>,
    reading: bool,
    kept: bool,
}

impl OsRoots {
    pub(crate) fn new(read: ReadOs) -> Arc<Self> {
        Arc::new(Self {
            read,
            state: Mutex::default(),
            landed: Condvar::new(),
        })
    }

    /// Starts a read, unless one is running or a whole one is kept.
    pub(crate) fn refresh(self: &Arc<Self>) {
        {
            let mut state = self.lock();
            if state.kept || state.reading {
                return;
            }
            state.reading = true;
        }
        let os = self.clone();
        std::thread::Builder::new()
            .name("os-trust-store".to_string())
            .spawn(move || {
                // A panic must still land something, or every unpinned dial waits it out.
                let (roots, kept) =
                    std::panic::catch_unwind(AssertUnwindSafe(|| read_roots(&os.read)))
                        .unwrap_or_else(|_| (RootCertStore::empty(), false));
                let mut state = os.lock();
                state.roots = Some(Arc::new(roots));
                state.kept = kept;
                state.reading = false;
                drop(state);
                os.landed.notify_all();
            })
            .expect("a thread to read the OS trust store on");
    }

    pub(crate) fn landed(&self) -> Option<Arc<RootCertStore>> {
        self.lock().roots.clone()
    }

    /// Waits at most `bound` for the first read, handing a multi-threaded runtime's worker on.
    pub(crate) fn within(&self, bound: Duration) -> Option<Arc<RootCertStore>> {
        let wait = || {
            self.landed
                .wait_timeout_while(self.lock(), bound, |state| state.roots.is_none())
                .unwrap_or_else(PoisonError::into_inner)
                .0
                .roots
                .clone()
        };
        match tokio::runtime::Handle::try_current().map(|runtime| runtime.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(wait),
            _ => wait(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn is_reading(&self) -> bool {
        self.lock().reading
    }
}

/// The roots read, and whether to keep them: no error and at least one root.
fn read_roots(read: &ReadOs) -> (RootCertStore, bool) {
    let native = read();
    for e in &native.errors {
        tracing::warn!(error = %e, "reading the OS trust store");
    }
    let mut roots = RootCertStore::empty();
    let (added, skipped) = roots.add_parsable_certificates(native.certs);
    tracing::debug!(added, skipped, "OS trust store read");
    (roots, native.errors.is_empty() && added > 0)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::testing::Authority;

    #[test]
    fn an_empty_or_failed_read_is_read_again_and_a_whole_one_kept() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let root = Authority::new(provider, "Widget Root").certificate;
        let reads = Arc::new(AtomicUsize::new(0));
        let os = OsRoots::new({
            let reads = reads.clone();
            Arc::new(move || {
                let mut read = CertificateResult::default();
                match reads.fetch_add(1, Ordering::SeqCst) {
                    0 => {}
                    1 => {
                        read.certs.push(root.clone());
                        read.errors.push(rustls_native_certs::Error {
                            context: "the keychain was busy",
                            kind: rustls_native_certs::ErrorKind::Os("busy".into()),
                        });
                    }
                    _ => read.certs.push(root.clone()),
                }
                read
            })
        });
        let settle = || {
            os.refresh();
            while os.is_reading() {
                std::thread::yield_now();
            }
            os.landed().expect("landed").len()
        };

        assert_eq!(settle(), 0, "empty");
        assert_eq!(settle(), 1, "failed, but what it found is used");
        assert_eq!(settle(), 1, "whole");
        assert_eq!(settle(), 1, "kept");
        assert_eq!(reads.load(Ordering::SeqCst), 3);
    }
}
