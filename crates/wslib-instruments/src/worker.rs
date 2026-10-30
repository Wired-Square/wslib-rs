use std::{
    io,
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};

/// Outlasts a BLE disconnect after a stop, the slowest release here.
const RELEASE_WITHIN: Duration = Duration::from_secs(15);

/// A thread that dropping waits for, so whatever it holds is released by then.
/// Signal it to stop first. One still running after `RELEASE_WITHIN`, or
/// dropped on its own thread, is left to finish alone.
pub(crate) struct Worker {
    finished: Receiver<()>,
    thread: Option<JoinHandle<()>>,
    release_within: Duration,
}

impl Worker {
    pub(crate) fn spawn(name: &str, work: impl FnOnce() + Send + 'static) -> io::Result<Self> {
        Self::spawn_within(name, RELEASE_WITHIN, work)
    }

    fn spawn_within(
        name: &str,
        release_within: Duration,
        work: impl FnOnce() + Send + 'static,
    ) -> io::Result<Self> {
        let (finishing, finished) = mpsc::channel();
        let thread = thread::Builder::new().name(name.into()).spawn(move || {
            let _finishing = finishing;
            work();
        })?;
        Ok(Self {
            finished,
            thread: Some(thread),
            release_within,
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        if thread.thread().id() != thread::current().id()
            && self.finished.recv_timeout(self.release_within)
                == Err(RecvTimeoutError::Disconnected)
        {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Instant,
    };

    use super::*;

    const WORK: Duration = Duration::from_millis(50);
    const BOUND: Duration = Duration::from_millis(100);
    const FOREVER: Duration = Duration::from_secs(3_600);

    #[test]
    fn dropping_waits_for_the_work_and_what_it_holds() {
        let released = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&released);
        let worker = Worker::spawn("test", move || {
            thread::sleep(WORK);
            held.store(true, Ordering::Relaxed);
        })
        .unwrap();
        drop(worker);
        assert!(released.load(Ordering::Relaxed));
    }

    #[test]
    fn dropping_gives_up_on_work_that_never_ends() {
        let worker = Worker::spawn_within("test", BOUND, || thread::sleep(FOREVER)).unwrap();
        let dropped = Instant::now();
        drop(worker);
        assert!(dropped.elapsed() < BOUND * 10, "{:?}", dropped.elapsed());
    }

    #[test]
    fn a_worker_dropped_on_its_own_thread_does_not_wait_for_itself() {
        let (handing, handed) = mpsc::channel::<Worker>();
        let (finishing, finished) = mpsc::channel();
        let worker = Worker::spawn_within("test", FOREVER, move || {
            drop(handed.recv());
            let _ = finishing.send(());
        })
        .unwrap();
        handing.send(worker).unwrap();
        assert_eq!(finished.recv_timeout(BOUND), Ok(()));
    }
}
