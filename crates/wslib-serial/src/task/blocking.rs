//! serialport, read on the blocking pool with a 50 ms timeout, so a stop or a
//! write waits for at most one read. serialport opens every port read-write,
//! and a Windows one always exclusively; without `write` no write code exists.

use std::{io, mem, time::Duration};

use serialport::{DataBits, FlowControl, StopBits};
use tokio::task::{JoinError, JoinHandle, spawn_blocking};

use super::{LineSettings, Parity, SerialError, SerialOptions, check};

const READ_TIMEOUT: Duration = Duration::from_millis(50);

type Boxed = Box<dyn serialport::SerialPort>;

/// A port opened read-write through serialport, for a protocol that drives the
/// line itself rather than through a [`SerialTask`](super::SerialTask). A
/// write cancelled once started still runs, and its failure is the next call's
/// answer.
pub struct SerialPort {
    state: State,
    /// A read that finished while a write waited for the port.
    unread: Option<io::Result<Vec<u8>>>,
    read_buffer: usize,
}

enum State {
    Idle(Boxed),
    /// Kept across a cancelled `read`, so the next call or `close` picks it up.
    Reading(JoinHandle<(Boxed, io::Result<Vec<u8>>)>),
    /// Kept across a cancelled `write`, as `Reading` is.
    #[cfg_attr(not(feature = "write"), allow(dead_code))]
    Writing(JoinHandle<(Boxed, io::Result<()>)>),
    Gone,
}

impl SerialPort {
    /// Takes `exclusive` and `read_buffer` from `options`.
    pub fn open(
        path: &str,
        line: LineSettings,
        options: &SerialOptions,
    ) -> Result<Self, SerialError> {
        check(line)?;
        let builder = serialport::new(path, line.baud)
            .data_bits(match line.data_bits {
                5 => DataBits::Five,
                6 => DataBits::Six,
                7 => DataBits::Seven,
                _ => DataBits::Eight,
            })
            .parity(match line.parity {
                Parity::None => serialport::Parity::None,
                Parity::Even => serialport::Parity::Even,
                Parity::Odd => serialport::Parity::Odd,
            })
            .stop_bits(match line.stop_bits {
                2 => StopBits::Two,
                _ => StopBits::One,
            })
            .flow_control(FlowControl::None)
            .timeout(READ_TIMEOUT);
        #[cfg(unix)]
        let builder = builder.exclusive(options.exclusive);
        let port = builder.open().map_err(|e| SerialError::Open {
            path: path.to_owned(),
            source: e.into(),
        })?;
        Ok(Self {
            state: State::Idle(port),
            unread: None,
            read_buffer: options.read_buffer.max(1),
        })
    }

    /// The next bytes off the line, never empty. Cancel-safe.
    pub async fn read(&mut self) -> Result<Vec<u8>, SerialError> {
        loop {
            let read = match self.unread.take() {
                Some(read) => read,
                None => self.next_read().await?,
            };
            match read {
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Ok(bytes) if bytes.is_empty() => return Err(SerialError::Closed),
                read => return read.map_err(SerialError::Read),
            }
        }
    }

    /// `write_all`, once any read or write in flight has returned; it returns
    /// once the bytes are queued, not sent. Cancel-safe: `bytes` is taken only
    /// when the write starts.
    #[cfg(feature = "write")]
    pub async fn write(&mut self, bytes: &mut Vec<u8>) -> Result<(), SerialError> {
        let mut port = self.idle().await?;
        let bytes = mem::take(bytes);
        self.state = State::Writing(spawn_blocking(move || {
            let written = port.write_all(&bytes);
            (port, written)
        }));
        self.written().await
    }

    /// Asserts DTR when `level` is true, once any read or write in flight has
    /// returned.
    #[cfg(feature = "write")]
    pub async fn set_dtr(&mut self, level: bool) -> Result<(), SerialError> {
        self.control(move |port| port.write_data_terminal_ready(level))
            .await
    }

    /// Asserts RTS when `level` is true, as [`set_dtr`](Self::set_dtr) does DTR.
    #[cfg(feature = "write")]
    pub async fn set_rts(&mut self, level: bool) -> Result<(), SerialError> {
        self.control(move |port| port.write_request_to_send(level))
            .await
    }

    #[cfg(feature = "write")]
    async fn control(
        &mut self,
        set: impl FnOnce(&mut Boxed) -> serialport::Result<()> + Send + 'static,
    ) -> Result<(), SerialError> {
        let mut port = self.idle().await?;
        self.state = State::Writing(spawn_blocking(move || {
            let set = set(&mut port).map_err(io::Error::from);
            (port, set)
        }));
        self.written().await
    }

    /// The port, taken once any read or write in flight has returned.
    #[cfg(feature = "write")]
    async fn idle(&mut self) -> Result<Boxed, SerialError> {
        if let State::Reading(_) = self.state {
            self.unread = Some(self.read_in_flight().await?);
        }
        self.written().await?;
        match mem::replace(&mut self.state, State::Gone) {
            State::Idle(port) => Ok(port),
            _ => Err(SerialError::Write(io::ErrorKind::NotConnected.into())),
        }
    }

    /// A second handle on the idle port, for a write that can't wait for a read.
    /// It shares the port's settings, so it must not change them.
    #[cfg(feature = "write")]
    pub fn try_clone(&self) -> io::Result<Box<dyn io::Write + Send>> {
        let State::Idle(port) = &self.state else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        Ok(port.try_clone()?)
    }

    /// Waits for a read or write in flight, then discards unsent output and
    /// closes the port.
    pub async fn close(self) {
        let port = match self.state {
            State::Idle(port) => Some(port),
            State::Reading(handle) => handle.await.ok().map(|(port, _)| port),
            State::Writing(handle) => handle.await.ok().map(|(port, _)| port),
            State::Gone => None,
        };
        // Linux waits out `closing_wait`, 30 s by default, to close a port
        // holding output that a halted device never took.
        if let Some(port) = port {
            let _ = port.clear(serialport::ClearBuffer::Output);
        }
    }

    /// The write in flight's result, if there is one.
    async fn written(&mut self) -> Result<(), SerialError> {
        let State::Writing(handle) = &mut self.state else {
            return Ok(());
        };
        let joined = handle.await;
        self.state = State::Gone;
        let (port, written) = finished(joined)?;
        self.state = State::Idle(port);
        written.map_err(SerialError::Write)
    }

    async fn next_read(&mut self) -> Result<io::Result<Vec<u8>>, SerialError> {
        self.written().await?;
        self.state = match mem::replace(&mut self.state, State::Gone) {
            State::Idle(port) => {
                let len = self.read_buffer;
                State::Reading(spawn_blocking(move || read_once(port, len)))
            }
            other => other,
        };
        let State::Reading(_) = self.state else {
            return Err(SerialError::Closed);
        };
        self.read_in_flight().await
    }

    async fn read_in_flight(&mut self) -> Result<io::Result<Vec<u8>>, SerialError> {
        let State::Reading(handle) = &mut self.state else {
            return Err(SerialError::Closed);
        };
        let joined = handle.await;
        self.state = State::Gone;
        let (port, read) = finished(joined)?;
        self.state = State::Idle(port);
        Ok(read)
    }
}

fn finished<T>(joined: Result<T, JoinError>) -> Result<T, SerialError> {
    joined.map_err(|e| {
        if e.is_panic() {
            SerialError::Panicked
        } else {
            SerialError::Cancelled
        }
    })
}

fn read_once(mut port: Boxed, len: usize) -> (Boxed, io::Result<Vec<u8>>) {
    let mut buf = vec![0; len];
    let read = port.read(&mut buf).map(|n| {
        buf.truncate(n);
        buf
    });
    (port, read)
}

#[cfg(test)]
pub(super) mod tests {
    use std::{
        io::{Read, Write},
        sync::mpsc,
    };

    use tokio::runtime::Builder;

    use super::*;

    const LINE: LineSettings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    fn panicked<T: Send + 'static>() -> Result<T, JoinError> {
        Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                spawn_blocking(|| -> T { panic!("a blocking call panicked") }).await
            })
    }

    fn cancelled() -> Result<(), JoinError> {
        let runtime = Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, held) = mpsc::channel::<()>();
            let busy = spawn_blocking(move || held.recv());
            let queued = spawn_blocking(|| ());
            queued.abort();
            release.send(()).unwrap();
            busy.await.unwrap().unwrap();
            queued.await
        })
    }

    #[test]
    fn a_blocking_call_that_panicked_is_panicked_and_one_cancelled_is_cancelled() {
        assert!(matches!(
            finished(panicked::<()>()),
            Err(SerialError::Panicked)
        ));
        let cancelled = finished(cancelled());
        assert!(
            matches!(cancelled, Err(SerialError::Cancelled)),
            "{cancelled:?}"
        );
    }

    #[test]
    fn a_blocking_call_that_returned_is_its_result() {
        let runtime = Builder::new_current_thread().build().unwrap();
        let joined = runtime.block_on(async { spawn_blocking(|| 1).await });
        assert_eq!(finished(joined).unwrap(), 1);
    }

    struct Panicking;

    impl Read for Panicking {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read panicked")
        }
    }

    impl Write for Panicking {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("write panicked")
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl serialport::SerialPort for Panicking {
        fn name(&self) -> Option<String> {
            None
        }
        fn baud_rate(&self) -> serialport::Result<u32> {
            Ok(LINE.baud)
        }
        fn data_bits(&self) -> serialport::Result<DataBits> {
            Ok(DataBits::Eight)
        }
        fn flow_control(&self) -> serialport::Result<FlowControl> {
            Ok(FlowControl::None)
        }
        fn parity(&self) -> serialport::Result<serialport::Parity> {
            Ok(serialport::Parity::None)
        }
        fn stop_bits(&self) -> serialport::Result<StopBits> {
            Ok(StopBits::One)
        }
        fn timeout(&self) -> Duration {
            READ_TIMEOUT
        }
        fn set_baud_rate(&mut self, _: u32) -> serialport::Result<()> {
            Ok(())
        }
        fn set_data_bits(&mut self, _: DataBits) -> serialport::Result<()> {
            Ok(())
        }
        fn set_flow_control(&mut self, _: FlowControl) -> serialport::Result<()> {
            Ok(())
        }
        fn set_parity(&mut self, _: serialport::Parity) -> serialport::Result<()> {
            Ok(())
        }
        fn set_stop_bits(&mut self, _: StopBits) -> serialport::Result<()> {
            Ok(())
        }
        fn set_timeout(&mut self, _: Duration) -> serialport::Result<()> {
            Ok(())
        }
        fn write_request_to_send(&mut self, _: bool) -> serialport::Result<()> {
            panic!("RTS panicked")
        }
        fn write_data_terminal_ready(&mut self, _: bool) -> serialport::Result<()> {
            panic!("DTR panicked")
        }
        fn read_clear_to_send(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn read_data_set_ready(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn read_ring_indicator(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn read_carrier_detect(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn bytes_to_read(&self) -> serialport::Result<u32> {
            Ok(0)
        }
        fn bytes_to_write(&self) -> serialport::Result<u32> {
            Ok(0)
        }
        fn clear(&self, _: serialport::ClearBuffer) -> serialport::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> serialport::Result<Box<dyn serialport::SerialPort>> {
            Ok(Box::new(Panicking))
        }
        fn set_break(&self) -> serialport::Result<()> {
            Ok(())
        }
        fn clear_break(&self) -> serialport::Result<()> {
            Ok(())
        }
    }

    pub(in crate::task) fn panicking() -> SerialPort {
        SerialPort {
            state: State::Idle(Box::new(Panicking)),
            unread: None,
            read_buffer: 1,
        }
    }

    #[tokio::test]
    async fn a_read_that_panicked_is_panicked_and_leaves_the_port_closed() {
        let mut port = panicking();
        assert!(matches!(port.read().await, Err(SerialError::Panicked)));
        assert!(matches!(port.read().await, Err(SerialError::Closed)));
    }

    #[cfg(feature = "write")]
    #[tokio::test]
    async fn a_write_behind_a_read_that_panicked_is_panicked_and_takes_none_of_its_bytes() {
        let mut port = SerialPort {
            state: State::Reading(spawn_blocking(|| -> (Boxed, io::Result<Vec<u8>>) {
                panic!("read panicked")
            })),
            unread: None,
            read_buffer: 1,
        };
        let mut bytes = b"x".to_vec();
        let written = port.write(&mut bytes).await;
        assert!(matches!(written, Err(SerialError::Panicked)), "{written:?}");
        assert_eq!(bytes, b"x");
        assert!(matches!(port.read().await, Err(SerialError::Closed)));
    }

    fn writing(write: impl FnOnce() -> (Boxed, io::Result<()>) + Send + 'static) -> SerialPort {
        SerialPort {
            state: State::Writing(spawn_blocking(write)),
            unread: None,
            read_buffer: 1,
        }
    }

    fn broken_pipe() -> (Boxed, io::Result<()>) {
        (Box::new(Panicking), Err(io::ErrorKind::BrokenPipe.into()))
    }

    #[tokio::test]
    async fn a_cancelled_write_that_failed_is_the_next_reads_answer() {
        let mut port = writing(|| panic!("write panicked"));
        assert!(matches!(port.read().await, Err(SerialError::Panicked)));
        let read = writing(broken_pipe).read().await;
        assert!(
            matches!(&read, Err(SerialError::Write(e)) if e.kind() == io::ErrorKind::BrokenPipe),
            "{read:?}"
        );
    }

    #[cfg(feature = "write")]
    #[tokio::test]
    async fn a_cancelled_write_that_failed_is_the_next_writes_answer_and_leaves_its_bytes() {
        let mut bytes = b"x".to_vec();
        assert!(matches!(
            writing(|| panic!("write panicked")).write(&mut bytes).await,
            Err(SerialError::Panicked)
        ));
        let mut port = writing(broken_pipe);
        let written = port.write(&mut bytes).await;
        assert!(
            matches!(&written, Err(SerialError::Write(e)) if e.kind() == io::ErrorKind::BrokenPipe),
            "{written:?}"
        );
        assert_eq!(bytes, b"x");
        assert!(matches!(
            port.write(&mut bytes).await,
            Err(SerialError::Panicked)
        ));
    }

    #[cfg(feature = "write")]
    #[tokio::test]
    async fn a_write_or_control_change_that_panicked_is_panicked() {
        assert!(matches!(
            panicking().write(&mut b"x".to_vec()).await,
            Err(SerialError::Panicked)
        ));
        assert!(matches!(
            panicking().set_dtr(true).await,
            Err(SerialError::Panicked)
        ));
        assert!(matches!(
            panicking().set_rts(true).await,
            Err(SerialError::Panicked)
        ));
    }
}
