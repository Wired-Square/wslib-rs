//! serialport, read on the blocking pool with a 50 ms timeout, so a stop or a
//! write waits for at most one read. serialport opens every port read-write,
//! and a Windows one always exclusively; without `write` no write code exists.

use std::{io, mem, time::Duration};

use serialport::{DataBits, FlowControl, StopBits};
use tokio::task::{JoinHandle, spawn_blocking};

use super::{LineSettings, Parity, SerialError, SerialOptions, check};

const READ_TIMEOUT: Duration = Duration::from_millis(50);

type Boxed = Box<dyn serialport::SerialPort>;

/// A port opened read-write through serialport, for a protocol that drives the
/// line itself rather than through a [`SerialTask`](super::SerialTask).
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
    pub async fn write(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
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
    pub async fn set_dtr(&mut self, level: bool) -> io::Result<()> {
        self.control(move |port| port.write_data_terminal_ready(level))
            .await
    }

    /// Asserts RTS when `level` is true, as [`set_dtr`](Self::set_dtr) does DTR.
    #[cfg(feature = "write")]
    pub async fn set_rts(&mut self, level: bool) -> io::Result<()> {
        self.control(move |port| port.write_request_to_send(level))
            .await
    }

    #[cfg(feature = "write")]
    async fn control(
        &mut self,
        set: impl FnOnce(&mut Boxed) -> serialport::Result<()> + Send + 'static,
    ) -> io::Result<()> {
        let mut port = self.idle().await?;
        self.state = State::Writing(spawn_blocking(move || {
            let set = set(&mut port).map_err(io::Error::from);
            (port, set)
        }));
        self.written().await
    }

    /// The port, taken once any read or write in flight has returned.
    #[cfg(feature = "write")]
    async fn idle(&mut self) -> io::Result<Boxed> {
        if let State::Reading(_) = self.state {
            self.unread = Some(self.next_read().await.map_err(io::Error::other)?);
        }
        let _ = self.written().await;
        match mem::replace(&mut self.state, State::Gone) {
            State::Idle(port) => Ok(port),
            _ => Err(io::ErrorKind::NotConnected.into()),
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
    async fn written(&mut self) -> io::Result<()> {
        let State::Writing(handle) = &mut self.state else {
            return Ok(());
        };
        let joined = handle.await;
        self.state = State::Gone;
        let (port, written) = joined.map_err(io::Error::other)?;
        self.state = State::Idle(port);
        written
    }

    async fn next_read(&mut self) -> Result<io::Result<Vec<u8>>, SerialError> {
        let _ = self.written().await;
        self.state = match mem::replace(&mut self.state, State::Gone) {
            State::Idle(port) => {
                let len = self.read_buffer;
                State::Reading(spawn_blocking(move || read_once(port, len)))
            }
            other => other,
        };
        let State::Reading(handle) = &mut self.state else {
            return Err(SerialError::Closed);
        };
        let joined = handle.await;
        self.state = State::Gone;
        let (port, read) = joined.map_err(|e| SerialError::Read(io::Error::other(e)))?;
        self.state = State::Idle(port);
        Ok(read)
    }
}

fn read_once(mut port: Boxed, len: usize) -> (Boxed, io::Result<Vec<u8>>) {
    let mut buf = vec![0; len];
    let read = port.read(&mut buf).map(|n| {
        buf.truncate(n);
        buf
    });
    (port, read)
}
