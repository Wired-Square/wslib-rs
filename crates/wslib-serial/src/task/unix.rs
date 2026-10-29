//! `O_RDONLY`, so no write path exists, and raw termios with software and
//! hardware flow control cleared explicitly: `cfmakeraw` leaves `IXOFF` as the
//! port had it, and with it set the kernel would put an XOFF on the wire.
//! `VMIN = 1`, so a read with nothing there is `WouldBlock` rather than zero:
//! zero is the line gone.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    mem,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
};

use tokio::io::{Interest, unix::AsyncFd};

use super::{LineSettings, Parity, SerialError, SerialOptions, check};

pub(super) struct Port {
    fd: AsyncFd<File>,
    buf: Vec<u8>,
}

impl Port {
    pub(super) fn open(
        path: &str,
        line: LineSettings,
        options: &SerialOptions,
    ) -> Result<Self, SerialError> {
        check(line)?;
        let speed = baud(line.baud).ok_or(SerialError::UnsupportedBaud(line.baud))?;
        let failed = |source| SerialError::Open {
            path: path.to_owned(),
            source,
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)
            .map_err(failed)?;
        configure(file.as_raw_fd(), line, speed, options.exclusive).map_err(failed)?;
        // SAFETY: the `AsyncFd` owns `file`, so its descriptor stays open and unchanged until drop.
        let fd = unsafe { AsyncFd::register(file) }.map_err(|e| failed(e.into()))?;
        Ok(Self {
            fd,
            buf: vec![0; options.read_buffer.max(1)],
        })
    }

    /// Cancel-safe.
    pub(super) async fn read(&mut self) -> Result<Vec<u8>, SerialError> {
        let buf = &mut self.buf;
        match self
            .fd
            .async_io(Interest::READABLE, |mut file| file.read(buf))
            .await
        {
            Ok(0) => Err(SerialError::Closed),
            Ok(n) => Ok(self.buf[..n].to_vec()),
            Err(e) => Err(SerialError::Read(e)),
        }
    }

    pub(super) async fn close(self) {}
}

fn ok(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn configure(
    fd: RawFd,
    line: LineSettings,
    speed: libc::speed_t,
    exclusive: bool,
) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor for the whole of this function, TIOCEXCL
    // takes no argument, and `t` is a termios the kernel filled before any use.
    unsafe {
        if exclusive {
            ok(libc::ioctl(fd, libc::TIOCEXCL as _))?;
        }
        let mut t: libc::termios = mem::zeroed();
        ok(libc::tcgetattr(fd, &mut t))?;
        libc::cfmakeraw(&mut t);
        ok(libc::cfsetspeed(&mut t, speed))?;
        t.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);
        t.c_cflag |= libc::CLOCAL | libc::CREAD;
        t.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::PARODD | libc::CSTOPB | libc::CRTSCTS);
        t.c_cflag |= match line.data_bits {
            5 => libc::CS5,
            6 => libc::CS6,
            7 => libc::CS7,
            _ => libc::CS8,
        };
        t.c_cflag |= match line.parity {
            Parity::None => 0,
            Parity::Even => libc::PARENB,
            Parity::Odd => libc::PARENB | libc::PARODD,
        };
        if line.stop_bits == 2 {
            t.c_cflag |= libc::CSTOPB;
        }
        ok(libc::tcsetattr(fd, libc::TCSANOW, &t))?;
        // Whatever arrived before the line was configured isn't this open's.
        ok(libc::tcflush(fd, libc::TCIFLUSH))
    }
}

/// macOS has no termios constant above 230 400 baud.
fn baud(rate: u32) -> Option<libc::speed_t> {
    Some(match rate {
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        #[cfg(target_os = "linux")]
        460800 => libc::B460800,
        #[cfg(target_os = "linux")]
        500000 => libc::B500000,
        #[cfg(target_os = "linux")]
        576000 => libc::B576000,
        #[cfg(target_os = "linux")]
        921600 => libc::B921600,
        #[cfg(target_os = "linux")]
        1000000 => libc::B1000000,
        #[cfg(target_os = "linux")]
        1152000 => libc::B1152000,
        #[cfg(target_os = "linux")]
        1500000 => libc::B1500000,
        #[cfg(target_os = "linux")]
        2000000 => libc::B2000000,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(baud: u32) -> LineSettings {
        LineSettings {
            baud,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
        }
    }

    #[test]
    fn standard_rates_map_to_their_kernel_constant() {
        assert_eq!(baud(9600), Some(libc::B9600));
        assert_eq!(baud(115200), Some(libc::B115200));
        assert_eq!(baud(230400), Some(libc::B230400));
        assert_eq!(baud(9601), None);
        assert_eq!(baud(0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_maps_rates_above_230400() {
        assert_eq!(baud(460800), Some(libc::B460800));
        assert_eq!(baud(921600), Some(libc::B921600));
        assert_eq!(baud(2000000), Some(libc::B2000000));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_refuses_rates_above_230400_before_opening() {
        for rate in [460800, 921600, 2000000] {
            let refused = Port::open("/nonexistent", line(rate), &SerialOptions::default());
            assert!(matches!(refused, Err(SerialError::UnsupportedBaud(r)) if r == rate));
        }
    }

    #[test]
    fn a_rate_with_no_constant_is_refused_before_opening() {
        let refused = Port::open("/nonexistent", line(9601), &SerialOptions::default());
        assert!(matches!(refused, Err(SerialError::UnsupportedBaud(9601))));
    }
}
