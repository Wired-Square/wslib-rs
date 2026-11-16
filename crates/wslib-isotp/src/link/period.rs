#[cfg(windows)]
mod windows {
    use windows_sys::Win32::Media::{TIMERR_NOERROR, timeBeginPeriod, timeEndPeriod};

    const PERIOD_MS: u32 = 1;

    pub(crate) struct Period {
        begun: bool,
    }

    impl Period {
        pub(crate) fn begin() -> Self {
            Self {
                begun: unsafe { timeBeginPeriod(PERIOD_MS) } == TIMERR_NOERROR,
            }
        }
    }

    impl Drop for Period {
        fn drop(&mut self) {
            if self.begun {
                unsafe { timeEndPeriod(PERIOD_MS) };
            }
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::Period;

#[cfg(not(windows))]
pub(crate) struct Period;

#[cfg(not(windows))]
impl Period {
    pub(crate) fn begin() -> Self {
        Self
    }
}
