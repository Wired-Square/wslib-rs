use crate::avahi::{self, Avahi};
use crate::in_process::{InProcess, Options};
use crate::{Advert, Error, Service};

/// Whichever responder this machine has: avahi where it runs, else in process.
#[derive(Debug, Clone)]
pub enum Responder {
    Avahi(Avahi),
    InProcess(InProcess),
}

impl Responder {
    /// avahi if anything owns its name on the system bus, else an
    /// [`InProcess`] made with `options`.
    pub async fn system(options: Options) -> Result<Self, Error> {
        if let Ok(bus) = zbus::Connection::system().await
            && avahi::is_running(&bus).await.unwrap_or(false)
        {
            return Ok(Self::Avahi(Avahi::new(&bus)));
        }
        InProcess::new(options).map(Self::InProcess)
    }

    pub async fn advertise(&self, service: &Service) -> Result<Advert, Error> {
        match self {
            Self::Avahi(avahi) => avahi.advertise(service).await,
            Self::InProcess(in_process) => in_process.advertise(service).await,
        }
    }
}
