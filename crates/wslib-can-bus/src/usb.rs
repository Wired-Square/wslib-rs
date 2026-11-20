use std::io;

use crate::{
    bus::CanBus,
    error::{OpenCause, OpenError},
};

const NO_SERIAL: &str = "(no serial)";
const LIST_SEPARATOR: &str = ", ";

pub(crate) fn only_adapter<D>(
    bus: &CanBus,
    found: io::Result<Vec<D>>,
    wanted: Option<&str>,
    serial_of: fn(&D) -> Option<&str>,
) -> Result<D, OpenError> {
    let failed = |source| OpenError::Open {
        bus: bus.clone(),
        source: OpenCause::Io(source),
    };
    let found = found.map_err(failed)?;
    let listed = found
        .iter()
        .map(|device| serial_of(device).unwrap_or(NO_SERIAL))
        .collect::<Vec<_>>()
        .join(LIST_SEPARATOR);
    let mut matching: Vec<D> = found
        .into_iter()
        .filter(|device| wanted.is_none_or(|wanted| serial_of(device) == Some(wanted)))
        .collect();
    match matching.len() {
        1 => Ok(matching.remove(0)),
        0 if listed.is_empty() => Err(failed(io::Error::new(
            io::ErrorKind::NotFound,
            "no adapter found",
        ))),
        0 => Err(failed(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no adapter has that serial; found {listed}"),
        ))),
        _ => Err(failed(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "several adapters found ({listed}); name one as {}=<serial>",
                without_serial(bus)
            ),
        ))),
    }
}

fn without_serial(bus: &CanBus) -> CanBus {
    match bus {
        CanBus::GsUsb { .. } => CanBus::GsUsb { serial: None },
        CanBus::Pcan { .. } => CanBus::Pcan { serial: None },
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests;
