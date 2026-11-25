//! UDS (ISO 14229-1), sans-IO and transport-agnostic: it takes and returns
//! message bytes, and the caller supplies the time.
//!
//! Every service decodes and encodes with no feature: the ones this crate
//! models typed, any other as its service id and bytes. [`Safety::of`] classes
//! a request, and a [`Client`] built without `write` sends only
//! [`Safety::ReadOnly`] ones; with it, only those up to the ceiling it was
//! built with. A bare service id has its service's class with the
//! sub-function unknown.
//!
//! | Request | Safety |
//! | --- | --- |
//! | ReadDTCInformation 0x19, ReadDataByIdentifier 0x22, TesterPresent 0x3E | read-only |
//! | RoutineControl 0x31 requestRoutineResults (0x03) | read-only |
//! | DiagnosticSessionControl 0x10 to any session but programming, ECUReset 0x11, ReadMemoryByAddress 0x23, SecurityAccess 0x27, CommunicationControl 0x28, ControlDTCSetting 0x85 | state-changing |
//! | DiagnosticSessionControl 0x10 to the programming session (0x02), or a bare 0x10 | destructive |
//! | ClearDiagnosticInformation 0x14, WriteDataByIdentifier 0x2E, InputOutputControlByIdentifier 0x2F | destructive |
//! | RoutineControl 0x31 start, stop, any other sub-function or none | destructive |
//! | RequestDownload 0x34, RequestUpload 0x35, TransferData 0x36, RequestTransferExit 0x37 | destructive |
//! | Any other service, ISO or vendor, and an empty message | destructive |

mod answer;
mod client;
mod codec;
mod identify;
mod nrc;
#[cfg(feature = "isotp")]
mod orient;
mod pairing;
mod safety;
mod scan;
pub mod sid;

#[cfg(feature = "testing")]
pub mod testing;

pub use answer::{Answer, answers};
#[cfg(feature = "write")]
pub use client::SendError;
pub use client::{Busy, Client, Event, Timing};
pub use codec::{
    BlockLength, DEFAULT_SESSION, DecodeError, Dtc, DtcRequest, DtcResponse, DtcStatus,
    EXTENDED_SESSION, EmptyList, InvalidReportType, InvalidWidth, MemoryRange, NonEmpty,
    OtherReportType, OtherResponseReportType, PROGRAMMING_SESSION, Request, Response,
    SessionTiming, SubFunction,
};
pub use identify::{Detail, Identity, identify};
pub use nrc::Nrc;
#[cfg(feature = "isotp")]
pub use orient::{
    Conversation, Endpoint, MAX_MESSAGE_BYTES, MAX_PARTNERS, Orientation, Unsettled, orient,
};
pub use pairing::{
    DEFAULT_TIMEOUT_US, MAX_OPEN_REQUESTS, Observed, Outcome, Sender, Tracker, Transaction,
};
pub use safety::{NotReadOnly, ReadOnly, Safety};
pub use scan::{
    AddressProbe, AddressScan, DEFAULT_BUSY_RETRIES, DidFinding, DidProbe, DidScan, DidVerdict,
    ReadOnlyServiceProbe, ReadOnlyServiceScan, ScanProgress, ServiceFinding, ServiceProbe,
    ServiceScan, ServiceVerdict, did_verdict, ecu_answered, service_verdict,
};
#[cfg(feature = "write")]
pub use scan::{SessionFinding, SessionProbe, SessionScan, SessionVerdict, session_verdict};

/// Without `write`, a client sends only read-only requests, a service scan
/// probes only read-only bare ids, and there is no session scan: none of these
/// builds.
///
/// ```compile_fail
/// let _ = wslib_uds::Client::send;
/// ```
/// ```compile_fail
/// use wslib_uds::SessionScan;
/// ```
/// ```compile_fail
/// let _ = wslib_uds::ServiceScan::up_to(wslib_uds::Safety::Destructive);
/// ```
/// ```compile_fail
/// let request = wslib_uds::Request::EcuReset { sub_function: wslib_uds::SubFunction::new(1) };
/// let _ = wslib_uds::ReadOnly(request);
/// ```
#[cfg(all(doctest, not(feature = "write")))]
pub struct NoWritePath;
