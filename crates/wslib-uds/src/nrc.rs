use std::fmt;

use serde::{Deserialize, Serialize};

/// A negative response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsNrc"))]
#[serde(transparent)]
pub struct Nrc(pub u8);

impl Nrc {
    pub const GENERAL_REJECT: Nrc = Nrc(0x10);
    pub const SERVICE_NOT_SUPPORTED: Nrc = Nrc(0x11);
    pub const SUB_FUNCTION_NOT_SUPPORTED: Nrc = Nrc(0x12);
    pub const INCORRECT_MESSAGE_LENGTH: Nrc = Nrc(0x13);
    pub const BUSY_REPEAT_REQUEST: Nrc = Nrc(0x21);
    pub const CONDITIONS_NOT_CORRECT: Nrc = Nrc(0x22);
    pub const REQUEST_SEQUENCE_ERROR: Nrc = Nrc(0x24);
    pub const REQUEST_OUT_OF_RANGE: Nrc = Nrc(0x31);
    pub const SECURITY_ACCESS_DENIED: Nrc = Nrc(0x33);
    pub const INVALID_KEY: Nrc = Nrc(0x35);
    pub const EXCEEDED_NUMBER_OF_ATTEMPTS: Nrc = Nrc(0x36);
    pub const REQUIRED_TIME_DELAY_NOT_EXPIRED: Nrc = Nrc(0x37);
    pub const RESPONSE_PENDING: Nrc = Nrc(0x78);
    pub const SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION: Nrc = Nrc(0x7E);
    pub const SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION: Nrc = Nrc(0x7F);

    /// The standard name, or `None` for a reserved code.
    pub fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x10 => "generalReject",
            0x11 => "serviceNotSupported",
            0x12 => "subFunctionNotSupported",
            0x13 => "incorrectMessageLengthOrInvalidFormat",
            0x14 => "responseTooLong",
            0x21 => "busyRepeatRequest",
            0x22 => "conditionsNotCorrect",
            0x24 => "requestSequenceError",
            0x25 => "noResponseFromSubnetComponent",
            0x26 => "failurePreventsExecutionOfRequestedAction",
            0x31 => "requestOutOfRange",
            0x33 => "securityAccessDenied",
            0x34 => "authenticationRequired",
            0x35 => "invalidKey",
            0x36 => "exceededNumberOfAttempts",
            0x37 => "requiredTimeDelayNotExpired",
            0x38 => "secureDataTransmissionRequired",
            0x39 => "secureDataTransmissionNotAllowed",
            0x3A => "secureDataVerificationFailed",
            0x50 => "certificateVerificationFailedInvalidTimePeriod",
            0x51 => "certificateVerificationFailedInvalidSignature",
            0x52 => "certificateVerificationFailedInvalidChainOfTrust",
            0x53 => "certificateVerificationFailedInvalidType",
            0x54 => "certificateVerificationFailedInvalidFormat",
            0x55 => "certificateVerificationFailedInvalidContent",
            0x56 => "certificateVerificationFailedInvalidScope",
            0x57 => "certificateVerificationFailedInvalidCertificate",
            0x58 => "ownershipVerificationFailed",
            0x59 => "challengeCalculationFailed",
            0x5A => "settingAccessRightsFailed",
            0x5B => "sessionKeyCreationDerivationFailed",
            0x5C => "configurationDataUsageFailed",
            0x5D => "deAuthenticationFailed",
            0x70 => "uploadDownloadNotAccepted",
            0x71 => "transferDataSuspended",
            0x72 => "generalProgrammingFailure",
            0x73 => "wrongBlockSequenceCounter",
            0x78 => "requestCorrectlyReceivedResponsePending",
            0x7E => "subFunctionNotSupportedInActiveSession",
            0x7F => "serviceNotSupportedInActiveSession",
            0x81 => "rpmTooHigh",
            0x82 => "rpmTooLow",
            0x83 => "engineIsRunning",
            0x84 => "engineIsNotRunning",
            0x85 => "engineRunTimeTooLow",
            0x86 => "temperatureTooHigh",
            0x87 => "temperatureTooLow",
            0x88 => "vehicleSpeedTooHigh",
            0x89 => "vehicleSpeedTooLow",
            0x8A => "throttlePedalTooHigh",
            0x8B => "throttlePedalTooLow",
            0x8C => "transmissionRangeNotInNeutral",
            0x8D => "transmissionRangeNotInGear",
            0x8F => "brakeSwitchesNotClosed",
            0x90 => "shifterLeverNotInPark",
            0x91 => "torqueConverterClutchLocked",
            0x92 => "voltageTooHigh",
            0x93 => "voltageTooLow",
            0x94 => "resourceTemporarilyNotAvailable",
            0xF0..=0xFE => "vehicleManufacturerSpecificConditionsNotCorrect",
            _ => return None,
        })
    }
}

impl fmt::Display for Nrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:02X})", self.0),
            None => write!(f, "0x{:02X}", self.0),
        }
    }
}
