//! Local command outcomes, distinct from RFC wire status codes. Rejections do
//! not change protocol state or terminate a healthy session.
use dlep_core::MacAddress;

use crate::FsmEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CommandKind {
    AddDestination,
    DropDestination,
    UpdateMetrics,
    UpdateAddresses,
    SessionAddresses,
    SessionMetrics,
    AnnounceDestination,
    LinkCharacteristics,
    LinkCharacteristicsResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandInfo {
    pub kind: CommandKind,
    /// None denotes a session-wide command.
    pub destination: Option<MacAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CommandError {
    #[error("a transaction for this scope is already in progress; retry after its response")]
    Busy,
    #[error("session is not established or is shutting down")]
    NotReady,
    #[error("destination is unknown on this session")]
    UnknownDestination,
    #[error("destination already exists on this session")]
    AlreadyExists,
    #[error("command is not supported by this role")]
    Unsupported,
    #[error("invalid or unencodable command values")]
    InvalidInput,
    #[error("no Link Characteristics Request from the peer awaits a response")]
    NoPendingRequest,
    #[error("destination MAC does not match the configured session address format")]
    MacAddressFormatMismatch,
}

impl CommandError {
    /// Stable snake_case name, as used by the bundled adapter protocols.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::NotReady => "not_ready",
            Self::UnknownDestination => "unknown_destination",
            Self::AlreadyExists => "already_exists",
            Self::Unsupported => "unsupported",
            Self::InvalidInput => "invalid_input",
            Self::NoPendingRequest => "no_pending_request",
            Self::MacAddressFormatMismatch => "mac_format_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandRejection {
    pub command: CommandInfo,
    pub reason: CommandError,
}

impl FsmEvent {
    pub fn command(&self) -> Option<CommandInfo> {
        use CommandKind as K;
        let (kind, destination) = match self {
            Self::AppAddDestination { mac, .. } => (K::AddDestination, Some(*mac)),
            Self::AppDropDestination { mac, .. } => (K::DropDestination, Some(*mac)),
            Self::AppUpdateMetrics { mac, .. } => (K::UpdateMetrics, Some(*mac)),
            Self::AppUpdateAddresses { mac, .. } => (K::UpdateAddresses, Some(*mac)),
            Self::AppSessionAddresses { .. } | Self::AppSetSessionAddresses { .. } => {
                (K::SessionAddresses, None)
            }
            Self::AppSessionUpdate { .. }
            | Self::AppSessionDefaults { .. }
            | Self::AppQueueSessionUpdate { .. } => (K::SessionMetrics, None),
            Self::AppAnnounceDestination { mac }
            | Self::AppAnnounceDestinationWithAddresses { mac, .. } => {
                (K::AnnounceDestination, Some(*mac))
            }
            Self::AppRequestLinkCharacteristics { mac, .. } => (K::LinkCharacteristics, Some(*mac)),
            Self::AppLinkCharacteristicsResponse { mac, .. } => {
                (K::LinkCharacteristicsResponse, Some(*mac))
            }
            // Shutdown bypasses transaction serialization, as required by §8.
            _ => return None,
        };
        Some(CommandInfo { kind, destination })
    }
}
