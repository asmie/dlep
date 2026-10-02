//! Local command outcomes, distinct from RFC wire status codes. Rejections do
//! not change protocol state or terminate a healthy session.
use dlep_core::MacAddress;

use crate::FsmEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandKind {
    AddDestination,
    DropDestination,
    UpdateMetrics,
    UpdateAddresses,
    SessionAddresses,
    SessionMetrics,
    AnnounceDestination,
    LinkCharacteristics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandInfo {
    pub kind: CommandKind,
    /// None denotes a session-wide command.
    pub destination: Option<MacAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
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
            Self::AppSessionAddresses { .. } => (K::SessionAddresses, None),
            Self::AppSessionUpdate { .. } => (K::SessionMetrics, None),
            Self::AppAnnounceDestination { mac } => (K::AnnounceDestination, Some(*mac)),
            Self::AppRequestLinkCharacteristics { mac, .. } => (K::LinkCharacteristics, Some(*mac)),
            // Shutdown bypasses transaction serialization, as required by §8.
            _ => return None,
        };
        Some(CommandInfo { kind, destination })
    }
}
