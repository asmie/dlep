//! Modem link-control backend for Link Characteristics Requests (RFC 8175
//! §12.18–12.19).
//!
//! A router may ask a modem to change a destination's data rate or latency.
//! Without a backend, [`crate::ModemDaemon`] immediately replies Request
//! Denied with the current metrics. A backend registered through
//! [`crate::ModemBuilder::link_control`] receives each request instead and
//! decides the response, which may take as long as the radio needs: RFC 8175
//! §8 gives transactions no deadline, and the router detects a failed modem
//! through the session heartbeat.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dlep_core::{MacAddress, StatusCode};
use dlep_ext::SessionId;
use dlep_fsm::FsmEvent;
use tokio::task::{Id, JoinSet};
use tracing::warn;

use crate::events::{DestinationId, LinkCharacteristics, LinkMetrics, PeerInfo};

/// One router request, scoped to the session it arrived on.
#[derive(Clone, Debug)]
pub struct LinkRequest {
    pub session_id: SessionId,
    pub peer: PeerInfo,
    pub id: DestinationId,
    /// Requested characteristics; omitted fields are not change requests.
    pub requested: LinkCharacteristics,
    /// Effective destination metrics on this session when the request arrived.
    pub current: LinkMetrics,
}

/// The backend's answer, sent as the Link Characteristics Response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkResponse {
    /// Success when the change was applied, Request Denied when it cannot be
    /// met (§12.19). Statuses that terminate the session are not allowed.
    pub status: StatusCode,
    pub text: String,
    /// Link metrics after processing, merged like
    /// [`crate::ModemDaemon::update_destination`]: omitted optional values are
    /// retained. None reports the destination's current metrics unchanged.
    /// The response always carries every metric declared for the session.
    pub metrics: Option<LinkMetrics>,
}

impl LinkResponse {
    /// The change was applied; `metrics` describe the link now.
    pub fn granted(metrics: LinkMetrics) -> Self {
        Self {
            status: StatusCode::SUCCESS,
            text: String::new(),
            metrics: Some(metrics),
        }
    }

    /// The change cannot be met; the link keeps its current metrics.
    pub fn denied() -> Self {
        Self {
            status: StatusCode::REQUEST_DENIED,
            text: String::new(),
            metrics: None,
        }
    }

    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    fn into_event(self, mac: MacAddress) -> FsmEvent {
        FsmEvent::AppLinkCharacteristicsResponse {
            mac,
            status: self.status,
            text: self.text,
            metrics: self.metrics,
        }
    }
}

pub type LinkControlFuture = Pin<Box<dyn Future<Output = LinkResponse> + Send + 'static>>;

/// Applies router-requested link changes on behalf of the modem daemon.
///
/// The returned future runs on its own task. It is dropped without a response
/// if the session ends first; the response is meaningless after a session
/// reset. Each destination has at most one outstanding request per session,
/// but requests for different destinations or sessions run concurrently.
/// A granted change is reported only to the requesting router; call
/// [`crate::ModemDaemon::update_destination`] if other sessions report the
/// same destination. An invalid response or a panic results in Request Denied.
///
/// Closures returning a `Send` future implement this trait:
///
/// ```
/// use std::sync::Arc;
/// use dlep_daemon::link_control::{LinkControl, LinkRequest, LinkResponse};
///
/// let backend: Arc<dyn LinkControl> = Arc::new(|request: LinkRequest| async move {
///     match request.requested.latency {
///         Some(_) => LinkResponse::denied().with_text("latency is fixed"),
///         None => LinkResponse::granted(request.current),
///     }
/// });
/// ```
pub trait LinkControl: Send + Sync + 'static {
    fn request(&self, request: LinkRequest) -> LinkControlFuture;
}

impl<F, Fut> LinkControl for F
where
    F: Fn(LinkRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = LinkResponse> + Send + 'static,
{
    fn request(&self, request: LinkRequest) -> LinkControlFuture {
        Box::pin(self(request))
    }
}

/// Backend calls in flight for one session. Dropping it aborts them.
#[derive(Default)]
pub(crate) struct LinkJobs {
    backend: Option<Arc<dyn LinkControl>>,
    tasks: JoinSet<LinkResponse>,
    macs: HashMap<Id, MacAddress>,
}

impl LinkJobs {
    pub(crate) fn new(backend: Option<Arc<dyn LinkControl>>) -> Self {
        Self {
            backend,
            ..Self::default()
        }
    }

    /// Without a backend, a deferred request is denied rather than left
    /// pending for the rest of the session.
    pub(crate) fn start(&mut self, request: LinkRequest) {
        let mac = request.id.0;
        let handle = match &self.backend {
            Some(backend) => {
                let backend = Arc::clone(backend);
                self.tasks
                    .spawn(async move { backend.request(request).await })
            }
            None => self.tasks.spawn(async { LinkResponse::denied() }),
        };
        self.macs.insert(handle.id(), mac);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Next completed answer as the FSM event that sends it.
    pub(crate) async fn next(&mut self) -> Option<FsmEvent> {
        let (id, response) = match self.tasks.join_next_with_id().await? {
            Ok((id, response)) => (id, response),
            Err(error) => {
                warn!("link-control backend failed: {error}; denying the request");
                (error.id(), LinkResponse::denied())
            }
        };
        let mac = self.macs.remove(&id).expect("tracked link-control task");
        Some(response.into_event(mac))
    }
}

/// Request Denied with current metrics, used when the FSM rejects a backend
/// answer so the router's transaction still completes.
pub(crate) fn fallback_denial(event: &FsmEvent) -> Option<FsmEvent> {
    match event {
        FsmEvent::AppLinkCharacteristicsResponse { mac, .. } => {
            Some(LinkResponse::denied().into_event(*mac))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn synchronous_backend_panic_becomes_denial() {
        let backend = |_request: LinkRequest| -> LinkControlFuture {
            panic!("backend panicked before returning its future")
        };
        let mut jobs = LinkJobs::new(Some(Arc::new(backend)));

        // A failed request must leave the job queue usable for the next one.
        for suffix in [1, 2] {
            let mac = MacAddress::new_eui48([2, 0, 0, 0, 0, suffix]);
            jobs.start(LinkRequest {
                session_id: SessionId(1),
                peer: PeerInfo {
                    addr: "127.0.0.1:12345".parse().unwrap(),
                    is_tls: false,
                    peer_description: None,
                },
                id: mac.into(),
                requested: LinkCharacteristics::default(),
                current: LinkMetrics::default(),
            });

            assert!(matches!(
                jobs.next().await,
                Some(FsmEvent::AppLinkCharacteristicsResponse {
                    mac: response_mac,
                    status: StatusCode::REQUEST_DENIED,
                    text,
                    metrics: None,
                }) if response_mac == mac && text.is_empty()
            ));
            assert!(jobs.is_empty());
            assert!(jobs.macs.is_empty());
        }
    }
}
