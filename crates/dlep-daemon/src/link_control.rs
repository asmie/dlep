//! Modem link-control backend for Link Characteristics Requests (RFC 8175
//! §12.18–12.19).
//!
//! A router may ask a modem to change a destination's data rate or latency.
//! Without a backend, [`crate::ModemDaemon`] immediately replies Request
//! Denied with the current metrics. A backend registered through
//! [`crate::ModemBuilder::link_control`] receives each request instead and
//! decides the response. RFC 8175 §8 gives transactions no deadline, but a
//! pending request holds the destination's transaction slot: the modem cannot
//! report Destination Down for it until the request is answered. The runtime
//! therefore denies a request the backend has not answered within
//! [`DEFAULT_LINK_CONTROL_TIMEOUT`]; configure or disable the deadline with
//! [`crate::ModemBuilder::link_control_timeout`]. On the deadline the backend
//! future is dropped, so a backend can detect cancellation through its own
//! drop guards or closed channels.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dlep_core::{MacAddress, StatusCode};
use dlep_ext::SessionId;
use dlep_fsm::FsmEvent;
use tokio::sync::oneshot;
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

/// Default deadline for a backend answer before the runtime replies Request
/// Denied ("link-control backend timed out").
pub const DEFAULT_LINK_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

pub type LinkControlFuture = Pin<Box<dyn Future<Output = LinkResponse> + Send + 'static>>;

/// Local disposition of a backend reply. Success means the session accepted
/// it and completed its local actions, including the response write; it is not
/// a peer acknowledgement. Rejection refers to the original reply even when
/// the runtime sends a fallback denial. A dropped sender leaves the outcome
/// unknown (for example, cancellation or an I/O failure during the write).
pub type LinkResponseReceipt = oneshot::Sender<Result<(), dlep_fsm::CommandRejection>>;

/// Backend answer with an optional local acceptance receipt.
#[derive(Debug)]
pub struct LinkControlReply {
    pub response: LinkResponse,
    /// Sent after the original reply's local actions and state publication.
    /// Dropping the receiver does not cancel the reply.
    pub receipt: Option<LinkResponseReceipt>,
}

impl From<LinkResponse> for LinkControlReply {
    fn from(response: LinkResponse) -> Self {
        Self {
            response,
            receipt: None,
        }
    }
}

pub type LinkControlReplyFuture = Pin<Box<dyn Future<Output = LinkControlReply> + Send + 'static>>;

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

    /// The runtime calls this method. Override it to attach an acceptance
    /// receipt before retaining a grant or handling a later hardware report.
    /// Existing backends use `request` unchanged through this default.
    /// Await the receipt outside the returned future, which must finish first:
    /// the receipt is sent only after the future completes, so awaiting it
    /// inside the future waits until the request's deadline denies it.
    fn request_with_receipt(&self, request: LinkRequest) -> LinkControlReplyFuture {
        let response = self.request(request);
        Box::pin(async move { response.await.into() })
    }
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

/// A registered backend and the deadline for each of its answers.
#[derive(Clone)]
pub(crate) struct LinkBackend {
    pub(crate) backend: Arc<dyn LinkControl>,
    /// None waits for the backend indefinitely.
    pub(crate) timeout: Option<Duration>,
}

/// Backend calls in flight for one session. Dropping it aborts them.
#[derive(Default)]
pub(crate) struct LinkJobs {
    backend: Option<LinkBackend>,
    tasks: JoinSet<LinkControlReply>,
    macs: HashMap<Id, MacAddress>,
}

impl LinkJobs {
    pub(crate) fn new(backend: Option<LinkBackend>) -> Self {
        Self {
            backend,
            ..Self::default()
        }
    }

    /// Without a backend, a deferred request is denied rather than left
    /// pending for the rest of the session. A backend that misses its deadline
    /// is cancelled and the request denied.
    pub(crate) fn start(&mut self, request: LinkRequest) {
        let mac = request.id.0;
        let handle = match &self.backend {
            Some(LinkBackend { backend, timeout }) => {
                let backend = Arc::clone(backend);
                let timeout = *timeout;
                self.tasks.spawn(async move {
                    let reply = backend.request_with_receipt(request);
                    let Some(limit) = timeout else {
                        return reply.await;
                    };
                    match tokio::time::timeout(limit, reply).await {
                        Ok(reply) => reply,
                        Err(_) => {
                            warn!("link-control backend did not answer within {limit:?}; denying");
                            LinkResponse::denied()
                                .with_text("link-control backend timed out")
                                .into()
                        }
                    }
                })
            }
            None => self.tasks.spawn(async { LinkResponse::denied().into() }),
        };
        self.macs.insert(handle.id(), mac);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Next completed answer as the FSM event that sends it.
    pub(crate) async fn next(&mut self) -> Option<(FsmEvent, Option<LinkResponseReceipt>)> {
        let (id, response) = match self.tasks.join_next_with_id().await? {
            Ok((id, response)) => (id, response),
            Err(error) => {
                warn!("link-control backend failed: {error}; denying the request");
                (error.id(), LinkResponse::denied().into())
            }
        };
        let mac = self.macs.remove(&id).expect("tracked link-control task");
        Some((response.response.into_event(mac), response.receipt))
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
        let mut jobs = LinkJobs::new(Some(LinkBackend {
            backend: Arc::new(backend),
            timeout: None,
        }));

        // A failed request must leave the job queue usable for the next one.
        for suffix in [1, 2] {
            let mac = MacAddress::new_eui48([2, 0, 0, 0, 0, suffix]);
            jobs.start(LinkRequest {
                session_id: SessionId(1),
                peer: PeerInfo {
                    secured_medium: None,
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
                Some((FsmEvent::AppLinkCharacteristicsResponse {
                    mac: response_mac,
                    status: StatusCode::REQUEST_DENIED,
                    text,
                    metrics: None,
                }, None)) if response_mac == mac && text.is_empty()
            ));
            assert!(jobs.is_empty());
            assert!(jobs.macs.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_request_is_denied_and_cancelled_at_its_deadline() {
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = cancelled.clone();
        let backend = move |_request: LinkRequest| {
            let guard = Dropped(flag.clone());
            async move {
                let _guard = guard;
                std::future::pending::<LinkResponse>().await
            }
        };
        let mut jobs = LinkJobs::new(Some(LinkBackend {
            backend: Arc::new(backend),
            timeout: Some(Duration::from_secs(30)),
        }));
        let mac = MacAddress::new_eui48([2, 0, 0, 0, 0, 1]);
        jobs.start(LinkRequest {
            session_id: SessionId(1),
            peer: PeerInfo {
                secured_medium: None,
                addr: "127.0.0.1:12345".parse().unwrap(),
                is_tls: false,
                peer_description: None,
            },
            id: mac.into(),
            requested: LinkCharacteristics::default(),
            current: LinkMetrics::default(),
        });
        let started = tokio::time::Instant::now();
        assert!(matches!(
            jobs.next().await,
            Some((FsmEvent::AppLinkCharacteristicsResponse {
                mac: response_mac,
                status: StatusCode::REQUEST_DENIED,
                text,
                metrics: None,
            }, None)) if response_mac == mac && text == "link-control backend timed out"
        ));
        assert_eq!(started.elapsed(), Duration::from_secs(30));
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
    }
}
