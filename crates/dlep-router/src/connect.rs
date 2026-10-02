//! Bounded connection futures owned by the event loop. Dropping the driver
//! cancels every attempt before graceful daemon shutdown, without detached tasks.

use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;

use dlep_daemon::{DaemonError, PeerOffer, RouterDaemon};

pub const MAX_CONNECT_ATTEMPTS: usize = 8;
type ConnectFuture<'a> = Pin<Box<dyn Future<Output = Result<SocketAddr, DaemonError>> + Send + 'a>>;

struct Attempt<'a> {
    endpoints: Vec<SocketAddr>,
    retry_peer: Option<SocketAddr>,
    future: ConnectFuture<'a>,
}

pub struct Completion {
    pub retry_peer: Option<SocketAddr>,
    pub result: Result<SocketAddr, DaemonError>,
}

#[derive(Default)]
pub struct ConnectAttempts<'a> {
    attempts: Vec<Attempt<'a>>,
    reserved: HashSet<SocketAddr>,
}

impl<'a> ConnectAttempts<'a> {
    pub fn capacity(&self) -> usize {
        MAX_CONNECT_ATTEMPTS - self.attempts.len()
    }

    pub fn contains(&self, peer: &SocketAddr) -> bool {
        self.reserved.contains(peer)
    }

    pub fn endpoints(&self) -> impl Iterator<Item = &SocketAddr> {
        self.reserved.iter()
    }

    pub fn start_static(&mut self, daemon: &'a RouterDaemon, peer: SocketAddr) -> bool {
        self.insert(
            vec![peer],
            Some(peer),
            Box::pin(async move { daemon.connect_static(peer).await.map(|()| peer) }),
        )
    }

    pub fn start_offer(&mut self, daemon: &'a RouterDaemon, offer: PeerOffer) -> bool {
        let endpoints = offer.endpoints.iter().map(|e| e.addr).collect();
        // Keep sequential preference/fallback within one offer. Independent
        // modems can connect while an endpoint in this offer stalls.
        self.insert(
            endpoints,
            None,
            Box::pin(async move { daemon.connect_discovered(&offer).await }),
        )
    }

    fn insert(
        &mut self,
        endpoints: Vec<SocketAddr>,
        retry_peer: Option<SocketAddr>,
        future: ConnectFuture<'a>,
    ) -> bool {
        if self.capacity() == 0
            || endpoints.is_empty()
            || endpoints.iter().any(|p| self.contains(p))
        {
            return false;
        }
        self.reserved.extend(endpoints.iter().copied());
        self.attempts.push(Attempt {
            endpoints,
            retry_peer,
            future,
        });
        true
    }

    /// Cancel retries whose discovered-peer history expired or was evicted.
    /// Fresh offers (retry_peer=None) have no retained entry until connected.
    pub fn retain_retries(&mut self, keep: impl Fn(&SocketAddr) -> bool) {
        self.attempts.retain(|attempt| {
            let retain = attempt.retry_peer.as_ref().is_none_or(&keep);
            if !retain {
                for endpoint in &attempt.endpoints {
                    self.reserved.remove(endpoint);
                }
            }
            retain
        });
    }

    pub async fn next(&mut self) -> Completion {
        // At most eight futures are polled on a wake. Each future registers
        // this task's waker; no extra task or unbounded work queue is needed.
        poll_fn(|cx| {
            for i in 0..self.attempts.len() {
                if let Poll::Ready(result) = self.attempts[i].future.as_mut().poll(cx) {
                    let attempt = self.attempts.remove(i);
                    for endpoint in attempt.endpoints {
                        self.reserved.remove(&endpoint);
                    }
                    return Poll::Ready(Completion {
                        retry_peer: attempt.retry_peer,
                        result,
                    });
                }
            }
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::oneshot;

    #[test]
    fn evicted_retries_are_cancelled_but_static_and_new_offers_survive() {
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let c = "127.0.0.1:3".parse().unwrap();
        let mut attempts = ConnectAttempts::default();
        let (tx, rx) = oneshot::channel::<()>();
        assert!(attempts.insert(
            vec![a],
            Some(a),
            Box::pin(async move {
                let _ = rx.await;
                Ok(a)
            })
        ));
        assert!(attempts.insert(vec![b], Some(b), Box::pin(std::future::pending())));
        assert!(attempts.insert(vec![c], None, Box::pin(std::future::pending())));
        attempts.retain_retries(|peer| *peer == b);
        assert!(tx.is_closed());
        assert!(!attempts.contains(&a));
        assert!(attempts.contains(&b) && attempts.contains(&c));
        assert_eq!(attempts.capacity(), MAX_CONNECT_ATTEMPTS - 2);
    }

    #[tokio::test]
    async fn bounded_attempts_poll_past_stalled_peers_and_cancel_on_drop() {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut attempts = ConnectAttempts::default();
        let mut triggers = Vec::new();
        for port in 1..=MAX_CONNECT_ATTEMPTS as u16 {
            let peer = SocketAddr::from(([127, 0, 0, 1], port));
            let (tx, rx) = oneshot::channel();
            triggers.push(tx);
            let guard = Guard(dropped.clone());
            assert!(attempts.insert(
                vec![peer],
                Some(peer),
                Box::pin(async move {
                    let _guard = guard;
                    rx.await.unwrap();
                    Ok(peer)
                })
            ));
        }
        assert_eq!(attempts.capacity(), 0);
        let extra = "127.0.0.1:9000".parse().unwrap();
        assert!(!attempts.insert(vec![extra], None, Box::pin(std::future::pending())));
        // Completing the last future must work while every earlier one stalls.
        triggers.pop().unwrap().send(()).unwrap();
        let result = attempts.next().await.result.unwrap();
        assert_eq!(result.port(), MAX_CONNECT_ATTEMPTS as u16);
        assert!(!attempts.contains(&result));
        assert_eq!(attempts.capacity(), 1);
        assert!(attempts.insert(vec![extra], None, Box::pin(std::future::pending())));
        drop(attempts);
        assert_eq!(dropped.load(Ordering::SeqCst), MAX_CONNECT_ATTEMPTS);
        assert!(triggers.iter().all(|t| t.is_closed()));
    }

    #[test]
    fn overlapping_offers_reserve_all_fallback_endpoints() {
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let c = "127.0.0.1:3".parse().unwrap();
        let mut attempts = ConnectAttempts::default();
        assert!(attempts.insert(vec![a, b], None, Box::pin(std::future::pending())));
        assert!(!attempts.insert(vec![b, c], None, Box::pin(std::future::pending())));
        assert!(!attempts.contains(&c));
        assert!(attempts.insert(vec![c], None, Box::pin(std::future::pending())));
    }
}
