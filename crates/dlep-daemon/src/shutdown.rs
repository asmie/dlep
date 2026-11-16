//! Opt-in process signal handling for the standalone binaries.

use std::io;
use std::time::Duration;

use tokio::signal::unix::{Signal, SignalKind, signal};

/// Register before starting listeners or connection attempts so shutdown
/// requests received during startup are retained. Embedders keep control of
/// their own process signals unless they explicitly construct this helper.
pub struct ShutdownSignals {
    interrupt: Signal,
    terminate: Signal,
}

impl ShutdownSignals {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Wait for SIGINT (Ctrl-C) or SIGTERM (including systemd stop).
    /// Cancelling this wait does not discard a pending signal.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }

    /// Whether SIGINT or SIGTERM arrives within `grace`, consuming it. A
    /// signal the runtime has already observed is reported without waiting.
    /// Use this to classify a failure that a process-group signal can cause,
    /// such as a child process exiting on the same Ctrl-C.
    pub async fn received_within(&mut self, grace: Duration) -> bool {
        tokio::time::timeout(grace, self.recv()).await.is_ok()
    }
}
