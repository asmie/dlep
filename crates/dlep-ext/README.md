# dlep-ext

Extension plug-in traits and negotiation registry for DLEP (RFC 8175). This crate is portable.

Requires Rust 1.85 or newer.

Negotiated extensions can request orderly termination of their current session:

```rust
use dlep_core::StatusCode;
use dlep_ext::{ExtensionCtx, TerminationRequestError};

fn reject_invalid_session(ctx: &mut dyn ExtensionCtx) -> Result<(), TerminationRequestError> {
    ctx.terminate_session(StatusCode::INVALID_DATA)
}
```

Call this from an in-session input or lifecycle hook. Input handlers should
return `ExtHandled::Handled` for consumed input. The runtime finishes the current
FSM action batch, then uses the usual Session Termination exchange and deadline.
Existing protocol-error/closing transitions take precedence. The first accepted
request wins; later requests return `AlreadyRequested`, and queued extension
messages are discarded once termination is requested. Session-down hooks return
`SessionClosing`; destination-down hooks can still request termination while the
session is active. Success means queued, not acknowledged by the peer.

The default trait method returns `Unsupported`, so existing custom contexts
continue to compile. Termination affects one session, and the application's
reconnect policy still applies.

```toml
[dependencies]
dlep-ext = "0.2.0"
```

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
