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

## Discovery hooks

Discovery is separate from session negotiation. A plugin must override
`supports_discovery()` to return true and advertise a nonempty ID list. Existing
session-only plugins remain inactive on UDP discovery. Opted-in plugins can
extend standard Peer Discovery and Peer Offer signals:

```rust
use std::sync::Arc;
use dlep_core::{DataItemType, ExtensionId, RawDataItem, Signal, SignalType};
use dlep_ext::{DiscoveryCtx, DlepExtension, ExtHandled};

struct DiscoveryTag;
impl DlepExtension for DiscoveryTag {
    fn advertised_ids(&self) -> &[ExtensionId] { &[ExtensionId(0xF020)] }
    fn supports_discovery(&self) -> bool { true }

    fn on_discovery_send(&self, _: SignalType, ctx: &mut dyn DiscoveryCtx) {
        let item = RawDataItem {
            type_id: DataItemType(0xFF80),
            value: b"vendor-tag".to_vec().into(),
        };
        if let Err(error) = ctx.add_data_item(item) {
            ctx.emit_event(Arc::new(error));
        }
    }

    fn on_discovery_data_item(
        &self, _: &Signal, item: &RawDataItem, _: &mut dyn DiscoveryCtx,
    ) -> ExtHandled {
        if item.type_id == DataItemType(0xFF80) {
            ExtHandled::Handled
        } else {
            ExtHandled::Passthrough
        }
    }
}
```

`DiscoveryCtx::info()` provides role, direction, peer, local address, and ingress
interface metadata where available. Incoming signals and their unicast replies
have packet metadata; periodic multicast has no peer or ingress metadata.
`on_discovery_signal` observes the complete original signal after every unknown
item is claimed; the core FSM receives only core items. Item handlers stop at the
first claimant in registration order. Unclaimed items discard the signal, and
core grammar is checked before item hooks. Receive contexts are read-only.

Outgoing additions may use non-core, non-reserved data-item types. All plugins
share 32 items and 4096 bytes per signal, including TLV headers; additions also
respect the UDP signal size limit. Rejected additions preserve the core signal.
Hooks cannot replace core fields, destinations, or send arbitrary signal types.
TTL/interface filtering and connected-router suppression precede receive hooks.

Discovery metadata is unauthenticated, has no `SessionId`, and does not activate
TCP hooks. Normal mutual session negotiation still applies. Hooks can emit
opaque application events; receive events may precede `PeerDiscovered` because
they run before the core discovery FSM. The same plugin instance may receive
discovery and session callbacks concurrently.

```toml
[dependencies]
dlep-ext = "0.2.0"
```

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
