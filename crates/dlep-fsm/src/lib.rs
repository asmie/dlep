//! DLEP state machines — pure logic, no I/O, no tokio.
//!
//! Each FSM exposes a synchronous `step(&mut self, event) -> Vec<FsmAction>`.
//! The async runtime in `dlep-daemon` owns timers, sockets and channels;
//! this crate knows only about events in and actions out. Keeping the fsm
//! crate tokio-free is a structural guarantee that no state handler can
//! accidentally block.

#![allow(dead_code)]

pub mod discovery_modem;
pub mod discovery_router;
pub mod events;
pub mod session_modem;
pub mod session_router;
pub mod timers;
pub mod transaction;

pub use events::{FsmAction, FsmEvent, SendTarget};
pub use timers::{TimerId, TimerKind};
