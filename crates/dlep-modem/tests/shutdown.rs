#![cfg(unix)]
#[path = "../../../tests/support/shutdown.rs"]
mod support;
use nix::sys::signal::Signal;
use support::Role;

#[tokio::test]
async fn sigterm_sends_termination_and_waits_for_response() {
    support::established(
        env!("CARGO_BIN_EXE_dlep-modem"),
        Role::Modem,
        Signal::SIGTERM,
        true,
    )
    .await;
}

#[tokio::test]
async fn sigint_sends_termination_and_waits_for_response() {
    support::established(
        env!("CARGO_BIN_EXE_dlep-modem"),
        Role::Modem,
        Signal::SIGINT,
        true,
    )
    .await;
}

#[tokio::test]
async fn sigterm_exits_after_termination_timeout() {
    support::established(
        env!("CARGO_BIN_EXE_dlep-modem"),
        Role::Modem,
        Signal::SIGTERM,
        false,
    )
    .await;
}

#[tokio::test]
async fn sigterm_interrupts_stalled_tls() {
    support::stalled_tls(env!("CARGO_BIN_EXE_dlep-modem"), Role::Modem).await;
}
