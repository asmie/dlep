#[path = "support/config.rs"]
mod support;

#[test]
fn check_config_rejects_typos_and_invalid_timers() {
    support::check_config_rejects_typos_and_invalid_timers(env!("CARGO_BIN_EXE_dlep-modem"));
}
