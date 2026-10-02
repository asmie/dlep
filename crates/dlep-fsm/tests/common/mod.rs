pub fn assert_rejected(actions: Vec<dlep_fsm::FsmAction>, reason: dlep_fsm::CommandError) {
    assert!(
        matches!(actions.as_slice(), [dlep_fsm::FsmAction::Emit(
        dlep_fsm::events::EmittedEvent::CommandRejected(rejection)
    )] if rejection.reason == reason),
        "expected {reason:?}, got {actions:?}"
    );
}
