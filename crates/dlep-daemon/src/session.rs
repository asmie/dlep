//! Active-session runtime. Owns the FSM instance, the `Framed` transport
//! stream, and the timer set. One task per session; the task is the sole
//! mutator of its FSM, so no locking is needed around the state.

use dlep_fsm::{FsmAction, FsmEvent};

pub trait SessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction>;
}

impl SessionFsm for dlep_fsm::session_router::RouterSessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        dlep_fsm::session_router::RouterSessionFsm::step(self, event)
    }
}

impl SessionFsm for dlep_fsm::session_modem::ModemSessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        dlep_fsm::session_modem::ModemSessionFsm::step(self, event)
    }
}
