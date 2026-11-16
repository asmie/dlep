//! In-memory ordered wire queues; no socket or timing simulation is implied.
use bytes::Bytes;
use dlep_core::Message;
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{FsmAction, FsmEvent, SessionConfig};
use std::collections::VecDeque;

pub struct Pair {
    router: RouterSessionFsm,
    modem: ModemSessionFsm,
    to_router: VecDeque<Bytes>,
    to_modem: VecDeque<Bytes>,
    pub events: Vec<(bool, EmittedEvent)>,
}

impl Pair {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            router: RouterSessionFsm::with_config(config.clone()),
            modem: ModemSessionFsm::with_config(config),
            to_router: VecDeque::new(),
            to_modem: VecDeque::new(),
            events: Vec::new(),
        }
    }

    fn collect(&mut self, actions: Vec<FsmAction>, from_router: bool) {
        for action in actions {
            match action {
                FsmAction::SendMessage(message) => {
                    let wire = message
                        .encode()
                        .expect("FSM emitted an unencodable message")
                        .freeze();
                    Message::decode(wire.clone()).expect("FSM emitted an undecodable message");
                    if from_router {
                        self.to_modem.push_back(wire);
                    } else {
                        self.to_router.push_back(wire);
                    }
                }
                FsmAction::Emit(event) => self.events.push((from_router, event)),
                _ => {}
            }
        }
    }

    pub fn step(&mut self, event: FsmEvent, at_router: bool, immediate: bool) {
        let actions = if at_router {
            self.router.step(event)
        } else {
            self.modem.step(event)
        };
        self.collect(actions, at_router);
        if immediate {
            self.drain();
        }
    }

    /// Deliver one message, preserving order within that direction. True means
    /// a message was delivered; an empty queue is a valid fuzz operation.
    pub fn deliver(&mut self, from_router: bool) -> bool {
        let wire = if from_router {
            self.to_modem.pop_front()
        } else {
            self.to_router.pop_front()
        };
        let Some(wire) = wire else { return false };
        let message = Message::decode(wire).expect("queued message must decode");
        self.step(FsmEvent::RecvMessage(message), !from_router, false);
        true
    }

    pub fn pending(&self, from_router: bool) -> usize {
        if from_router {
            self.to_modem.len()
        } else {
            self.to_router.len()
        }
    }

    pub fn drain(&mut self) {
        for _ in 0..256 {
            if self.pending(true) + self.pending(false) == 0 {
                return;
            }
            self.deliver(true);
            self.deliver(false);
        }
        assert_eq!(
            self.pending(true) + self.pending(false),
            0,
            "unbounded peer response chain"
        );
    }
}
