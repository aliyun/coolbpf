use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use once_cell::sync::Lazy;
use log::error;
use crate::collector::capture::{CapEvent, TimeEvent};

pub static EVENTLOOP: Lazy<(Sender<Event>, Receiver<Event>)> =
    Lazy::new(|| crossbeam_channel::unbounded());

#[derive(Debug)]
pub enum Event {
    TcCapture(CapEvent),
    KernelTimeStamp(TimeEvent),
    Stop,
    CtrlC,
}

pub fn get_event_channel() -> (Sender<Event>, Receiver<Event>) {
    (EVENTLOOP.0.clone(), EVENTLOOP.1.clone())
}

pub fn send_stop_event() {
    if let Err(error) = EVENTLOOP.0.send(Event::Stop) {
        error!("Failed to send stop event: {}", error);
    }
}


