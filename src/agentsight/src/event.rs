use crate::probes::sslsniff::SslEvent;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use once_cell::sync::Lazy;

#[derive(Debug)]
pub enum Event {
    Ssl(SslEvent),
}



pub fn get_event_channel() {
    
}