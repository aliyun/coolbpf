mod config;
mod collector;
mod eventloop;
mod pcap;

use crate::{
    collector::capture::*,
    eventloop::*,
    pcap::*,
};




fn main() { 

    let (tx, rx) = get_event_channel();

    let mut tc = TcCaptureCollector::new();
    
    tc.attach();
    
    tc.tc_hook_and_attach("eth0");

    tc.poll(tx);

    let mut writer = pcap::writer::Writer::new("out.pcapng").unwrap();
    writer.write_packets(rx);
}
