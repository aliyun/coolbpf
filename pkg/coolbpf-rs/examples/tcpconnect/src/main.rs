include!(concat!(env!("OUT_DIR"), "/tcpconnect.rs"));
include!(concat!(env!("OUT_DIR"), "/tcpconnect.skel.rs"));

use coolbpf_rs::metrics::{describe_counter, increment_counter};
use coolbpf_rs::{vec_to_anytype, CoolBPF};
use coolbpf_rs::helper::net::to_socketaddr;

fn main() {
    // set log level from environment
    coolbpf_rs::logger::init_from_env();
    // enable prometheus exporter
    coolbpf_rs::exporter::start_prometheus_server();
    // open, load and attach eBPF program
    let mut cb = CoolBPF::tryfrom_builder(TcpconnectSkelBuilder::default()).unwrap();
    // open perf buffer to receive data
    cb.open_perf("perf").unwrap();

    describe_counter!(
        "tcp_connect",
        "The times of issueing tcp connecting."
    );

    loop {
        let mut data = cb.perf_recv().unwrap();
        let event = vec_to_anytype::<event>(&mut data.1);
        increment_counter!("tcp_connect");

        let src = to_socketaddr(event.saddr, event.sport);
        let dst = to_socketaddr(event.daddr, event.dport);

        increment_counter!("tcp_connect", "tuples" => format!("{src} -> {dst}"));
    }
}
