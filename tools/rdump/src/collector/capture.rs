mod bpf {
    include!("../bpf/skel/tc_capture.skel.rs");
    include!("../bpf/skel/tc_capture.rs");
}

use bpf::*;

use libbpf_rs::skel::*;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::{TC_INGRESS, TC_EGRESS};
use crossbeam_channel::Sender;
use core::panic;
use std::os::fd::AsFd;

use log::{error, debug};
use crate::{
    config::POLL_PER_MINISECOND,
    collector::common::*,
    eventloop::Event,
};


pub struct TcCaptureCollector<'a> {
    skel: TcCaptureSkel<'a>,
}

impl<'a> TcCaptureCollector<'a> {
    /// attach tcp reset eBPF program
    pub fn new() -> Self {
        bump_memlock_rlimit();
        // 从Skel里获取信息，从opts里获取ifindex
        let builder = TcCaptureSkelBuilder::default();

        let open_skel = builder
                .open()
                .expect("Failed to open tc_capture program");

        let skel = open_skel
                .load()
                .expect("failed to load tc_capture program");
                
        TcCaptureCollector { skel }
    }

    pub fn attach(&mut self) {
        self
            .skel
            .attach()
            .expect("failed to attach capture program");
    }

    pub fn tc_hook_and_attach(&self, netif_name: &str) {
        self.tc_egress_hook_and_attach(netif_name);
        self.tc_ingress_hook_and_attach(netif_name);
    }
    
    fn tc_egress_hook_and_attach(&self, netif_name: &str) {
        let binding = self.skel.progs();
        
        let ifidx: i32 = nix::net::if_::if_nametoindex(netif_name).unwrap() as i32;

        let mut tc_builder = TcHookBuilder::new(binding.tc_egress().as_fd());
        tc_builder
                .ifindex(ifidx)
                .replace(true)
                .handle(1)
                .priority(1);

        // 挂载驱动到TC的ingress\egress接口上
        let mut egress = tc_builder.hook(TC_EGRESS);

        // 执行attach，驱动开始工作
        if let Err(e) = egress.attach() {
            error!("failed to attach egress hook {} ", e);
            panic!("failed to attach egress hook !");
        }
    }

    pub fn tc_ingress_hook_and_attach(&self, netif_name: &str) {
        let binding = self.skel.progs();
        
        let ifidx: i32 = nix::net::if_::if_nametoindex(netif_name).unwrap() as i32;

        let mut tc_builder = TcHookBuilder::new(binding.tc_ingress().as_fd());
        tc_builder
                .ifindex(ifidx)
                .replace(true)
                .handle(1)
                .priority(1);

        // 挂载驱动到TC的ingress\egress接口上
        let mut ingress = tc_builder.hook(TC_INGRESS);

        // 执行attach，驱动开始工作
        if let Err(e) = ingress.attach() {
            error!("failed to attach ingress hook {} ", e);
            panic!("failed to attach ingress hook !");
        }
    }

    pub fn poll(&mut self, mut tx: Sender<Event>) {
        debug!("start timestamp events polling thread");

        let mut tx1 = tx.clone();
        let handle_tstamp_recv_event = move |cpu: i32, data: &[u8]| {
            __handle_tstamp_recv_event(&mut tx1, cpu, data);
        };

        let recv_tstamp_events = PerfBufferBuilder::new(&self.skel.maps_mut().recv_timestamp_events())
            .sample_cb(handle_tstamp_recv_event)
            .lost_cb(handle_lost_events)
            .build()
            .unwrap();

        std::thread::spawn(move || {
                loop {
                    recv_tstamp_events.poll(std::time::Duration::from_millis(POLL_PER_MINISECOND)).unwrap();
                }
                // println!("tstamp recv event thread finish");
            }
        );

        debug!("start pcaket events polling thread");

        let handle_packet_event = move |cpu: i32, data: &[u8]| {
            __handle_packet_event(&mut tx, cpu, data);
        };

        let packet_events = PerfBufferBuilder::new(&self.skel.maps_mut().packet_events())
            .sample_cb(handle_packet_event)
            .lost_cb(handle_lost_events)
            .build()
            .unwrap();

        std::thread::spawn(move || {
                loop {
                    packet_events.poll(std::time::Duration::from_millis(POLL_PER_MINISECOND)).unwrap();
                }
                // println!("packet event thread finish");
            }
        );
    }

}

fn __handle_packet_event(tx: &mut Sender<Event>, _cpu: i32, data: &[u8]) {
    let mut data_vec = data.to_vec();   // TODO: FIXME: &[u8]转换vec<u8>是拷贝的，可能存在性能问题，有时间再看看有没有更高效的方案

    let payload = data_vec.split_off(std::mem::size_of::<packet_event_t>());
    
    let (_head, body, _tail) = unsafe { data_vec.align_to::<packet_event_t>() };

    let mut pk = CapEvent::new(body[0]);
    pk.payload = payload;

    let event = Event::TcCapture(pk);
    tx.send(event).expect("failed to send events");
}

fn __handle_tstamp_recv_event(tx: &mut Sender<Event>, _cpu: i32, data: &[u8]) {
    
    let data_vec = data.to_vec();
    let (_head, body, _tail) = unsafe { data_vec.align_to::<recv_timestamp_event_t>() };
    
    let event = Event::KernelTimeStamp(TimeEvent::new(body[0]));
    tx.send(event).expect("failed to send events");
}


#[derive(Debug)]
pub struct TimeEvent {
    pub meta: recv_timestamp_event_t,
}

impl TimeEvent {
    pub fn new(data: recv_timestamp_event_t) -> Self {
        Self { meta: data }
    }

    pub fn new_empty() -> Self {
        let data = recv_timestamp_event_t{
            tc: 0,
            net_recv: 0,
            ip_recv: 0,
            tcp_recv: 0,
        };
        Self { meta: data }
    }
}

#[derive(Debug)]
pub struct CapEvent {
    pub meta: packet_event_t,
    pub payload: Vec<u8>,
}

impl CapEvent {
    pub fn new(data: packet_event_t) -> Self {
        Self {
            meta: data,
            payload: vec![]
        }
    }
}
