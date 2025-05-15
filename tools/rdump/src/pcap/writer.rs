use crate::eventloop::Event;
use crate::config::{ENDIANNESS, MAJOR_VERSION, MINOR_VERSION, SECTION_LENGTH_DEFAULT};
use crate::CapEvent;
use crossbeam_channel::Receiver;
use pcap_file::pcapng::PcapNgBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::{
    enhanced_packet::EnhancedPacketBlock,
    interface_description::InterfaceDescriptionBlock,
    enhanced_packet::EnhancedPacketOption,
    section_header::SectionHeaderBlock,
    section_header::SectionHeaderOption,
};
use pcap_file::DataLink;
use std::time;
use std::borrow::Cow;
use std::fs::File;
use std::collections::HashMap;
use crate::collector::capture::TimeEvent;

pub struct Writer {
    writer: PcapNgWriter<File>,
    map: HashMap<u64, Event>, 
    sum_ts: i32,
    sum_pk_in: i32,
    sum_pk_e: i32,
}

impl Writer {

    pub fn new(path: &str) -> Result<Writer, pcap_file::PcapError> {
        match File::create(path) {
            Ok(file) => {
                let writer = PcapNgWriter::new(file)?;
                Ok(Self { 
                    writer,
                    map: HashMap::new(),
                    sum_ts: 0,
                    sum_pk_in: 0,
                    sum_pk_e: 0,
                })
            },
            Err(e) => Err(pcap_file::PcapError::IoError(e))
        }
    }

    pub fn write_packets(&mut self, rx: Receiver<Event>) {
        log::debug!("start catch packets");

        if let Err(e) = self.write_section_block() {
            println!("write_section_block error: {}", e);
        }

        self.write_interface_block();

        loop {
            println!("sum_ts: {},sum_pk_in: {}, sum_pk_e: {},", self.sum_ts, self.sum_pk_in, self.sum_pk_e);
            match rx.recv() {
                Ok(event) => {
                    match event {
                        Event::KernelTimeStamp(info) => {
                            let key = info.meta.tc;
                            if self.map.contains_key(&key) {
                                let event = self.map.remove(&key).unwrap();
                                let pk = match event {
                                    Event::TcCapture(pk) => Some(pk),
                                    _ => None,
                                };
                                _ = self.parse_event_2_enhancedblock(pk.unwrap(), info);
                            } else {
                                self.map.insert(key, Event::KernelTimeStamp(info));
                            }
                            self.sum_ts += 1;
                        },
                        Event::TcCapture(pk) => {
                            let key = pk.meta.tc_timestamp;
                            if pk.meta.packet_type == 0 {   // TODO: ingress
                                self.sum_pk_in += 1;
                                if self.map.contains_key(&key) {
                                    let ts = self.map.remove(&key).unwrap();
                                    let ts = match ts {
                                        Event::KernelTimeStamp(ts) => Some(ts),
                                        _ => None,
                                    };
                                    _ = self.parse_event_2_enhancedblock(pk, ts.unwrap());
                                } else {
                                    self.map.insert(key, Event::TcCapture(pk));
                                }
                            } else {
                                self.sum_pk_e += 1;
                            }
                        },
                        _ => {},
                    }
                },
                Err(e) => panic!("unexpected channel error: {}", e),
            }
        }
    }

    fn write_section_block(&mut self) -> Result<usize, pcap_file::PcapError> {
        let mut block = SectionHeaderBlock {
            endianness: ENDIANNESS,
            major_version: MAJOR_VERSION,
            minor_version: MINOR_VERSION,
            section_length: SECTION_LENGTH_DEFAULT, //TODO: -1代表没有指定该节的长度，无法跳过
            options: vec![],
        };

        let mut section_opts = vec![
            SectionHeaderOption::OS(Cow::Borrowed(std::env::consts::OS)),
            SectionHeaderOption::Hardware(Cow::Borrowed(std::env::consts::ARCH)),
            SectionHeaderOption::UserApplication(Cow::Borrowed("rdump")),   // TODO: FIXME:
            SectionHeaderOption::Comment(Cow::Borrowed("TODO")),            // TODO: FIXME:
        ];
        block.options.append(&mut section_opts);
        self.writer.write_block(&block.into_block())
    }

    fn write_interface_block(&mut self) {
        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0xFFFF,
            options: vec![],
        };
        self.writer.write_block(&interface.into_block()).unwrap();
    }

    fn parse_event_2_enhancedblock(&mut self, pk: CapEvent, ts: TimeEvent) -> Result<usize, pcap_file::PcapError> {
        let mut block = EnhancedPacketBlock {
            // interface_id: pk.meta.meta.ifindex,
            interface_id: 0,
            timestamp: time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap(),
            original_len: pk.payload.len() as u32,
            data: Cow::Borrowed(&pk.payload),
            options: vec![],
        };

        let option = parse_pid_option();
        let option = EnhancedPacketOption::Comment(Cow::Borrowed(option.as_str()));
        block.options.push(option);

        let option = parse_container_option();
        let option = EnhancedPacketOption::Comment(Cow::Borrowed(option.as_str()));
        block.options.push(option);

        let option = parse_timestamp_option(ts);
        let option = EnhancedPacketOption::Comment(Cow::Borrowed(option.as_str()));
        block.options.push(option);

        self.writer.write_block(&block.into_block())
    }
}

fn parse_timestamp_option(info: TimeEvent) -> String {
    format!(
        "tc timestamp: {}\nip_rcv: {}\ntcp_v4_rcv: {}", 
        info.meta.tc,
        info.meta.ip_recv,
        info.meta.tcp_recv
    )
}

fn parse_pid_option() -> String {
    "pid = 1246\nppid = 331055".to_string()
}

fn parse_container_option() -> String {
    "Container = \nname = ".to_string()
}


