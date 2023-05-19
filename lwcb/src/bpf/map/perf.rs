use crate::{is_python, IS_IN_PYTHON};

use super::{
    map::{bpf_create_map, Map},
    perfbuffer::PerfBuffer,
};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, NativeEndian};
use libbpf_sys::bpf_map_update_elem;
use mio::unix::SourceFd;
use std::ffi::CString;

pub struct PerfMap {
    fd: i64,
    buffers: Vec<PerfBuffer>,
    poll: mio::Poll,
}

impl PerfMap {
    pub fn new() -> Self {
        let mut pm = PerfMap {
            fd: -1,
            buffers: vec![],
            poll: mio::Poll::new().expect("Failed to create mio poll"),
        };
        if pm.create().is_err() {
            panic!("Failed to create perf map, err: {}", pm.fd)
        }
        log::debug!("Create perf map, mapfd: {}", pm.fd);
        pm
    }

    pub fn open_buffer(&mut self) {
        let page_size = page_size::get();
        for i in 0..num_cpus::get() {
            let buffer =
                PerfBuffer::open(i as u32, page_size, 128).expect("Failed to create perf buffer");

            let ret = unsafe {
                bpf_map_update_elem(
                    self.fd as i32,
                    &i as *const usize as *const libc::c_void,
                    &buffer.fd() as *const i32 as *const libc::c_void,
                    0,
                )
            };

            if ret < 0 {
                panic!("failed to update perf map")
            }

            self.poll
                .registry()
                .register(
                    &mut SourceFd(&buffer.fd()),
                    mio::Token(i),
                    mio::Interest::READABLE,
                )
                .expect("failed to register poll event");
            self.buffers.push(buffer);
        }
    }

    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let mut ret_events = vec![];
        let mut events = mio::Events::with_capacity(self.buffers.len());
        self.poll.poll(&mut events, None).expect("failed to poll");

        for event in events.iter() {
            let to = event.token().0;

            loop {
                if self.buffers[to].readable() {
                    if let Some(data) = self.buffers[to].read_events() {
                        ret_events.push(data);
                        // let id = NativeEndian::read_u64(&data[..8]);
                        // self.events[id as usize].handle_data(&data);
                    }
                } else {
                    break;
                }
            }
        }
        ret_events
    }

    pub fn read_events(&mut self) -> Vec<Vec<String>> {
        todo!()
        // let mut ret_events = vec![];
        // let mut events = mio::Events::with_capacity(self.buffers.len());
        // self.poll.poll(&mut events, None).expect("failed to poll");

        // for event in events.iter() {
        //     let to = event.token().0;

        //     loop {
        //         if self.buffers[to].readable() {
        //             if let Some(data) = self.buffers[to].read_events() {
        //                 let id = NativeEndian::read_u64(&data[..8]);
        //                 if let Some(ret) = self.events[id as usize].handle_data(&data) {
        //                     ret_events.push(ret);
        //                 }
        //             }
        //         } else {
        //             break;
        //         }
        //     }
        // }

        // ret_events
    }
}

impl Map for PerfMap {
    fn create(&mut self) -> Result<()> {
        let fd = bpf_create_map(
            libbpf_sys::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            4,
            4,
            num_cpus::get() as u32,
        );

        self.fd = fd;
        if fd < 0 {
            bail!("Failed to create perf map")
        }

        Ok(())
    }

    fn fd(&self) -> i64 {
        self.fd
    }

    fn key_size(&self) -> usize {
        4
    }
    fn value_size(&self) -> usize {
        4
    }

    fn max_entries(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_perf_map_create() {
        assert!(PerfMap::new().fd() > 0);
    }

    #[test]
    fn test_print_handler_fmt() {
        let mut ph = PrintHandler::new("");
        assert!(ph.fmts.len() == 1);
        assert_eq!(ph.fmts[0], CString::new("").unwrap());

        ph = PrintHandler::new("\n");
        assert!(ph.fmts.len() == 1);
        assert_eq!(ph.fmts[0], CString::new("\n").unwrap());

        ph = PrintHandler::new("%u");
        assert!(ph.fmts.len() == 2);
        assert_eq!(ph.fmts[0], CString::new("").unwrap());
        assert_eq!(ph.fmts[1], CString::new("%u").unwrap());

        ph = PrintHandler::new("123%u");
        assert!(ph.fmts.len() == 2);
        assert_eq!(ph.fmts[0], CString::new("123").unwrap());
        assert_eq!(ph.fmts[1], CString::new("%u").unwrap());

        ph = PrintHandler::new("123%u\n");
        assert!(ph.fmts.len() == 2);
        assert_eq!(ph.fmts[0], CString::new("123").unwrap());
        assert_eq!(ph.fmts[1], CString::new("%u\n").unwrap());
    }
}
