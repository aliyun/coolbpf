use crate::{is_python, IS_IN_PYTHON};

use super::{
    layout::Layout,
    map::{bpf_create_map, Map},
    perfbuffer::PerfBuffer,
};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, NativeEndian};
use libbpf_sys::bpf_map_update_elem;
use mio::unix::SourceFd;
use std::ffi::CString;

#[derive(Clone, Debug)]
pub struct PrintHandler {
    fmts: Vec<CString>,
    cursor: usize,
    pyret: Vec<String>,
}

impl PrintHandler {
    pub fn new(fmt: &str) -> Self {
        let mut is_escape = false;
        let mut fmts = vec![];
        let mut pre = 0;
        for (i, c) in fmt.chars().enumerate() {
            if c == '\\' {
                is_escape = !is_escape;
                continue;
            }
            if !is_escape && c == '%' {
                if i == 0 {
                    fmts.push(CString::new("").expect("Failed to create cstring"));
                } else {
                    fmts.push(CString::new(&fmt[pre..i]).unwrap());
                }
                pre = i;
                continue;
            }
            is_escape = false;
        }

        fmts.push(CString::new(&fmt[pre..fmt.len()]).unwrap());
        PrintHandler {
            fmts,
            cursor: 0,
            pyret: vec![],
        }
    }

    pub fn print<T>(&mut self, val: T) {
        unsafe { libc::printf(self.fmts[self.cursor].as_ptr(), val) };
        self.cursor += 1;
    }

    pub fn print_string(&mut self, val: String) {
        if is_python() {
            self.pyret.push(val);
        } else {
            let cstring = CString::new(val).unwrap();
            self.print(cstring.as_ptr());
        }
    }

    pub fn print_number<T: ToString>(&mut self, val: T) {
        if is_python() {
            self.pyret.push(val.to_string());
        } else {
            self.print(val);
        }
    }

    pub fn reset(&mut self) {
        if !is_python() {
            unsafe { libc::printf(self.fmts[0].as_ptr()) };
            self.cursor = 1;
        }
    }

    pub fn pyret(&mut self) -> Vec<String> {
        let mut ret = vec![];
        std::mem::swap(&mut ret, &mut self.pyret);
        ret
    }
}

pub struct Stringify {
    cursor: usize,
}

pub struct PerfEvent {
    print: Option<PrintHandler>,
    lo: Layout,
}

impl PerfEvent {
    pub fn new(fmt: Option<String>, lo: Layout) -> Self {
        let mut pe = PerfEvent { print: None, lo };

        if let Some(f) = fmt {
            pe.set_print(&f);
        }
        pe
    }

    pub fn set_print(&mut self, fmt: &str) {
        self.print = Some(PrintHandler::new(fmt));
    }

    pub fn set_layout(&mut self, lo: Layout) {
        self.lo = lo
    }

    pub fn handle_data(&mut self, data: &[u8]) -> Option<Vec<String>> {
        if let Some(p) = &mut self.print {
            p.reset();
            self.lo.print(p, data);
            return Some(p.pyret());
        }
        None
    }
}

pub struct PerfMap {
    fd: i64,
    events: Vec<PerfEvent>,
    buffers: Vec<PerfBuffer>,
    poll: mio::Poll,
}

impl PerfMap {
    pub fn new() -> Self {
        let mut pm = PerfMap {
            fd: -1,
            events: Vec::new(),
            buffers: vec![],
            poll: mio::Poll::new().expect("Failed to create mio poll"),
        };
        if pm.create().is_err() {
            panic!("Failed to create perf map, err: {}", pm.fd)
        }
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

    pub fn poll(&mut self) {
        let mut events = mio::Events::with_capacity(self.buffers.len());
        loop {
            self.poll.poll(&mut events, None).expect("failed to poll");

            for event in events.iter() {
                let to = event.token().0;

                loop {
                    if self.buffers[to].readable() {
                        if let Some(data) = self.buffers[to].read_events() {
                            let id = NativeEndian::read_u64(&data[..8]);
                            self.events[id as usize].handle_data(&data);
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }

    pub fn read_events(&mut self) -> Vec<Vec<String>> {
        let mut ret_events = vec![];
        let mut events = mio::Events::with_capacity(self.buffers.len());
        self.poll.poll(&mut events, None).expect("failed to poll");

        for event in events.iter() {
            let to = event.token().0;

            loop {
                if self.buffers[to].readable() {
                    if let Some(data) = self.buffers[to].read_events() {
                        let id = NativeEndian::read_u64(&data[..8]);
                        if let Some(ret) = self.events[id as usize].handle_data(&data) {
                            ret_events.push(ret);
                        }
                    }
                } else {
                    break;
                }
            }
        }

        ret_events
    }

    pub fn event_id(&self) -> usize {
        self.events.len()
    }

    pub fn add_perf_event(&mut self, event: PerfEvent) {
        self.events.push(event);
    }

    pub fn perf_event(&mut self, event_id: usize) -> &mut PerfEvent {
        &mut self.events[event_id]
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
