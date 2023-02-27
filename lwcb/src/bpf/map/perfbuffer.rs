use std::{
    cell::RefCell,
    os::unix::prelude::{AsRawFd, RawFd},
    sync::atomic::{self, AtomicPtr, Ordering},
};

use anyhow::{bail, Result};
use perf_event_open_sys::{
    bindings::{
        perf_event_attr, perf_event_header, perf_event_ioctls, perf_event_mmap_page,
        perf_event_sample_format_PERF_SAMPLE_RAW, perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT,
        perf_type_id_PERF_TYPE_SOFTWARE, perf_type_id_PERF_TYPE_TRACEPOINT, PERF_FLAG_FD_CLOEXEC,
    },
    perf_event_open,
};

#[repr(C)]
pub struct Sample {
    header: perf_event_header,
    pub size: u32,
    pub data: [u8; 0],
}

#[repr(C)]
pub struct LostSample {
    header: perf_event_header,
    pub id: u64,
    pub count: u64,
}

pub struct PerfBuffer {
    base: AtomicPtr<perf_event_mmap_page>,
    cpu: u32,
    fd: RawFd,
    size: usize,
    page_size: usize,
    page_cnt: usize,
}

impl PerfBuffer {
    pub fn open(cpu: u32, page_size: usize, page_cnt: usize) -> Result<Self> {
        // create perf buffer
        let mut attrs = perf_event_attr::default();
        attrs.size = std::mem::size_of::<perf_event_attr>() as u32;
        attrs.type_ = perf_type_id_PERF_TYPE_SOFTWARE;
        attrs.config = perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT as u64;
        attrs.sample_type = perf_event_sample_format_PERF_SAMPLE_RAW;
        attrs.__bindgen_anon_1.sample_period = 1;
        attrs.__bindgen_anon_2.wakeup_events = 1;
        let fd =
            unsafe { perf_event_open(&mut attrs, -1, cpu as i32, -1, PERF_FLAG_FD_CLOEXEC as u64) };
        if fd <= 0 {
            bail!("Failed to open perf buffer")
        }
        // do mmap
        let size = page_cnt * page_size;
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size + page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            bail!("PerfBuffer mmap failed");
        }
        // enable perf buffer
        let ret = unsafe { perf_event_open_sys::ioctls::ENABLE(fd, 0) };
        if ret < 0 {
            bail!("Failed to enable perf buffer")
        }
        Ok(PerfBuffer {
            base: AtomicPtr::new(addr as *mut perf_event_mmap_page),
            cpu,
            fd,
            page_size,
            page_cnt,
            size,
        })
    }

    pub fn readable(&self) -> bool {
        let header = self.base.load(Ordering::SeqCst);
        let head = unsafe { (*header).data_head } as usize;
        let tail = unsafe { (*header).data_tail } as usize;
        head != tail
    }

    pub fn read_events(&mut self) -> Option<Vec<u8>> {
        unsafe {
            let header = self.base.load(Ordering::SeqCst);
            let data_head = (*header).data_head;
            let data_tail = (*header).data_tail;
            let raw_size = (self.page_cnt * self.page_size) as u64;
            let base = (header as *const u8).add(self.page_size);

            if data_tail == data_head {
                return None;
            }

            let start = (data_tail % raw_size) as usize;
            let event = base.add(start) as *const perf_event_header;
            let end = ((data_tail + (*event).size as u64) % raw_size) as usize;

            let mut buf = vec![];
            buf.clear();

            if end < start {
                let len = (raw_size as usize - start) as usize;
                let ptr = base.add(start);
                buf.extend_from_slice(std::slice::from_raw_parts(ptr, len));

                let len = (*event).size as usize - len;
                let ptr = base;
                buf.extend_from_slice(std::slice::from_raw_parts(ptr, len));
            } else {
                let ptr = base.add(start);
                let len = (*event).size as usize;
                buf.extend_from_slice(std::slice::from_raw_parts(ptr, len));
            }

            atomic::fence(Ordering::SeqCst);
            (*header).data_tail += (*event).size as u64;

            match (*event).type_ {
                perf_event_type_PERF_RECORD_SAMPLE => {
                    // header + size
                    let offset = std::mem::size_of::<perf_event_header>() + 4;
                    Some(buf[offset..].to_vec())
                }
                perf_event_type_PERF_RECORD_LOST => {
                    let ls = &*(buf.as_ptr() as *const LostSample);
                    println!("cpu {} lost {} events", ls.id, ls.count);
                    None
                }
                _ => {
                    println!("unexpected event type");
                    None
                }
            }
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawFd for PerfBuffer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        unsafe {
            // disable buffer
            perf_event_open_sys::ioctls::DISABLE(self.fd, 0);
            libc::munmap(
                self.base.load(Ordering::SeqCst) as *mut libc::c_void,
                self.size + self.page_size,
            );
            // close buffer fd
            libc::close(self.fd);
        }
    }
}
