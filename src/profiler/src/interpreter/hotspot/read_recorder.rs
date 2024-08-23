use crate::process::memory::ProcessMemory;
use std::io::Read;

pub struct ReadRecorder {
    pm: ProcessMemory,
    offset: u64,
    chunk: usize,
    curr: usize,
    pub buf: Vec<u8>,
}

impl Read for &mut ReadRecorder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.curr >= self.buf.len() {
            let old_len = self.buf.len();
            self.buf.resize(old_len + self.chunk, 0);
            match self.pm.read_at(self.offset, &mut self.buf[old_len..]) {
                Ok(sz) => {
                    self.buf.resize(old_len + sz, 0);
                    self.offset += sz as u64;
                }
                Err(e) => {
                    buf.fill(0);
                    return Err(e);
                }
            }
        }
        buf.clone_from_slice(&self.buf[self.curr..self.curr + buf.len()]);
        self.curr += buf.len();
        Ok(buf.len())
    }
}

impl ReadRecorder {
    pub fn new(pm: ProcessMemory, offset: u64, chunk: usize) -> Self {
        Self {
            pm,
            offset,
            chunk,
            curr: 0,
            buf: vec![],
        }
    }
}
