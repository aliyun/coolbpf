use anyhow::bail;
use anyhow::Result;
use std::io::Read;

#[derive(Debug, Clone, Copy)]
pub struct ProcessMemory {
    pid: u32,
    bias: u64,
}

impl ProcessMemory {
    pub fn new(pid: u32) -> Result<Self> {
        Ok(ProcessMemory { pid, bias: 0 })
    }

    pub fn ptr(&self, addr: u64) -> Result<u64> {
        let ptr = self.u64(addr)?;
        Ok(ptr - self.bias)
    }

    pub fn u8(&self, addr: u64) -> Result<u8> {
        let mut data = [0; 1];
        self.read_exact(addr, &mut data)?;
        Ok(data[0])
    }

    pub fn u16(&self, addr: u64) -> Result<u16> {
        let mut data = [0; 2];
        self.read_exact(addr, &mut data)?;
        Ok(u16::from_le_bytes(data))
    }

    pub fn u32(&self, addr: u64) -> Result<u32> {
        let mut data = [0; 4];
        self.read_exact(addr, &mut data)?;
        Ok(u32::from_le_bytes(data))
    }

    pub fn u64(&self, addr: u64) -> Result<u64> {
        let mut data = [0; 8];
        self.read_exact(addr, &mut data)?;
        Ok(u64::from_le_bytes(data))
    }

    pub fn read_exact(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let n = self.read_at(addr, buf)?;
        if n != buf.len() {
            bail!("truncated data")
        }
        Ok(())
    }

    pub fn read_at(&self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let local_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let result =
            unsafe { libc::process_vm_readv(self.pid as i32, &local_iov, 1, &remote_iov, 1, 0) };
        if result == -1 {
            log::warn!(
                "failed to read process-{} memory, address: {:x}, size: {}",
                self.pid,
                addr,
                buf.len()
            );
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(result as usize)
        }
    }

    pub fn string(&self, addr: u64) -> Result<String> {
        let mut buf = [0; 1024];
        let n = self.read_at(addr, &mut buf)?;

        if n == 0 {
            return Ok(String::new());
        }

        let buf_slice = &buf[..n];
        if let Some(zero_idx) = buf_slice.iter().position(|&x| x == 0) {
            return Ok(String::from_utf8_lossy(&buf_slice[..zero_idx]).into_owned());
        }

        if n != buf.len() {
            return Ok(String::new());
        }

        let mut big_buf = [0u8; 4096];
        big_buf[..buf.len()].copy_from_slice(&buf);
        let n = self.read_at(addr + buf.len() as u64, &mut big_buf[buf.len()..])?;

        if n == 0 {
            return Ok(String::new());
        }

        let big_buf_slice = &big_buf[..buf.len() + n];
        if let Some(zero_idx) = big_buf_slice.iter().position(|&x| x == 0) {
            return Ok(String::from_utf8_lossy(&big_buf_slice[..zero_idx]).into_owned());
        }

        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_read_string() {
        // In Rust, str and String are not null-terminated, so here we use CString.
        let str = CString::new("abcdefg").unwrap();
        let pid = unsafe { libc::getpid() };
        let pm = ProcessMemory::new(pid as u32).unwrap();

        let ret = CString::new(pm.string(str.as_ptr() as u64).unwrap()).unwrap();
        assert_eq!(ret, str);
    }

    #[test]
    fn test_read_large_string() {
        let str = CString::new("a".repeat(2048)).unwrap();
        let pid = unsafe { libc::getpid() };
        let pm = ProcessMemory::new(pid as u32).unwrap();

        let ret = CString::new(pm.string(str.as_ptr() as u64).unwrap()).unwrap();
        assert_eq!(ret, str);
    }
}
