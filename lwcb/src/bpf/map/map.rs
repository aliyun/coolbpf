use anyhow::{bail, Result};
use libbpf_sys::*;
use libc::c_void;

pub(crate) fn bpf_create_map(
    map_type: bpf_map_type,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> i64 {
    let mut attr = bpf_attr::default();

    attr.__bindgen_anon_1.map_type = map_type;
    attr.__bindgen_anon_1.key_size = key_size;
    attr.__bindgen_anon_1.value_size = value_size;
    attr.__bindgen_anon_1.max_entries = max_entries;
    attr.__bindgen_anon_1.map_flags = 0;

    return unsafe { libc::syscall(321, BPF_MAP_CREATE, &attr, std::mem::size_of::<bpf_attr>()) };
}

// int bpf_lookup_elem(int fd, void *key, void *value)
// {
// 	union bpf_attr attr;
//         memset(&attr, 0, sizeof(union bpf_attr));
// 	attr.map_fd = fd;
// 	attr.key = ptr_to_u64(key);
// 	attr.value = ptr_to_u64(value);

// 	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
// }

pub(crate) fn bpf_map_lookup(fd: i32, key: &[u8], value_size: usize) -> Result<Option<Vec<u8>>> {
    let mut value: Vec<u8> = Vec::with_capacity(value_size);

    let ret = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            fd,
            key.as_ptr() as *const c_void,
            value.as_mut_ptr() as *mut c_void,
        )
    };

    if ret == 0 {
        unsafe {
            value.set_len(value_size);
        }
        return Ok(Some(value));
    } else {
        if errno::errno() == errno::Errno(libc::ENOENT) {
            return Ok(None);
        }
        bail!("failed to do lookup: {}", errno::errno())
    }
}

pub trait Map {
    fn create(&mut self) -> Result<()>;

    fn fd(&self) -> i64;

    fn key_size(&self) -> usize;
    fn value_size(&self) -> usize;
    fn max_entries(&self) -> usize;

    fn set_key_size(&mut self, _: usize) {}

    fn set_value_size(&mut self, _: usize) {}

    fn set_max_entries(&mut self, max_entries: usize) {}
}
