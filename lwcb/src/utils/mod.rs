use anyhow::{bail, Result};

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn to_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>()) }
}

mod macros;
pub(crate) mod tcpstate;

pub(crate) mod align;
pub(crate) mod btf;
pub(crate) mod kernel_version;
pub(crate) mod tcpflags;
pub(crate) mod timestr;
pub(crate) mod tracepoint;
pub(crate) mod tstamp;
