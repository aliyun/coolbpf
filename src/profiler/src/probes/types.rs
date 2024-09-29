use byteorder::ByteOrder;
use byteorder::NativeEndian;
use std::ops::Deref;

/// convert any structure into bytes
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}

pub mod bpf {
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
    include!(concat!(env!("OUT_DIR"), "/stackdeltatypes.rs"));
}

macro_rules! impl_default {
    ($ident: ident) => {
        impl Default for $ident {
            fn default() -> Self {
                Self {
                    raw: unsafe { std::mem::zeroed::<bpf::$ident>() },
                }
            }
        }

        impl $ident {
            pub fn slice(&self) -> &[u8] {
                unsafe { crate::probes::types::any_as_u8_slice(&self.raw) }
            }

            pub fn raw_size(&self) -> usize {
                std::mem::size_of::<bpf::$ident>()
            }
        }
    };

    ($ident: ident, $cident: ident) => {
        impl Default for $ident {
            fn default() -> Self {
                Self {
                    raw: unsafe { std::mem::zeroed::<bpf::$cident>() },
                }
            }
        }

        impl $ident {
            pub fn slice(&self) -> &[u8] {
                unsafe { crate::probes::types::any_as_u8_slice(&self.raw) }
            }

            pub fn raw_size(&self) -> usize {
                std::mem::size_of::<bpf::$cident>()
            }
        }
    };
}

pub(crate) use impl_default;

pub struct StackEvent {
    pub raw: bpf::Trace,
}

#[derive(Debug)]
pub struct SystemConfig {
    pub raw: bpf::SystemConfig,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            raw: unsafe { std::mem::zeroed::<bpf::SystemConfig>() },
        }
    }
}

impl Deref for SystemConfig {
    type Target = bpf::SystemConfig;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl SystemConfig {
    pub fn set_pac(&mut self, pac: u64) {
        self.raw.inverse_pac_mask = !pac;
    }

    pub fn set_tpbase_offset(&mut self, off: u64) {
        self.raw.tpbase_offset = off;
    }

    pub fn set_task_stack_offset(&mut self, off: u32) {
        self.raw.task_stack_offset = off;
    }

    pub fn set_stack_ptregs_offset(&mut self, off: u32) {
        self.raw.stack_ptregs_offset = off;
    }

    pub fn set_has_pid_namespace(&mut self, has: bool) {
        self.raw.has_pid_namespace = has;
    }

    pub fn slice(&self) -> &[u8] {
        unsafe { any_as_u8_slice(&self.raw) }
    }
}

#[derive(Debug)]
pub struct SystemAnalysis {
    pub raw: bpf::SystemAnalysis,
}

impl Default for SystemAnalysis {
    fn default() -> Self {
        Self {
            raw: unsafe { std::mem::zeroed::<bpf::SystemAnalysis>() },
        }
    }
}

impl From<Vec<u8>> for SystemAnalysis {
    fn from(value: Vec<u8>) -> Self {
        let (head, body, _tail) = unsafe { value.align_to::<bpf::SystemAnalysis>() };
        debug_assert!(head.is_empty(), "Data was not aligned");
        let raw = body[0];
        Self { raw }
    }
}

impl SystemAnalysis {
    pub fn set_pid(&mut self, pid: u32) {
        self.raw.pid = pid;
    }

    pub fn set_address(&mut self, addr: u64) {
        self.raw.address = addr;
    }

    pub fn slice(&self) -> &[u8] {
        unsafe { any_as_u8_slice(&self.raw) }
    }

    pub fn code_u64(&self) -> u64 {
        NativeEndian::read_u64(&self.raw.code)
    }
}

#[repr(u32)]
pub enum UnwindProgramType {
    Native = bpf::TracePrograms_PROG_UNWIND_NATIVE,
}

pub struct HotspotProcInfo {
    pub raw: bpf::HotspotProcInfo,
}

impl_default!(HotspotProcInfo);
