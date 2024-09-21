use profiler::Profiler;
use std::ffi::CStr;
use std::ffi::CString;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
pub mod error;
pub mod executable;
pub mod interpreter;
pub mod opened_file;
pub mod pb;
pub mod probes;
pub mod process;
pub mod profiler;
pub mod stack;
pub mod symbollizer;
pub mod utils;
use ctor::*;

const MAX_NUM_OF_PROCESSES: usize = 4096;
const MIN_PROCESS_SAMPLES: usize = 10;

pub static SYSTEM_PROFILING: AtomicBool = AtomicBool::new(false);

pub fn is_system_profiling() -> bool {
    SYSTEM_PROFILING.load(Ordering::SeqCst)
}

#[ctor]
fn global_libarary_constructor() {
    env_logger::init();
}

#[no_mangle]
pub extern "C" fn livetrace_enable_system_profiling() {
    SYSTEM_PROFILING.store(true, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn livetrace_profiler_create() -> *mut Profiler<'static> {
    Box::into_raw(Box::new(Profiler::new()))
}

#[no_mangle]
pub extern "C" fn livetrace_profiler_destroy(profiler: *mut Profiler) {
    if !profiler.is_null() {
        unsafe { std::ptr::drop_in_place(profiler) }
    }
}

#[no_mangle]
pub extern "C" fn livetrace_profiler_ctrl(
    profiler: *mut Profiler,
    _op: libc::c_int,
    pids: *const libc::c_char,
) -> i32 {
    let pids = unsafe { CStr::from_ptr(pids) };
    let pids = match pids.to_str() {
        Ok(pids) => pids,
        Err(_e) => {
            return -1;
        }
    };

    let pids: Vec<u32> = match pids.split(',').map(str::trim).map(str::parse).collect() {
        Ok(pids) => pids,
        Err(_e) => return -1,
    };

    let profiler = match unsafe { profiler.as_mut() } {
        Some(profiler) => profiler,
        None => return -1,
    };

    match profiler.populate_pids(pids) {
        Ok(()) => 0,
        Err(_e) => -1,
    }
}

#[no_mangle]
pub extern "C" fn livetrace_profiler_read(
    profiler: *mut Profiler,
    cb: unsafe extern "C" fn(libc::c_uint, *const libc::c_char, *const libc::c_char, libc::c_uint),
) {
    let profiler = match unsafe { profiler.as_mut() } {
        Some(profiler) => profiler,
        None => return,
    };

    for proc in profiler.read() {
        let cstr = CString::new(proc.to_string()).unwrap();
        let comm = CString::new(proc.comm.clone()).unwrap();
        unsafe { cb(proc.pid, comm.as_ptr(), cstr.as_ptr(), proc.count) };
    }
}

#[no_mangle]
pub extern "C" fn livetrace_profiler_read_bytes(
    profiler: *mut Profiler,
    cb: unsafe extern "C" fn(*const libc::uint8_t, libc::c_uint),
) {
    let profiler = match unsafe { profiler.as_mut() } {
        Some(profiler) => profiler,
        None => return,
    };

    let bytes = profiler.read2();
    if !bytes.is_empty() {
        unsafe {
            cb(bytes.as_ptr(), bytes.len() as u32);
        }
    }
}
