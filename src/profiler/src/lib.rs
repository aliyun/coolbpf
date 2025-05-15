use profiler::Profiler;
use stack::SymbolizedStack;
use std::ffi::CStr;
use std::ffi::CString;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
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
pub mod tpbase;
pub mod utils;
use ctor::*;
use std::str::FromStr;
pub mod heatmap;

const MAX_NUM_OF_PROCESSES: usize = 4096;
const MIN_PROCESS_SAMPLES: usize = 10;

pub static SYSTEM_PROFILING: AtomicBool = AtomicBool::new(false);
pub static ENABLE_SYMBOLIZER: AtomicBool = AtomicBool::new(true);
pub static SYMBOL_FILE_MAX_SIZE: AtomicU64 = AtomicU64::new(u64::MAX);
pub static LIVETRACE_ENABLE_CPU_INFO: AtomicBool = AtomicBool::new(false);
pub static LIVETRACE_ENABLE_FUNCTION_OFFSET: AtomicBool = AtomicBool::new(false);

pub fn is_enable_cpuno() -> bool {
    LIVETRACE_ENABLE_CPU_INFO.load(Ordering::SeqCst)
}

pub fn is_enable_function_offset() -> bool {
    LIVETRACE_ENABLE_FUNCTION_OFFSET.load(Ordering::SeqCst)
}

pub fn is_system_profiling() -> bool {
    SYSTEM_PROFILING.load(Ordering::SeqCst)
}

pub fn is_enable_symbolizer() -> bool {
    ENABLE_SYMBOLIZER.load(Ordering::SeqCst)
}

pub fn symbol_file_max_size() -> u64 {
    SYMBOL_FILE_MAX_SIZE.load(Ordering::SeqCst)
}

pub fn symbol_file_max_symbols() -> u64 {
    let sz = symbol_file_max_size();
    if sz == u64::MAX {
        return u64::MAX;
    }
    sz / 100
}

#[ctor]
fn global_libarary_constructor() {
    env_logger::init();

    match std::env::var("LIVETRACE_SYMBOL_FILE_MAX_MB") {
        Ok(value) => {
            let sz = match u64::from_str(&value) {
                Ok(num) => num * 1024 * 1024,
                Err(_) => 2 * 1024 * 1025,
            };
            SYMBOL_FILE_MAX_SIZE.store(sz, Ordering::SeqCst);
        }
        Err(_) => {}
    };

    match std::env::var("LIVETRACE_ENABLE_CPU_INFO") {
        Ok(value) => {
            if value == "1" {
                LIVETRACE_ENABLE_CPU_INFO.store(true, Ordering::SeqCst);
            }
        }
        Err(_) => {}
    };

    match std::env::var("LIVETRACE_ENABLE_FUNCTION_OFFSET") {
        Ok(value) => {
            if value == "1" {
                LIVETRACE_ENABLE_FUNCTION_OFFSET.store(true, Ordering::SeqCst);
            }
        }
        Err(_) => {}
    };
}

#[no_mangle]
pub extern "C" fn livetrace_enable_system_profiling() {
    SYSTEM_PROFILING.store(true, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn livetrace_disable_symbolizer() {
    ENABLE_SYMBOLIZER.store(false, Ordering::SeqCst);
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
    op: libc::c_int,
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

    if op == 1 {
        return match profiler.populate_pids(pids.clone()) {
            Ok(()) => 0,
            Err(_e) => -1,
        };
    } else if op == 0 {
        for pid in pids {
            match profiler.process_exit(pid) {
                Ok(()) => continue,
                Err(_e) => return -1,
            };
        }
    } else if op == 2 {
        // add heatmap process
        profiler.add_heatmap_pids(pids);
    }
    -1
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
        send_symbolized_stack(proc, cb);
    }
}

#[no_mangle]
pub extern "C" fn livetrace_profiler_read_heatmap(
    profiler: *mut Profiler,
    cb: unsafe extern "C" fn(
        libc::c_ulonglong,
        libc::c_uint,
        *const libc::c_char,
        *const libc::c_char,
    ),
) {
    let profiler = match unsafe { profiler.as_mut() } {
        Some(profiler) => profiler,
        None => return,
    };

    for heat in profiler.proc_heatmap.flush() {
        let beg = heat.base;
        let pid = heat.pid;
        let comm = match CString::new(heat.comm) {
            Ok(c) => c,
            Err(_) => return,
        };

        let content = heat
            .values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .join(" ");

        let content = match CString::new(content) {
            Ok(c) => c,
            Err(_) => return,
        };

        unsafe {
            cb(beg, pid, comm.as_ptr(), content.as_ptr());
        }
    }
}

fn send_symbolized_stack(
    proc: SymbolizedStack,
    cb: unsafe extern "C" fn(libc::c_uint, *const libc::c_char, *const libc::c_char, libc::c_uint),
) {
    let mut cnt = 0;

    loop {
        let mut stack_cnt = 0;
        let mut stack_data = Vec::new();
        let mut data_len = 0;
        for stack in proc.stacks[cnt..].iter() {
            cnt += 1;
            stack_cnt += stack.count;
            let tmp = format!("{}:{};{}", proc.comm, proc.pid, stack.to_string());
            data_len += tmp.len() + 1;
            stack_data.push(tmp);
            if data_len > 8 * 1024 * 1024 {
                break;
            }
        }

        if data_len == 0 {
            break;
        }

        let data = stack_data.join("\n");
        if let Ok(cstr) = CString::new(data) {
            if let Ok(comm) = CString::new(proc.comm.clone()) {
                unsafe { cb(proc.pid, comm.as_ptr(), cstr.as_ptr(), stack_cnt) };
            }
        }
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

#[cfg(test)]
mod tests {
    use crate::stack::Stack;
    use crate::symbollizer::symbolizer::Symbol;

    use super::*;

    unsafe extern "C" fn test_send_data_call_back(
        pid: libc::c_uint,
        comm: *const libc::c_char,
        stack: *const libc::c_char,
        cnt: libc::c_uint,
    ) {
        let stack_cstring = CStr::from_ptr(stack);
        assert!(stack_cstring.count_bytes() > 0);
        assert!(stack_cstring.count_bytes() < 9 * 1024 * 1024);
        assert!(pid == 1);
        assert_ne!(cnt, 0);
    }

    #[test]
    fn test_send_symbolized_stack_large() {
        let mut proc = SymbolizedStack {
            comm: "test".to_string(),
            pid: 1,
            count: 0,
            stacks: vec![],
        };

        // 10kb
        let stack = Stack {
            count: 1,
            frames: vec![
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
                Symbol::new("s".repeat(1024)),
            ],
        };

        // 10kb * 10240 => 100mb
        for _ in 0..10240 {
            proc.stacks.push(stack.clone());
        }

        send_symbolized_stack(proc, test_send_data_call_back);
    }

    fn test_send_symbolized_stack_small() {
        let mut proc = SymbolizedStack {
            comm: "test".to_string(),
            pid: 1,
            count: 0,
            stacks: vec![],
        };

        // 10b
        let stack = Stack {
            count: 1,
            frames: vec![
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
                Symbol::new("s".repeat(1)),
            ],
        };

        // 10b * 10240 => 100kb
        for _ in 0..10240 {
            proc.stacks.push(stack.clone());
        }

        send_symbolized_stack(proc, test_send_data_call_back);
    }
}
