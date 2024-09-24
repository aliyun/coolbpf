use profiler::livetrace_profiler_create;
use profiler::livetrace_profiler_ctrl;
use profiler::livetrace_profiler_read;
use profiler::utils::process::find_processes_by_comm;
use std::ffi::CStr;
use std::ffi::CString;

unsafe extern "C" fn callback(
    pid: libc::c_uint,
    comm: *const libc::c_char,
    stack: *const libc::c_char,
    cnt: libc::c_uint,
) {
    let comm_cstring = CStr::from_ptr(comm as *mut i8);
    let stack_cstring = CStr::from_ptr(stack as *mut i8);
    println!("{pid}:{:?};{:?} {cnt}", comm_cstring, stack_cstring);
}

fn main() {
    let prof = livetrace_profiler_create();

    for pid in find_processes_by_comm("java") {
        let cstr = CString::new(pid.to_string()).unwrap();
        livetrace_profiler_ctrl(prof, 0, cstr.into_raw());

        println!("add java process: {}", pid);
    }

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        livetrace_profiler_read(prof, callback);
    }
}
