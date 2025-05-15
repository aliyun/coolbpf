use profiler::livetrace_profiler_create;
use profiler::livetrace_profiler_ctrl;
use profiler::livetrace_profiler_read;
use profiler::profiler::Profiler;
use profiler::utils::process::find_processes_by_comm;
use std::ffi::CStr;
use std::ffi::CString;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "rtrace", about = "Diagnosing tools of kernel network")]
pub struct Command {
    #[structopt(long, help = "Specify the Pid of the tracking process")]
    pid: u32,
}

unsafe extern "C" fn callback(
    pid: libc::c_uint,
    comm: *const libc::c_char,
    stack: *const libc::c_char,
    cnt: libc::c_uint,
) {
    let comm_cstring = CStr::from_ptr(comm);
    let stack_cstring = CStr::from_ptr(stack);
    println!("{pid}:{:?};{:?} {cnt}", comm_cstring, stack_cstring);
}

fn main() {
    let opts = Command::from_args();
    let mut prof = Profiler::new();
    prof.populate_pids(vec![opts.pid]).unwrap();
    loop {
        prof.poll();
    }
}
