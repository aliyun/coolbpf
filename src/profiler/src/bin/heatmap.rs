use profiler::livetrace_profiler_create;
use profiler::livetrace_profiler_ctrl;
use profiler::livetrace_profiler_read;
use profiler::livetrace_profiler_read_heatmap;
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
    _pid: libc::c_uint,
    _comm: *const libc::c_char,
    _stack: *const libc::c_char,
    _cnt: libc::c_uint,
) {
}

unsafe extern "C" fn handle_heatmap(
    ts: u64,
    pid: u32,
    comm: *const libc::c_char,
    heat: *const libc::c_char,
) {
    let comm_cstring = CStr::from_ptr(comm);
    let heatmap_cstring = CStr::from_ptr(heat);

    println!("{ts} {pid}-{:?}: {:?}", comm_cstring, heatmap_cstring);
}

fn main() {
    let opts = Command::from_args();
    let prof = livetrace_profiler_create();
    let cstr = CString::new(opts.pid.to_string()).unwrap();
    let raw = cstr.into_raw();
    livetrace_profiler_ctrl(prof, 1, raw);
    livetrace_profiler_ctrl(prof, 2, raw);

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        livetrace_profiler_read(prof, callback);
        livetrace_profiler_read_heatmap(prof, handle_heatmap);
    }
}
