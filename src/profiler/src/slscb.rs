use std::ffi::CString;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::heatmap::TenSecHeatMap;

static SLSCB_HEATMAP_SENDER: Lazy<
    Mutex<
        Option<
            unsafe extern "C" fn(
                libc::c_ulonglong,   // beg
                libc::c_uint,        // pid
                *const libc::c_char, // comm
                *const libc::c_char, // heat
            ),
        >,
    >,
> = Lazy::new(|| Mutex::new(None));

#[no_mangle]
pub extern "C" fn livetrace_slscb_register_heatmap_sender(
    send: unsafe extern "C" fn(
        libc::c_ulonglong,   // beg
        libc::c_uint,        // pid
        *const libc::c_char, // comm
        *const libc::c_char, // heat
    ),
) {
    SLSCB_HEATMAP_SENDER.lock().unwrap().replace(send);
}

pub fn slscb_call_heatmap_sender(heat: &TenSecHeatMap) {
    let beg = heat.base;
    let pid = heat.pid;
    let comm = match CString::new(heat.comm.clone()) {
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

    let cb = SLSCB_HEATMAP_SENDER.lock().unwrap();
    let cb_ptr = cb.as_ref().unwrap();
    unsafe {
        (*cb_ptr)(beg, pid, comm.as_ptr(), content.as_ptr());
    }
}
