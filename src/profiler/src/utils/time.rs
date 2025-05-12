use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use chrono::DateTime;
use chrono::Local;

static DELTA_OF_MONO_REAL_TIME: AtomicU64 = AtomicU64::new(0);

/// Monotonically increasing timestamp, incremented by 1 when the clock interrupt
/// is triggered. This clock source is used by the bpf_ktime_get_ns function.
pub fn current_monotime() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };

    (ts.tv_sec as u64) * 1000_000_000 + (ts.tv_nsec as u64)
}

/// System-wide realtime clock. It is generally synchronized with the clock of
/// the master server through the ntp protocol.
pub fn current_realtime() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };

    (ts.tv_sec as u64) * 1000_000_000 + (ts.tv_nsec as u64)
}

pub fn monotime_to_datetime(ns: u64) -> DateTime<Local> {
    let realtime = ns + DELTA_OF_MONO_REAL_TIME.load(Ordering::SeqCst);

    let secs = realtime / 1000_000_000;
    let nsecs = realtime % 1000_000_000;
    DateTime::from_timestamp(secs as i64, nsecs as u32)
        .unwrap()
        .into()
}

pub fn __monotime_to_datatime(ns: u64) -> u64 {
    ns + DELTA_OF_MONO_REAL_TIME.load(Ordering::SeqCst)
}

pub fn time_delta() -> u64 {
    DELTA_OF_MONO_REAL_TIME.load(Ordering::SeqCst)
}

pub fn init_tstamp() {
    let x1 = current_monotime();
    let y1 = current_realtime();
    let y2 = current_realtime();
    let x2 = current_monotime();
    let delta = (y2 - x2 + y1 - x1) / 2;

    DELTA_OF_MONO_REAL_TIME.store(delta, Ordering::SeqCst);
}
