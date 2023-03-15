use cached::proc_macro::cached;
/// https://linux.die.net/man/3/clock_gettime

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

#[cached(size = 1)]
pub fn delta_of_mono_real_time() -> u64 {
    let x1 = current_monotime();
    let y1 = current_realtime();
    let y2 = current_realtime();
    let x2 = current_monotime();
    (y2 - x2 + y1 - x1) / 2
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_timestamp_current_monotime() {
        assert_ne!(current_monotime(), 0);
    }

    #[test]
    fn test_timestamp_current_realtime() {
        assert_ne!(current_realtime(), 0);
    }

    #[test]
    fn test_timestamp_delta_of_mono_real_time() {
        assert_ne!(delta_of_mono_real_time(), 0);
        assert_eq!(delta_of_mono_real_time(), delta_of_mono_real_time());
    }
}
