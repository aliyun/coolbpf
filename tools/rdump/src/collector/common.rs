use log::error;
use crate::config::MEMLOCK_128M;

pub fn handle_lost_events(cpu: i32, count: u64) {
    error!("Lost {count} events on CPU {cpu}");
}

pub fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit {
        rlim_cur: MEMLOCK_128M,
        rlim_max: MEMLOCK_128M,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        // warn!("Failed to increase rlimit");
    }
}