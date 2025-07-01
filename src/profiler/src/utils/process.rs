use glob::Pattern;
use procfs::process::all_processes;

pub fn find_processes_by_comm(pat: &str) -> Vec<i32> {
    let mut ret = vec![];
    let pattern = Pattern::new(pat).unwrap();

    all_processes().unwrap().into_iter().for_each(|p| {
        let stat = p.unwrap().stat().unwrap();
        if pattern.matches(&stat.comm) {
            ret.push(stat.pid);
        }
    });

    ret
}

pub fn get_comm_by_pid(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    match std::fs::read_to_string(path) {
        Ok(mut s) => {
            s.pop(); // 去除末尾换行符
            s
        }
        Err(_) => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_pid() {
        // 获取当前进程的 PID
        let current_pid = std::process::id();
        // 获取当前进程的 comm
        let comm = get_comm_by_pid(current_pid);
        // 验证 comm 不为空且不为 "Unknown"
        assert!(
            !comm.is_empty(),
            "Expected non-empty comm for current process"
        );
        assert_ne!(comm, "Unknown", "Expected valid comm for current process");
        log::info!("Current process (PID {}): {}", current_pid, comm);
    }

    #[test]
    fn test_invalid_pid() {
        // 使用一个不可能存在的 PID
        let invalid_pid = u32::MAX; // 4294967295
        let comm = get_comm_by_pid(invalid_pid);
        assert_eq!(comm, "Unknown", "Expected 'Unknown' for invalid PID");
        log::info!("Invalid process (PID {}): {}", invalid_pid, comm);
    }
}
