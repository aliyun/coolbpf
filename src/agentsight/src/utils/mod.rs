
use anyhow::Result;

pub fn find_openclaw() -> Result<Vec<i32>> {
    let mut res = vec![];
    for proc in procfs::process::all_processes()? {
        if let Ok(proc) = proc {
            if let Ok(cmd) = proc.cmdline() {
                for c in cmd {
                    if c.starts_with("openclaw-gateway") {
                        res.push(proc.pid);
                    }
                }
            }
        }
        
    }
    Ok(res)
}