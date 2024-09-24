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
