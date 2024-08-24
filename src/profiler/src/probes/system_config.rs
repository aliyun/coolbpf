use crate::SYSTEM_PROFILING;

use super::types::SystemConfig;
use libbpf_rs::btf::types::Composite;
use libbpf_rs::btf::types::MemberAttr;
use libbpf_rs::btf::types::Struct;
use libbpf_rs::Btf;
use std::cmp::Ordering;
use std::sync::atomic;

pub fn get_system_config() -> SystemConfig {
    let btf = Btf::from_vmlinux().unwrap();
    let mut sc = SystemConfig::default();

    let system_profiling = SYSTEM_PROFILING.load(atomic::Ordering::SeqCst);

    let ty = Composite::from(btf.type_by_name::<Struct>("task_struct").unwrap());
    let thread_offset = get_member_offset(&ty, "thread");
    let thread_ty = Composite::from(btf.type_by_name::<Struct>("thread_struct").unwrap());
    let fsbase_offset = get_member_offset(&thread_ty, "fsbase");
    sc.set_pac(0);
    sc.raw.drop_error_only_traces = true;
    sc.raw.all_system_profiling = system_profiling;
    sc.set_task_stack_offset(get_member_offset(&ty, "stack").unwrap());
    sc.set_tpbase_offset((thread_offset.unwrap() + fsbase_offset.unwrap()) as u64);
    sc
}

fn get_member_offset(comp: &Composite, name: &str) -> Option<u32> {
    for mem in comp.iter() {
        if let Some(x) = mem.name {
            if let Some(y) = x.to_str().ok() {
                if y.cmp(name) == Ordering::Equal {
                    match mem.attr {
                        MemberAttr::Normal { offset } => {
                            log::debug!("offset: {}", offset);
                            return Some(offset / 8);
                        }
                        MemberAttr::BitField { size, offset } => {
                            panic!("size: {}, offset: {}", size, offset);
                        }
                    };
                }
            }
        }
    }
    None
}

pub fn run_bpf() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ksyms() {
        println!("{:?}", get_system_config());
    }
}
