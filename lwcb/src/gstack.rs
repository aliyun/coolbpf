// global stackmap
use crate::{
    bpf::map::{Map, PerfEvent, PerfMap, StackMap},
    kallsyms::GLOBAL_KALLSYMS,
};
use lazy_static::lazy_static;
use paste::paste;
use std::sync::{Mutex, MutexGuard};

macro_rules! create_stackmap {
    ($($depth: expr), *) => {
        paste! {
            $(
                lazy_static! {
                    pub static ref [<GLOBAL_STACKMAP_ $depth>]: StackMap = {
                        let mut stack = StackMap::new();
                        stack.set_depth($depth);
                        stack.create().unwrap();
                        stack
                    };
                }
            )*
        }
    };
}

create_stackmap!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20);

pub fn get_stackmap(depth: u8) -> &'static StackMap {
    match depth {
        1 => &*GLOBAL_STACKMAP_1,
        2 => &*GLOBAL_STACKMAP_2,
        3 => &*GLOBAL_STACKMAP_3,
        4 => &*GLOBAL_STACKMAP_4,
        5 => &*GLOBAL_STACKMAP_5,
        6 => &*GLOBAL_STACKMAP_6,
        7 => &*GLOBAL_STACKMAP_7,
        8 => &*GLOBAL_STACKMAP_8,
        9 => &*GLOBAL_STACKMAP_9,
        10 => &*GLOBAL_STACKMAP_10,
        11 => &*GLOBAL_STACKMAP_11,
        12 => &*GLOBAL_STACKMAP_12,
        13 => &*GLOBAL_STACKMAP_13,
        14 => &*GLOBAL_STACKMAP_14,
        15 => &*GLOBAL_STACKMAP_15,
        16 => &*GLOBAL_STACKMAP_16,
        17 => &*GLOBAL_STACKMAP_17,
        18 => &*GLOBAL_STACKMAP_18,
        19 => &*GLOBAL_STACKMAP_19,
        20 => &*GLOBAL_STACKMAP_20,
        _ => panic!("Over max depth: 20"),
    }
}

pub fn get_stackmap_fd(depth: u8) -> i64 {
    get_stackmap(depth).fd()
}

pub fn get_stack_string(stack: &Vec<u64>) -> String {
    let mut stack_string = "\n".to_owned();
    for addr in stack {
        stack_string.push('\t');
        stack_string.push_str(GLOBAL_KALLSYMS.addr_to_sym(*addr).as_str());
        stack_string.push('\n');
    }

    stack_string
}
