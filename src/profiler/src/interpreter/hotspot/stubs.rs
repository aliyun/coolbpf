/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
use super::file_info::VmStructs;
use crate::process::memory::ProcessMemory;

const CODE_ALIGN: u64 = 64;
const MAX_STUB_LEN: u64 = 8 * 1024;

#[derive(Clone)]
pub struct StubRoutine {
    pub name: String,
    pub start: u64,
    pub end: u64,
}

pub fn find_stub_bounds(vms: &VmStructs, bias: u64, pm: &ProcessMemory) -> Vec<StubRoutine> {
    let mut stubs = Vec::with_capacity(64);
    for (field, addr) in &vms.stub_routines.catch_all {
        if !field.contains("_table_") {
            let entry = pm.ptr(addr + bias).unwrap_or(0);
            if entry != 0 {
                stubs.push(StubRoutine {
                    name: field.trim_start_matches('_').to_string(),
                    start: entry,
                    end: 0, // filled in later
                });
            }
        }
    }
    stubs.sort_by(|a, b| {
        if a.start == b.start {
            return a.name.cmp(&b.name);
        }
        a.start.cmp(&b.start)
    });

    let mut filtered = Vec::with_capacity(stubs.len());
    for mut i in 0..stubs.len() {
        let cur = i;

        while i < stubs.len() {
            if i != stubs.len() - 1 {
                stubs[cur].end = stubs[i + 1].start;
            } else {
                stubs[cur].end = stubs[cur].start + MAX_STUB_LEN - 1;
            }

            if stubs[cur].start == stubs[cur].end {
                i += 1;
            } else {
                break;
            }
        }

        let heuristic_end = find_heuristic_end(stubs[cur].start, pm);
        if heuristic_end != 0 {
            stubs[cur].end = std::cmp::min(stubs[cur].end, heuristic_end);
        }

        if stubs[cur].end - stubs[cur].start > MAX_STUB_LEN {
            log::debug!(
                "Unable to determine length for JVM stub {}",
                stubs[cur].name
            );
            continue;
        }

        filtered.push(stubs[cur].clone());
    }

    filtered
}

fn find_heuristic_end(start: u64, pm: &ProcessMemory) -> u64 {
    let next_aligned = |addr: u64| -> u64 { (addr + CODE_ALIGN) & !(CODE_ALIGN - 1) };

    let mut heuristic_end = 0;
    for p in (next_aligned(start)..(start + MAX_STUB_LEN)).step_by(CODE_ALIGN as usize) {
        let mut block = [0u8; CODE_ALIGN as usize];
        if let Ok(_) = pm.read_at(p - CODE_ALIGN, &mut block) {
            if block.iter().all(|&b| b == 0) {
                heuristic_end = p;
                break;
            }
        }
    }
    // TODO: support arm64 and amd64

    heuristic_end
}
