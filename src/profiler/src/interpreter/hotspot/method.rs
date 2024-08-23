/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
use std::collections::HashMap;
use std::collections::HashSet;

use super::file_info::HotspotFileInfo;
use super::file_info::HotspotVmInfo;
use super::instance::HotspotInstance;
use crate::probes::probes::Probes;
use crate::probes::types::bpf::FileID;
use crate::symbollizer::symbolizer::Symbol;
use crate::utils::safe_reader::SafeReader;
use anyhow::Result;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub struct HotspotMethod {
    pub source_file_name: String,
    // pub object_id: FileID,
    pub method_name: String,
    pub bytecode_size: u16,
    pub start_line_no: u16,
    pub line_table: Vec<u8>,
    pub bci_seen: HashSet<u16>,
}

#[derive(Debug)]
pub struct HotspotJITInfo {
    pub compile_id: u32,
    pub method: u64,
    pub scopes_pcs: Vec<u8>,
    pub scopes_data: Vec<u8>,
    pub metadata: Vec<u8>,
}

impl HotspotJITInfo {
    pub fn get_methods(&self, rip_delta: i32, hi: &HotspotInstance) -> Result<Vec<(u64, i32)>> {
        let vms = &hi.vm.clone().vm_structs;
        let mut best_pcdelta: i32 = -2;
        let mut scope_off = 0;
        let scopes_pcs = &self.scopes_pcs;

        for i in (0..scopes_pcs.len()).step_by(vms.pc_desc.sizeof as usize) {
            let pc_delta = (SafeReader::u32(scopes_pcs, i + vms.pc_desc.pc_offset as usize)) as i32;
            if pc_delta >= best_pcdelta && pc_delta <= rip_delta {
                best_pcdelta = pc_delta;
                scope_off =
                    SafeReader::u32(scopes_pcs, i + vms.pc_desc.scope_decode_offset as usize);
                if pc_delta == rip_delta {
                    break;
                }
            }
        }

        if scope_off == 0 {
            return Ok(vec![(self.method, 0)]);
        }
        let mut max_scope_off = self.scopes_data.len() as u32;
        let mut methods = vec![];
        while scope_off != 0 && scope_off < max_scope_off {
            max_scope_off = scope_off;
            let mut decoder = hi.unsigned5_decoder(&self.scopes_data[scope_off as usize..]);
            scope_off = decoder.get_uint()?;
            let method_idx = decoder.get_uint()?;
            let mut byte_code_index = decoder.get_uint()?;

            if byte_code_index > 0 {
                byte_code_index -= 1;
            }

            if method_idx != 0 {
                let method_ptr = SafeReader::ptr(&self.metadata, 8 * (method_idx - 1) as usize);
                methods.push((method_ptr, byte_code_index as i32));
            }
        }

        Ok(methods)
    }
}
