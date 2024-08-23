/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
use super::types::bpf;
use super::types::impl_default;
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;

#[derive(Debug, Copy, Clone)]
pub struct UnwindInfo {
    pub raw: bpf::UnwindInfo,
}

impl fmt::Display for UnwindInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{Opcode:{} FPOpcode:{} MergeOpcode:{} Param:{} FPParam:{}}}",
            self.raw.opcode,
            self.raw.fpOpcode,
            self.raw.mergeOpcode,
            self.raw.param,
            self.raw.fpParam
        )
    }
}

impl PartialEq for UnwindInfo {
    fn eq(&self, other: &Self) -> bool {
        self.raw.opcode == other.raw.opcode
            && self.raw.fpOpcode == other.raw.fpOpcode
            && self.raw.mergeOpcode == other.raw.mergeOpcode
            && self.raw.param == other.raw.param
            && self.raw.fpParam == other.raw.fpParam
    }
}

impl Hash for UnwindInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.opcode.hash(state);
        self.raw.fpOpcode.hash(state);
        self.raw.mergeOpcode.hash(state);
        self.raw.param.hash(state);
        self.raw.fpParam.hash(state);
    }
}

impl Eq for UnwindInfo {}

impl_default!(UnwindInfo);

impl UnwindInfo {
    pub fn invalid() -> Self {
        let mut uwi = UnwindInfo::default();
        uwi.raw.opcode = bpf::UNWIND_OPCODE_COMMAND as u8;
        uwi.raw.param = bpf::UNWIND_COMMAND_INVALID as i32;
        uwi
    }

    pub fn stop() -> Self {
        let mut uwi = UnwindInfo::default();
        uwi.raw.opcode = bpf::UNWIND_OPCODE_COMMAND as u8;
        uwi.raw.param = bpf::UNWIND_COMMAND_STOP as i32;
        uwi
    }

    pub fn signal() -> Self {
        let mut uwi = UnwindInfo::default();
        uwi.raw.opcode = bpf::UNWIND_OPCODE_COMMAND as u8;
        uwi.raw.param = bpf::UNWIND_COMMAND_SIGNAL as i32;
        uwi
    }

    pub fn frame_pointer() -> Self {
        let mut uwi = UnwindInfo::default();
        uwi.raw.opcode = bpf::UNWIND_OPCODE_BASE_FP as u8;
        uwi.raw.param = 16;
        uwi.raw.fpOpcode = bpf::UNWIND_OPCODE_BASE_CFA as u8;
        uwi.raw.fpParam = -16;
        uwi
    }

    pub fn set_opcode(&mut self, opcode: u8) {
        self.raw.opcode = opcode;
    }

    pub fn set_param(&mut self, param: i32) {
        self.raw.param = param;
    }

    pub fn set_fpopcode(&mut self, opcode: u8) {
        self.raw.fpOpcode = opcode;
    }

    pub fn set_fpparam(&mut self, param: i32) {
        self.raw.fpParam = param;
    }
}

pub struct UnwindInfoMap {
    map: MapHandle,
}

impl UnwindInfoMap {
    pub fn new(map: MapHandle) -> Self {
        UnwindInfoMap { map }
    }

    pub fn update(&self, index: u32, info: &UnwindInfo) -> Result<()> {
        self.map
            .update(&index.to_ne_bytes(), info.slice(), MapFlags::ANY)?;
        Ok(())
    }
}
