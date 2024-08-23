use super::types::bpf;
use super::types::impl_default;
use crate::symbollizer::file_id::FileId64;
use crate::utils::lpm::Prefix;
use anyhow::bail;
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;

pub struct PidAddr {
    raw: bpf::PIDPage,
}

impl_default!(PidAddr, PIDPage);

impl PidAddr {
    pub fn new(prefix: &Prefix, pid: u32) -> Self {
        let mut pp = PidAddr::default();
        pp.raw.pid = pid.to_be();
        pp.raw.page = prefix.key.to_be();
        pp.raw.prefixLen = prefix.length + u32::BITS;
        pp
    }
}

pub struct PidMapsInfo {
    raw: bpf::PIDPageMappingInfo,
}

impl_default!(PidMapsInfo, PIDPageMappingInfo);

impl PidMapsInfo {
    pub fn new(file_id: FileId64, bias: u64) -> Self {
        let mut ppmi = PidMapsInfo::default();
        ppmi.raw.file_id = file_id.into();
        ppmi.raw.bias_and_unwind_program = bias;
        ppmi
    }
}

pub struct PidMapsInfoMap {
    map: MapHandle,
}

impl PidMapsInfoMap {
    pub fn new(map: MapHandle) -> Self {
        PidMapsInfoMap { map }
    }

    pub fn insert_dummy(&self, pid: u32) {
        let prefix = Prefix::dummy();
        self.update(pid, &prefix, FileId64(0), 0)
            .expect("failed to insert dummy prefix into pid_page_to_mapping_info map");
    }

    pub fn delete(&self, pid: u32, prefixes: &Vec<Prefix>) -> Result<()> {
        for prefix in prefixes {
            self.__delete(pid, prefix)?;
        }
        Ok(())
    }

    fn __delete(&self, pid: u32, prefix: &Prefix) -> Result<()> {
        let pp = PidAddr::new(prefix, pid);
        self.map.delete(pp.slice())?;
        Ok(())
    }

    pub fn update(&self, pid: u32, prefix: &Prefix, file_id: FileId64, bias: u64) -> Result<()> {
        let encoded_bias = encode_bias_and_unwind_program(bias, 1)?;

        let key = PidAddr::new(&prefix, pid);
        let val = PidMapsInfo::new(file_id, encoded_bias);
        self.map
            .update(key.slice(), val.slice(), MapFlags::NO_EXIST)?;
        Ok(())
    }

    pub fn interpreter_update(
        &self,
        pid: u32,
        prefix: &Prefix,
        prog: u8,
        file_id: FileId64,
        bias: u64,
    ) -> Result<()> {
        let key = PidAddr::new(prefix, pid);
        let bias_and_unwind_program = encode_bias_and_unwind_program(bias, prog)?;
        let val = PidMapsInfo::new(file_id, bias_and_unwind_program);
        self.map
            .update(key.slice(), val.slice(), MapFlags::NO_EXIST)?;
        Ok(())
    }
}

fn encode_bias_and_unwind_program(bias: u64, unwind_program: u8) -> Result<u64> {
    if (bias >> 56) > 0 {
        bail!("bias value too large");
    }
    return Ok(bias | ((unwind_program as u64) << 56));
}

fn decode_bias_and_unwind_program(bias_and_unwind_program: u64) -> (u64, u8) {
    return (
        bias_and_unwind_program & 0x00ffffffffffffff,
        (bias_and_unwind_program >> 56) as u8,
    );
}
