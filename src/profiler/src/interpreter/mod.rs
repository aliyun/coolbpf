use crate::probes::probes::Probes;
use crate::probes::types::bpf::Frame;
use crate::process::process::Process;
use crate::stack::Stack;
use hotspot::file_info::HotspotFileInfo;
use hotspot::instance::HotspotInstance;
use std::rc::Rc;
pub mod hotspot;
use anyhow::Result;
pub mod python;

pub enum IFileInfo {
    Hotspot(Rc<HotspotFileInfo>),
}

impl IFileInfo {
    pub fn parse(file_name: &str, elf: &object::File) -> Option<IFileInfo> {
        if file_name.contains("libjvm.so") {
            match HotspotFileInfo::new(file_name, elf) {
                Ok(hs) => {
                    return Some(IFileInfo::Hotspot(Rc::new(hs)));
                }
                Err(e) => {
                    log::warn!("failed to parse file: {file_name}, error: {e}");
                    return None;
                }
            }
        }
        None
    }
}

pub enum Interpreter {
    Hotspot(HotspotInstance),
}

impl Interpreter {
    pub fn parse(fi: &IFileInfo, proc: &Process, bias: u64) -> Result<Interpreter> {
        match fi {
            IFileInfo::Hotspot(hs) => Ok(Interpreter::Hotspot(HotspotInstance::new(
                hs.clone(),
                proc,
                bias,
            )?)),
        }
    }

    pub fn sync_maps(&mut self, probes: &mut Probes) -> Result<()> {
        match self {
            Interpreter::Hotspot(hs) => hs.sync_maps(probes),
        }
    }

    pub fn symbolize(&mut self, frame: &Frame, stack: &mut Stack) -> Result<()> {
        match self {
            Interpreter::Hotspot(hs) => {
                hs.symbolize(frame, stack)?;
            }
        }

        Ok(())
    }
}
