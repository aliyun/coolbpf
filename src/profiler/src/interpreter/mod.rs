use crate::probes::probes::Probes;
use crate::probes::types::bpf;
use crate::probes::types::bpf::Frame;
use crate::process::process::Process;
use crate::stack::Stack;
use crate::symbollizer::file_id::FileId64;
use hotspot::file_info::HotspotFileInfo;
use hotspot::instance::HotspotInstance;
use python::python::PythonData;
use python::python::PythonInstance;
use regex::Regex;
use std::rc::Rc;
pub mod hotspot;
use anyhow::Result;
pub mod python;

pub enum IFileInfo {
    Hotspot(Rc<HotspotFileInfo>),
    Python(PythonData),
}

impl IFileInfo {
    pub fn parse(
        file_name: &str,
        elf: &object::File,
        id: FileId64,
        bias: u64,
        probes: &Probes,
    ) -> Option<IFileInfo> {
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
        } else if file_name.contains("python") {
            return PythonData::new(file_name, elf, id, bias, probes).map_or_else(
                |e| {
                    log::warn!("failed to parse python file: {e}");
                    None
                },
                |x| Some(IFileInfo::Python(x)),
            );
        }

        None
    }
}

pub enum Interpreter {
    Hotspot(HotspotInstance),
    Python(PythonInstance),
}

impl Interpreter {
    pub fn parse(fi: &IFileInfo, proc: &Process, bias: u64) -> Result<Interpreter> {
        match fi {
            IFileInfo::Hotspot(hs) => Ok(Interpreter::Hotspot(HotspotInstance::new(
                hs.clone(),
                proc,
                bias,
            )?)),

            IFileInfo::Python(py) => Ok(Interpreter::Python(
                PythonInstance::new(py.clone(), proc, bias).unwrap(),
            )),
        }
    }

    pub fn sync_maps(&mut self, probes: &mut Probes) -> Result<()> {
        match self {
            Interpreter::Hotspot(hs) => hs.sync_maps(probes),
            Interpreter::Python(_) => Ok(()),
        }
    }

    pub fn update_tsd_info(
        &mut self,
        probes: &Probes,
        pid: u32,
        tsd_info: bpf::TSDInfo,
    ) -> Result<()> {
        match self {
            Interpreter::Hotspot(_hs) => Ok(()),
            Interpreter::Python(py) => py.update_tsd_info(probes, pid, tsd_info),
        }
    }

    pub fn symbolize(&mut self, frame: &Frame, stack: &mut Stack) -> Result<()> {
        match self {
            Interpreter::Hotspot(hs) => {
                hs.symbolize(frame, stack)?;
            }
            Interpreter::Python(py) => {
                py.symbolize(frame, stack)?;
            }
        }

        Ok(())
    }
}
