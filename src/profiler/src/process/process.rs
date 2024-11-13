use super::maps::ExeMapsEntry;
use super::memory::ProcessMemory;
use crate::executable::ExecutableCache;
use crate::probes::probes::Probes;
use crate::probes::types::bpf;
use crate::symbollizer::file_cache::FileInfo;
use crate::utils::lpm::calculate_prefixes;
use anyhow::Result;
use std::collections::HashMap;

#[derive(Default)]
pub struct Process {
    pub maps: HashMap<u64, ExeMapsEntry>,
    pub tsd_info: Option<bpf::TSDInfo>,
    pub pid: u32,
}

impl Process {
    pub fn new(pid: u32) -> Self {
        Process {
            pid,
            ..Default::default()
        }
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn memory(&self) -> Result<ProcessMemory> {
        ProcessMemory::new(self.pid)
    }

    pub fn remove_maps_entries(
        &mut self,
        probes: &mut Probes,
        exes: &mut ExecutableCache,
        entries: &Vec<u64>,
    ) -> Result<()> {
        for &map in entries {
            if let Some(f) = self.maps.remove(&map) {
                log::debug!("remove pid:{} maps entry: {:?}", self.pid(), f);
                let prefixes = calculate_prefixes(f.vaddr, f.vaddr + f.length)?;
                probes.pid_maps_info_map.delete(self.pid(), &prefixes)?;
                exes.remove(probes, f.file_id)?;
            }
        }
        Ok(())
    }

    pub fn exit(&mut self, probes: &mut Probes, exes: &mut ExecutableCache) -> Result<()> {
        for (_, f) in &self.maps {
            log::debug!("remove pid:{} maps entry: {:?}", self.pid(), f);
            let prefixes = calculate_prefixes(f.vaddr, f.vaddr + f.length)?;
            probes.pid_maps_info_map.delete(self.pid(), &prefixes)?;
            exes.remove(probes, f.file_id)?;
        }
        Ok(())
    }

    pub fn add_maps_entry(
        &mut self,
        elf: &FileInfo,
        probes: &mut Probes,
        added: ExeMapsEntry,
    ) -> Result<()> {
        if self.maps.contains_key(&added.vaddr) {
            return Ok(());
        }
        let prefixes = calculate_prefixes(added.vaddr, added.vaddr + added.length)?;

        for prefix in prefixes {
            probes
                .pid_maps_info_map
                .update(self.pid, &prefix, elf.file_id, added.bias)?;
        }

        log::debug!("added new maps, pid: {}, {:x?}", self.pid, added);
        self.maps.insert(added.vaddr, added);

        Ok(())
    }
}
