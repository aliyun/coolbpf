use crate::interpreter::IFileInfo;
use crate::probes::probes::Probes;
use crate::probes::stack_delta::StackDelta;
use crate::probes::types::bpf;
use crate::probes::types::bpf::STACK_DELTA_PAGE_BITS;
use crate::probes::types::bpf::STACK_DELTA_PAGE_MASK;
use crate::process::maps::ProcessMapsEntry;
use crate::symbollizer::elf::ElfFile;
use crate::symbollizer::file_cache::FileInfo;
use crate::symbollizer::file_id::FileId64;
use crate::tpbase::libc::extract_tsd_info;
use crate::tpbase::libc::is_potential_tsd_dso;
use anyhow::bail;
use anyhow::Result;
use std::collections::HashMap;
use std::collections::HashSet;

pub struct LoadedDelta {
    map_id: u16,
    num_page: u32,
    start_page: u64,
}

pub struct Executable {
    map_info: LoadedDelta,
    pub i_info: Option<IFileInfo>,
    pub tsd_info: Option<bpf::TSDInfo>,
    rc: u32,
}

#[derive(Default)]
pub struct ExecutableCache {
    errors: HashSet<FileId64>,
    pub executables: HashMap<FileId64, Executable>,
}

impl ExecutableCache {
    pub fn load_stack_deltas() {}

    pub fn remove(&mut self, probes: &mut Probes, id: FileId64) -> Result<()> {
        let mut remove = false;
        if let Some(exe) = self.executables.get(&id) {
            if exe.rc == 1 {
                remove = true;
            }
        }

        if remove {
            if let Some(exe) = self.executables.remove(&id) {
                probes.stack_delta_page_map.delete(
                    id,
                    exe.map_info.start_page,
                    exe.map_info.num_page,
                )?;
                probes
                    .stack_delta_map
                    .delete(id, exe.map_info.map_id as u32)?;
            }
        }
        Ok(())
    }

    pub fn get_or_insert(
        &mut self,
        probes: &mut Probes,
        elf: &FileInfo,
        map: &ProcessMapsEntry,
        bias: u64,
    ) -> Result<Option<&mut Executable>> {
        let file_id = elf.file_id;
        // 1. check erros
        if self.errors.contains(&file_id) {
            return Ok(None);
        }
        if !self.executables.contains_key(&file_id) {
            // 4. not found, create
            // a. extract elf
            // b. load deltas, return mapref
            let mut ebpf_deltas = vec![];

            let deltas = match ElfFile::parse_eh_frame(&elf.file) {
                Ok(deltas) => deltas,
                Err(e) => {
                    bail!("internal error: {e}")
                }
            };
            if deltas.is_empty() {
                self.errors.insert(elf.file_id);
                bail!("no eh_frame")
            }

            let first_page = deltas[0].addr >> STACK_DELTA_PAGE_BITS;
            let first_page_addr = deltas[0].addr & !(STACK_DELTA_PAGE_MASK as u64);
            let last_page = deltas.last().unwrap().addr >> STACK_DELTA_PAGE_BITS;
            let num_pages = last_page - first_page + 1;
            let mut num_deltas_per_page = vec![0; num_pages as usize];

            // TODO: 可以进行合并，降低unwindinfo的使用量
            for (_i, delta) in deltas.iter().enumerate() {
                let unwind_info_idx = probes.get_unwind_info_index(&delta.info)?;

                ebpf_deltas.push(StackDelta::new(delta.addr as u16, unwind_info_idx));

                num_deltas_per_page
                    [((delta.addr >> STACK_DELTA_PAGE_BITS) - first_page) as usize] += 1;
            }

            let map_id = probes.stack_delta_map.update(elf.file_id, ebpf_deltas)?;
            log::debug!("update deltas into stack_delta_page_map");
            probes.stack_delta_page_map.update(
                elf.file_id,
                &num_deltas_per_page,
                map_id as u16,
                first_page_addr,
            )?;

            let exe = Executable {
                rc: 0,
                map_info: LoadedDelta {
                    map_id: map_id as u16,
                    num_page: num_pages as u32,
                    start_page: first_page_addr,
                },
                tsd_info: map
                    .path
                    .as_ref()
                    .map(|x| {
                        if !is_potential_tsd_dso(x) {
                            None
                        } else {
                            let mmap_ref = unsafe { memmap2::Mmap::map(&elf.file).unwrap() };
                            let object =
                                object::File::parse(&*mmap_ref).expect("failed to parse elf file");
                            match extract_tsd_info(&object) {
                                Ok(info) => Some(info),
                                Err(e) => {
                                    log::error!("failed to extract tsd info: {e}");
                                    None
                                }
                            }
                        }
                    })
                    .flatten(),
                i_info: if let Some(p) = &map.path {
                    let mmap_ref = unsafe { memmap2::Mmap::map(&elf.file)? };
                    let object = object::File::parse(&*mmap_ref).expect("failed to parse elf file");
                    IFileInfo::parse(p.as_str(), &object, file_id, bias, probes)
                    // PythonData::new(file_name, elf, id, bias, probes);
                } else {
                    None
                },
            };

            self.executables.insert(file_id, exe);
        }

        let exe = self.executables.get_mut(&file_id).unwrap();
        exe.rc += 1;
        return Ok(Some(exe));
    }
}
