use super::elf::ElfSymbol;
use super::file_cache::FileInfo;
use super::file_id::FileId64;
use super::lru_file_symbols::LruFileSymbols;
use crate::process::maps::ProcessMaps;
use anyhow::Result;
use lru::LruCache;
use std::cmp::Ordering;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ops::Range;

#[derive(Debug)]
pub struct ProcessFileInfo {
    pub file_id: FileId64,
    pub path: String,
    pub bias: u64,
    pc: Range<u64>,
}

#[derive(Debug)]
pub struct ProcessFiles {
    files: Vec<ProcessFileInfo>,
}

impl ProcessFiles {
    pub fn new(pid: u32) -> Result<Self> {
        log::debug!("Loading process files for pid {}", pid);
        let mut files = vec![];
        let maps = ProcessMaps::new(pid)?;
        for (_addr, map) in maps.iter() {
            if (map.inode == 0 && !map.is_vdso()) || !map.is_executable() {
                continue;
            }

            let path = map.file_path(pid);
            if path.is_empty() {
                // TODO: handle vdso
                continue;
            }

            let info = match FileInfo::from_path(path.as_str()) {
                Ok(x) => x,
                Err(e) => {
                    log::warn!("failed to get file info: {e}");
                    continue;
                }
            };
            let voff = match info.file_offset_to_virtual_address(map.offset) {
                Some(x) => x,
                None => continue,
            };

            files.push(ProcessFileInfo {
                file_id: info.file_id,
                path: path.to_owned(),
                bias: map.start - voff,
                pc: map.start..map.end,
            });
        }

        files.sort_by_key(|x| x.pc.start);
        Ok(ProcessFiles { files })
    }

    pub fn symbolize(&self, lru_files: &mut LruFileSymbols, addrs: &Vec<u64>) -> Vec<ElfSymbol> {
        let mut syms = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            let sym = match self.files.binary_search_by(|a| {
                if a.pc.contains(&addr) {
                    Ordering::Equal
                } else if a.pc.start > addr {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }) {
                Ok(x) => lru_files.symbolize_with_path(
                    self.files[x].file_id,
                    addr - self.files[x].bias,
                    &self.files[x].path,
                ),
                Err(_) => ElfSymbol::not_found(addr),
            };
            syms.push(sym);
        }
        syms
    }

    pub fn cache(&self, lru_files: &mut LruFileSymbols) {
        for file in &self.files {
            let _ = lru_files.symbolize_with_path(file.file_id, 0, &file.path);
        }
    }
}

#[derive(Debug)]
pub struct LruProcessFiles {
    pub(crate) lru: LruCache<u32, ProcessFiles>,
}

impl LruProcessFiles {
    pub fn new() -> Self {
        let cpus = num_cpus::get();
        LruProcessFiles {
            // 128B * 100(share library) * 1024 => 12MB for one cpu
            lru: LruCache::new(NonZeroUsize::new(cpus * 32).unwrap()),
        }
    }

    pub fn symbolize(
        &mut self,
        pid: u32,
        lru_files: &mut LruFileSymbols,
        addrs: &Vec<u64>,
    ) -> Vec<ElfSymbol> {
        match self
            .lru
            .try_get_or_insert(pid, || -> Result<ProcessFiles> { ProcessFiles::new(pid) })
        {
            Ok(pf) => pf.symbolize(lru_files, addrs),
            Err(e) => {
                log::warn!("failed to add process files for pid {pid}: {e}");
                let mut syms = Vec::with_capacity(addrs.len());
                for &addr in addrs {
                    syms.push(ElfSymbol::not_found(addr));
                }
                syms
            }
        }
    }

    pub fn cache(&mut self, pid: u32, lru_files: &mut LruFileSymbols) {
        match self
            .lru
            .try_get_or_insert(pid, || -> Result<ProcessFiles> { ProcessFiles::new(pid) })
        {
            Ok(pf) => pf.cache(lru_files),
            Err(e) => {
                log::warn!("failed to add process files for pid {pid}: {e}");
            }
        }
    }
}

impl Deref for LruProcessFiles {
    type Target = LruCache<u32, ProcessFiles>;

    fn deref(&self) -> &Self::Target {
        &self.lru
    }
}

impl DerefMut for LruProcessFiles {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.lru
    }
}
