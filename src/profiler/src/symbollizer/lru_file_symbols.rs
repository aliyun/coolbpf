use super::elf::ElfSymbol;
use super::file_id::FileId64;
use crate::symbollizer::elf::ElfFile;
use anyhow::bail;
use anyhow::Result;
use schnellru::ByMemoryUsage;
use schnellru::LruMap;
use std::collections::HashMap;
use std::fs::File;
use std::ops::Deref;
use std::ops::DerefMut;

#[derive(Debug)]
pub struct LruFileSymbols {
    symbols: LruMap<FileId64, Vec<ElfSymbol>, ByMemoryUsage>,
    path: HashMap<FileId64, String>,
}

impl Deref for LruFileSymbols {
    type Target = LruMap<FileId64, Vec<ElfSymbol>, ByMemoryUsage>;

    fn deref(&self) -> &Self::Target {
        &self.symbols
    }
}

impl DerefMut for LruFileSymbols {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.symbols
    }
}

impl LruFileSymbols {
    pub fn new() -> Self {
        LruFileSymbols {
            symbols: LruMap::with_memory_budget(100 * 1024 * 1024),
            path: HashMap::new(),
        }
    }

    pub fn record_file_path(&mut self, file_id: FileId64, path: String) {
        self.path.insert(file_id, path);
    }

    pub fn add_symbols(&mut self, file_id: FileId64, syms: Vec<ElfSymbol>) {
        self.symbols.insert(file_id, syms);
    }

    pub fn symbolize(&mut self, file_id: FileId64, addr: u64) -> ElfSymbol {
        match self
            .symbols
            .get_or_insert_fallible(file_id, || -> Result<Vec<ElfSymbol>> {
                if let Some(path) = self.path.get(&file_id) {
                    let mut syms = vec![];
                    let file = File::open(path)?;
                    let mmap_ref = unsafe { memmap2::Mmap::map(&file)? };
                    let object = object::File::parse(&*mmap_ref).expect("failed to parse elf file");
                    ElfFile::parse_symbols2(object, &mut syms);
                    return Ok(syms);
                }
                bail!("internal bug: ID-{:?} file path not found", file_id)
            }) {
            Ok(Some(syms)) => binary_find_symbol(syms, addr),
            Ok(None) | Err(_) => ElfSymbol::not_found(addr),
        }
    }

    pub fn symbolize_with_path(&mut self, file_id: FileId64, addr: u64, path: &str) -> ElfSymbol {
        match self
            .symbols
            .get_or_insert_fallible(file_id, || -> Result<Vec<ElfSymbol>> {
                let path = self.path.entry(file_id).or_insert(path.to_string());
                let mut syms = vec![];
                let file = File::open(path)?;
                let mmap_ref = unsafe { memmap2::Mmap::map(&file)? };
                let object = object::File::parse(&*mmap_ref).expect("failed to parse elf file");
                ElfFile::parse_symbols2(object, &mut syms);
                return Ok(syms);
            }) {
            Ok(Some(syms)) => binary_find_symbol(syms, addr),
            Ok(None) | Err(_) => ElfSymbol::not_found(addr),
        }
    }
}

fn binary_find_symbol(syms: &Vec<ElfSymbol>, addr: u64) -> ElfSymbol {
    match syms.binary_search_by(|x| x.start.cmp(&addr)) {
        Ok(x) => syms[x].clone(),
        Err(x) => {
            if x == 0 {
                ElfSymbol::not_found(addr)
            } else {
                syms[x - 1].clone()
            }
        }
    }
}
