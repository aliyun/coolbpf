use super::elf::ElfSymbol;
use super::file_id::FileId64;
use crate::symbollizer::elf::ElfFile;
use crate::SYMBOL_FILE_MAX_SIZE;
use anyhow::bail;
use anyhow::Result;
use clru::CLruCache;
use clru::CLruCacheConfig;
use clru::WeightScale;
use std::collections::HashMap;
use std::fs::File;
use std::hash::RandomState;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::atomic::Ordering;

#[derive(Debug)]
struct WeightSymbols {
    symbols: Vec<ElfSymbol>,
    weight: usize,
}

impl WeightSymbols {
    pub fn new(symbols: Vec<ElfSymbol>) -> Self {
        let weight: usize = symbols.iter().map(|x| x.name.len() + 16).sum();
        WeightSymbols {
            symbols,
            weight: weight + 16,
        }
    }
}

#[derive(Debug)]
struct CustomScale;

impl WeightScale<FileId64, WeightSymbols> for CustomScale {
    fn weight(&self, _key: &FileId64, value: &WeightSymbols) -> usize {
        value.weight
    }
}

#[derive(Debug)]
pub struct LruFileSymbols {
    symbols: CLruCache<FileId64, WeightSymbols, RandomState, CustomScale>,
    path: HashMap<FileId64, String>,
    max_sz: usize,
    max_weight: usize,
}

// in mb
fn symbols_cache_usage() -> u32 {
    match std::env::var("LIVETRACE_SYMBOLS_CACHE_MB") {
        Ok(value) => {
            let period = match u32::from_str(&value) {
                Ok(num) => num,
                Err(_) => 100,
            };
            period
        }
        Err(_) => 100,
    }
}

impl LruFileSymbols {
    pub fn new() -> Self {
        let bytes = symbols_cache_usage() * 1024 * 1024;
        let cache = CLruCache::with_config(
            CLruCacheConfig::new(NonZeroUsize::new(bytes as usize).unwrap())
                .with_scale(CustomScale),
        );
        LruFileSymbols {
            symbols: cache,
            path: HashMap::new(),
            max_sz: SYMBOL_FILE_MAX_SIZE.load(Ordering::SeqCst) as usize,
            max_weight: bytes as usize,
        }
    }

    pub fn record_file_path(&mut self, file_id: FileId64, path: String) {
        self.path.insert(file_id, path);
    }

    pub fn contains(&self, file_id: FileId64) -> bool {
        self.symbols.contains(&file_id)
    }

    pub fn add_symbols(&mut self, file_id: FileId64, syms: Vec<ElfSymbol>) {
        let wsyms = WeightSymbols::new(syms);
        match self.symbols.put_with_weight(file_id, wsyms) {
            Ok(_) => {}
            Err(e) => {
                log::error!("add symbols failed, weight = {}", e.1.weight);
            }
        }
    }

    fn __symbolize(
        &mut self,
        file_id: FileId64,
        addr: u64,
        path: Option<&String>,
    ) -> Result<ElfSymbol> {
        match self.symbols.get(&file_id) {
            Some(wsyms) => Ok(binary_find_symbol(&wsyms.symbols, addr)),
            None => {
                let opath = path.or_else(|| self.path.get(&file_id));
                if let Some(path) = opath {
                    let mut syms = vec![];
                    let file = File::open(path)?;
                    let mmap_ref = unsafe { memmap2::Mmap::map(&file)? };
                    let object = object::File::parse(&*mmap_ref).expect("failed to parse elf file");
                    ElfFile::parse_symbols2(object, &mut syms);
                    let sym = binary_find_symbol(&syms, addr);
                    let wsyms = WeightSymbols::new(syms);
                    log::debug!(
                        "cache file symbols for {}, weight: {}, symbols len: {}",
                        path,
                        wsyms.weight,
                        wsyms.symbols.len()
                    );
                    if wsyms.weight > self.max_sz || wsyms.weight > self.max_weight {
                        log::warn!(
                            "file symbols weight too large: {}, depreceated it",
                            wsyms.weight
                        );
                        let new_wsyms = WeightSymbols::new(vec![]);
                        self.symbols.put_with_weight(file_id, new_wsyms).unwrap();
                    } else {
                        self.symbols.put_with_weight(file_id, wsyms).unwrap();
                    }

                    return Ok(sym);
                }
                bail!("internal bug: ID-{:?} file path not found", file_id)
            }
        }
    }

    pub fn symbolize(&mut self, file_id: FileId64, addr: u64) -> ElfSymbol {
        match self.__symbolize(file_id, addr, None) {
            Ok(sym) => sym,
            Err(_) => ElfSymbol::not_found(addr),
        }
    }

    pub fn symbolize_with_path(
        &mut self,
        file_id: FileId64,
        addr: u64,
        path: &String,
    ) -> ElfSymbol {
        match self.__symbolize(file_id, addr, Some(path)) {
            Ok(sym) => sym,
            Err(_) => ElfSymbol::not_found(addr),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_symbols_weight() {
        let mut symer = LruFileSymbols::new();
        let sym = ElfSymbol {
            name: std::iter::repeat('1').take(1024).collect(),
            start: 0,
            end: 0,
        };

        // 1k * 1024000 = 1000M
        for i in 0..1024000 {
            symer.add_symbols(FileId64(i), vec![sym.clone()]);
        }

        println!("{}", symer.symbols.weight());

        std::thread::sleep(std::time::Duration::from_secs(1024));
    }
}
