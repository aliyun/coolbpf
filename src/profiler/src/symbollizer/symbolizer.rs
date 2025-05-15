use crate::is_enable_cpuno;
use crate::is_enable_function_offset;
use crate::process::maps::ProcessMaps;
use crate::MAX_NUM_OF_PROCESSES;
use anyhow::bail;
use anyhow::Result;
use lru::LruCache;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::Range;

use super::elf::ElfFile;
use super::elf::ElfSymbol;
use super::file_cache::FileInfo;
use super::file_id::FileId;
use super::file_id::FileId64;
use super::lru_file_symbols::LruFileSymbols;
use super::lru_process_files::LruProcessFiles;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Symbol {
    pub name: String,
}

impl Symbol {
    pub fn unknown() -> Self {
        Symbol {
            name: "unknown".to_owned(),
        }
    }

    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FileSymbol(Range<usize>);

impl Deref for FileSymbol {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct Symbolizer {
    pub bias_cache: HashMap<FileId64, u64>,

    // pid <-> comm
    procs: LruCache<u32, String>,
    file_symbols: LruFileSymbols,
    proc_files: LruProcessFiles,
    //
    kernel: Vec<ElfSymbol>,
    adb_regex: Option<Regex>,

    pub need_cpu: bool,
    pub need_function_offset: bool,
}

impl Symbolizer {
    pub fn new() -> Self {
        let symer = Symbolizer {
            bias_cache: HashMap::default(),
            procs: LruCache::new(NonZeroUsize::new(MAX_NUM_OF_PROCESSES).unwrap()),
            file_symbols: LruFileSymbols::new(),
            proc_files: LruProcessFiles::new(),
            kernel: vec![],
            adb_regex: std::env::var("ADB_CMDLINE_REGEX")
                .map_or(None, |x| Some(Regex::new(&x).unwrap())),
            need_cpu: is_enable_cpuno(),
            need_function_offset: is_enable_function_offset(),
        };
        symer
    }

    pub fn bias_by_fileid(&self, id: &FileId64) -> Option<&u64> {
        self.bias_cache.get(id)
    }

    pub fn add_parsed_file(&mut self, file_id: FileId64, file: object::File, path: String) {
        if path.is_empty() {
            return;
        }

        if self.file_symbols.contains(file_id) {
            return;
        }

        let mut symbols = vec![];
        ElfFile::parse_symbols2(file, &mut symbols);
        self.file_symbols.add_symbols(file_id, symbols);
        self.file_symbols.record_file_path(file_id, path);
    }

    pub fn add_kernel(&mut self, path: &str) {
        let file = File::open(path).unwrap();
        let lines = io::BufReader::new(file).lines();
        for line in lines {
            if let Ok(l) = line {
                let parts = l.trim().split_whitespace().collect::<Vec<&str>>();
                if parts[1].contains("T") || parts[1].contains("t") {
                    let addr = u64::from_str_radix(parts[0], 16).unwrap();
                    let sym = parts[2].to_string();
                    self.kernel.push(ElfSymbol {
                        name: sym,
                        start: addr,
                        end: 0,
                    });
                }
            }
        }
        self.kernel.sort_by_key(|x| x.start);
    }

    pub fn proc_comm(&mut self, pid: u32) -> Result<&String> {
        let get_comm = || {
            let mut comm = read_to_string(format!("/proc/{pid}/comm"))?;
            comm.pop();
            Ok(comm)
        };

        self.procs
            .try_get_or_insert(pid, || -> Result<String> {
                let comm = if let Some(reg) = &self.adb_regex {
                    let cmdline = read_to_string(format!("/proc/{pid}/cmdline"))?;
                    reg.find(&cmdline)
                        .map_or_else(|| get_comm(), |x| Ok(x.as_str().to_owned()))
                } else {
                    get_comm()
                };
                comm
            })
            .map(|x| x)
    }

    pub fn proc_symbolize(&mut self, pid: u32, addrs: &Vec<u64>) -> Vec<Symbol> {
        let mut syms = Vec::with_capacity(addrs.len());
        for sym in self
            .proc_files
            .symbolize(pid, &mut self.file_symbols, addrs)
        {
            syms.push(Symbol::new(sym.name.clone()));
        }
        syms
    }

    pub fn fileid_symbolize(&mut self, fileid: &FileId64, addr: u64) -> Symbol {
        let sym = self.file_symbols.symbolize(*fileid, addr);
        Symbol::new(sym.name.clone())
    }

    pub fn kernel_symbolize(&self, addrs: &Vec<u64>) -> Vec<Symbol> {
        let mut syms = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            let sym = match self.kernel.binary_search_by(|x| x.start.cmp(&addr)) {
                Ok(x) => &self.kernel[x],
                Err(x) => &self.kernel[x - 1],
            };
            syms.push(Symbol::new(sym.name.clone()));
        }
        syms
    }

    pub fn kernel_symbolize_with_offset(&self, addrs: &Vec<u64>) -> Vec<Symbol> {
        let mut syms = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            let (sym, offset) = match self.kernel.binary_search_by(|x| x.start.cmp(&addr)) {
                Ok(x) => (&self.kernel[x], addr - self.kernel[x].start),
                Err(x) => (&self.kernel[x - 1], addr - self.kernel[x - 1].start),
            };
            syms.push(Symbol::new(format!("{}+0x{:x}", sym.name, offset)));
        }
        syms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbolic_common::Name;
    use symbolic_demangle::Demangle;
    use symbolic_demangle::DemangleOptions;

    #[test]
    fn test_kernel_symbolize() {
        let mut symer = Symbolizer::new();
        symer.add_kernel("tests/data/kallsyms");

        let mut prev = 0;
        for sym in symer.kernel.iter() {
            assert!(sym.start >= prev, "prev: {:x}, now: {:x}", prev, sym.start);
            prev = sym.start;
        }

        let addr = 0xffffffff9f979500u64 + 24;
        assert_eq!(
            symer.kernel_symbolize(&vec![addr])[0],
            Symbol::new("tcp_sendmsg".to_string())
        );
    }

    #[test]
    fn test_file_symbolize() {
        let mut symer = Symbolizer::new();
        let mut file = File::open("tests/data/ld-2.32.so").unwrap();

        let id = FileId::try_from_reader(&mut file).unwrap();
        let id = FileId64::from(&id);
        let mmap_ref = unsafe { memmap2::Mmap::map(&file).unwrap() };
        let elf = object::File::parse(&*mmap_ref).unwrap();

        symer.add_parsed_file(id, elf, "tests/data/ld-2.32.so".to_owned());

        assert_eq!(
            symer.fileid_symbolize(&id, 0x18780),
            Symbol::new("_dl_next_tls_modid".to_owned())
        );
        assert_eq!(
            symer.fileid_symbolize(&id, 0x18780 + 1),
            Symbol::new("_dl_next_tls_modid".to_owned())
        );
        assert_eq!(
            symer.fileid_symbolize(&id, 0x18780 + 2),
            Symbol::new("_dl_next_tls_modid".to_owned())
        );
    }

    #[inline(never)]
    fn do_nothing_func() {}
    #[test]
    fn test_proc_symbolize() {
        let mut symer = Symbolizer::new();
        let pid = unsafe { libc::getpid() };

        let func_addr = do_nothing_func as *const () as u64;
        let syms = symer.proc_symbolize(pid as u32, &vec![func_addr, func_addr + 1]);
        let name = Name::from(&syms[0].name);
        let name = name.try_demangle(DemangleOptions::complete());
        assert!(name.contains("do_nothing_func"));
        let name = Name::from(&syms[1].name);
        assert!(name
            .try_demangle(DemangleOptions::complete())
            .contains("do_nothing_func"));
    }
}
