use anyhow::bail;
use anyhow::Result;
use lru::LruCache;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::Range;

use crate::process::maps::ProcessMaps;
use crate::MAX_NUM_OF_PROCESSES;

use super::elf::ElfFile;
use super::elf::ElfSymbol;
use super::file_cache::FileInfo;
use super::file_id::FileId;
use super::file_id::FileId64;

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, Default)]
struct ProcSymbol {
    bias: u64,
    pc: Range<u64>,
    syms: FileSymbol,
}

#[derive(Debug, Default)]
struct ProcInfo {
    syms: Vec<ProcSymbol>,
    comm: String,
}

#[derive(Debug)]
pub struct Symbolizer {
    pub bias_cache: HashMap<FileId64, u64>,

    symbols: Vec<ElfSymbol>,

    // pid <-> (pc, sym)
    procs: LruCache<u32, ProcInfo>,
    //
    files: HashMap<FileId64, FileSymbol>,
    kernel: FileSymbol,
}

impl Symbolizer {
    pub fn new() -> Self {
        let symer = Symbolizer {
            bias_cache: HashMap::default(),
            symbols: Vec::new(),
            procs: LruCache::new(NonZeroUsize::new(MAX_NUM_OF_PROCESSES).unwrap()),
            files: HashMap::default(),
            kernel: FileSymbol::default(),
        };
        symer
    }

    pub fn add_file(&mut self, file_id: FileId64, file: object::File) {
        let start = self.symbols.len();
        ElfFile::parse_symbols2(file, &mut self.symbols);
        let end = self.symbols.len();

        let fsym = FileSymbol(start..end);
        self.files.insert(file_id, fsym);
    }

    fn __sort_symbols(&mut self, s: usize, e: usize) {
        self.symbols[s..e].sort_by_key(|x| x.start);
    }

    fn __find_symbol(&self, s: usize, e: usize, addr: u64) -> &ElfSymbol {
        match self.symbols[s..e].binary_search_by(|x| x.start.cmp(&addr)) {
            Ok(x) => &self.symbols[s + x],
            Err(x) => &self.symbols[s + x - 1],
        }
    }

    pub fn add_kernel(&mut self, path: &str) {
        let start = self.symbols.len();
        let file = File::open(path).unwrap();
        let lines = io::BufReader::new(file).lines();
        for line in lines {
            if let Ok(l) = line {
                let parts = l.trim().split_whitespace().collect::<Vec<&str>>();
                if parts[1].contains("T") || parts[1].contains("t") {
                    let addr = u64::from_str_radix(parts[0], 16).unwrap();
                    let sym = parts[2].to_string();
                    self.symbols.push(ElfSymbol {
                        name: sym,
                        start: addr,
                        end: 0,
                    });
                }
            }
        }
        let end = self.symbols.len();
        self.__sort_symbols(start, end);
        self.kernel = FileSymbol(start..end);
    }

    fn get_or_insert_proc(&mut self, pid: u32) -> Result<&ProcInfo> {
        self.procs.try_get_or_insert(pid, || -> Result<ProcInfo> {
            let mut psyms = vec![];
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

                let info = FileInfo::from_path(path.as_str())?;
                let id = info.file_id;
                let fsym = self.files.entry(id).or_insert_with(|| {
                    let start = self.symbols.len();
                    ElfFile::parse_symbols2(info.elf.object_file(), &mut self.symbols);
                    let end = self.symbols.len();
                    let fsym = FileSymbol(start..end);
                    fsym
                });

                psyms.push(ProcSymbol {
                    bias: map.start - info.file_offset_to_virtual_address(map.offset).unwrap(),
                    syms: fsym.clone(),
                    pc: map.start..map.end,
                });
            }
            psyms.sort_by_key(|x| x.pc.start);
            let mut comm = read_to_string(format!("/proc/{pid}/comm"))?;
            comm.pop();
            Ok(ProcInfo { comm, syms: psyms })
        })
    }

    pub fn proc_symbolize(&mut self, pid: u32, addrs: &Vec<u64>) -> Result<Vec<Symbol>> {
        let mut syms = Vec::with_capacity(addrs.len());
        let mut slices = Vec::with_capacity(addrs.len());
        match self.get_or_insert_proc(pid) {
            Ok(pi) => {
                for &addr in addrs {
                    match pi.syms.binary_search_by(|a| {
                        if a.pc.contains(&addr) {
                            Ordering::Equal
                        } else if a.pc.start > addr {
                            Ordering::Greater
                        } else {
                            Ordering::Less
                        }
                    }) {
                        Ok(x) => {
                            let psym = &pi.syms[x];
                            let start = psym.syms.start;
                            let end = psym.syms.end;
                            slices.push((start, end, addr - psym.bias));
                        }
                        Err(_e) => {
                            slices.push((usize::MAX, 0, addr));
                        }
                    }
                }
            }
            Err(e) => {
                bail!("failed to get procinfo: {pid}, error: {e}")
            }
        }

        for (s, e, a) in slices {
            let sym = if s == usize::MAX {
                Symbol::new(format!("!{:x}", a))
            } else {
                let elf_sym = self.__find_symbol(s, e, a);
                Symbol::new(elf_sym.name.clone())
            };
            syms.push(sym);
        }
        Ok(syms)
    }

    pub fn proc_comm(&mut self, pid: u32) -> Result<&String> {
        self.procs
            .try_get_or_insert(pid, || -> Result<ProcInfo> {
                let mut comm = read_to_string(format!("/proc/{pid}/comm"))?;
                comm.pop();
                Ok(ProcInfo { comm, syms: vec![] })
            })
            .map(|x| &x.comm)
    }

    pub fn fileid_symbolize(&self, fileid: &FileId64, addr: u64) -> Symbol {
        let fsym = self.files.get(fileid).unwrap();
        let sym = self.__find_symbol(fsym.start, fsym.end, addr);
        Symbol::new(sym.name.clone())
    }

    pub fn kernel_symbolize(&self, addrs: &Vec<u64>) -> Vec<Symbol> {
        let mut syms = Vec::with_capacity(addrs.len());
        let s = self.kernel.start;
        let e = self.kernel.end;
        for &addr in addrs {
            let sym = self.__find_symbol(s, e, addr);
            syms.push(Symbol::new(sym.name.clone()));
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
        for sym in symer.symbols.iter() {
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
        symer.add_file(id, elf);

        let mut prev = 0;
        for sym in symer.symbols.iter() {
            assert!(sym.start >= prev, "prev: {:x}, now: {:x}", prev, sym.start);
            prev = sym.start;
        }

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
        let syms = symer
            .proc_symbolize(pid as u32, &vec![func_addr, func_addr + 1])
            .unwrap();
        let name = Name::from(&syms[0].name);
        let name = name.try_demangle(DemangleOptions::complete());
        assert!(name.contains("do_nothing_func"));
        let name = Name::from(&syms[1].name);
        assert!(name
            .try_demangle(DemangleOptions::complete())
            .contains("do_nothing_func"));
    }
}
