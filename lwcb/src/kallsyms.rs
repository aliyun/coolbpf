use anyhow::{bail, Result};
use lazy_static::lazy_static;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufRead},
    sync::Mutex,
};

lazy_static! {
    pub static ref GLOBAL_KALLSYMS: Kallsyms = {
        let ksyms = Kallsyms::try_from("/proc/kallsyms").unwrap();
        ksyms
    };
}

#[derive(Debug, Default)]
pub struct Kallsyms {
    syms: Vec<(String, u64)>,
    hs: HashSet<String>,
}

impl TryFrom<&str> for Kallsyms {
    type Error = anyhow::Error;
    fn try_from(path: &str) -> Result<Self> {
        let mut ksyms = Kallsyms::new();
        let file = File::open(path)?;
        let lines = io::BufReader::new(file).lines();
        for line in lines {
            if let Ok(l) = line {
                let mut iter = l.trim().split_whitespace();
                if let Some(x) = iter.next() {
                    iter.next();
                    if let Some(y) = iter.next() {
                        ksyms.insert(y.to_string(), u64::from_str_radix(x, 16)?);
                    }
                }
            }
        }
        ksyms.sort();
        log::debug!(
            "Load ksyms done from {:?}, symbols length: {}",
            path,
            ksyms.get_ksyms_num()
        );
        Ok(ksyms)
    }
}

impl Kallsyms {
    pub fn new() -> Self {
        Kallsyms {
            syms: Vec::new(),
            hs: HashSet::default(),
        }
    }

    fn insert(&mut self, sym_name: String, sym_addr: u64) {
        self.syms.push((sym_name.clone(), sym_addr));
        self.hs.insert(sym_name);
    }

    fn get_ksyms_num(&self) -> usize {
        self.syms.len()
    }

    fn sort(&mut self) {
        self.syms.sort_by(|a, b| a.1.cmp(&b.1));
    }

    pub fn has_sym(&self, sym_name: &str) -> bool {
        self.hs.contains(sym_name)
    }

    pub fn symbol(&self, addr: u64) -> String {
        let mut start = 0;
        let mut end = self.syms.len() - 1;
        let mut mid;
        let mut sym_addr;

        while start < end {
            mid = start + (end - start + 1) / 2;
            sym_addr = self.syms[mid].1;

            if sym_addr <= addr {
                start = mid;
            } else {
                end = mid - 1;
            }
        }

        if start == end && self.syms[start].1 <= addr {
            let mut name = self.syms[start].0.clone();
            return name;
        }

        return String::from("Not Found");
    }

    pub fn addr_to_sym(&self, addr: u64) -> String {
        let mut start = 0;
        let mut end = self.syms.len() - 1;
        let mut mid;
        let mut sym_addr;

        while start < end {
            mid = start + (end - start + 1) / 2;
            sym_addr = self.syms[mid].1;

            if sym_addr <= addr {
                start = mid;
            } else {
                end = mid - 1;
            }
        }

        if start == end && self.syms[start].1 <= addr {
            let mut name = self.syms[start].0.clone();
            name.push_str(&format!("+{}", addr - self.syms[start].1));
            return name;
        }

        return String::from("Not Found");
    }
}
