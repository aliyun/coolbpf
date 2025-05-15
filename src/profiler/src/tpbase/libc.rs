/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
// Rewrite with gpt

use anyhow::bail;
use anyhow::Result;
use object::ObjectSymbol;
use regex::Regex;

use crate::probes::types::bpf;
use crate::symbollizer::elf::ElfFile;

use super::libc_decode::extract_tsd_info_native;

/// Determines if the DSO filename potentially contains pthread code
pub fn is_potential_tsd_dso(filename: &str) -> bool {
    let libc_regex: Regex = Regex::new(r".*/(ld-musl|libpthread)([-.].*)?\.so").unwrap();
    libc_regex.is_match(filename)
}

pub fn extract_tsd_info(elf: &object::File) -> Result<bpf::TSDInfo> {
    let symtab = match ElfFile::lookup_symbol(elf, "__pthread_getspecific") {
        Ok(sym) => sym,
        Err(_) => ElfFile::lookup_symbol(elf, "pthread_getspecific")?,
    };

    if symtab.size() < 8 {
        bail!("getspecific function size is {}", symtab.size())
    }

    let code = ElfFile::read_at(elf, symtab.address(), symtab.size() as usize)?;

    let info = extract_tsd_info_native(&code)?;

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::extract_tsd_info;
    use super::ElfFile;

    #[test]
    fn test_parse_elf2() {
        // llvm-dwarfdump --eh-frame /usr/lib64/ld-2.32.so
        let mut elf = ElfFile::new("/lib64/libpthread-2.32.so").unwrap();
        let file = elf.object_file();
        extract_tsd_info(&file).unwrap();
    }
}
