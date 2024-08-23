use anyhow::Result;
use blazesym::helper::ElfResolver;

pub struct SymbolFile {
    file_id: u128,
    elf: ElfResolver,
}

impl SymbolFile {
    pub fn new(path: &str) -> Result<Self> {
        let elf = ElfResolver::open(path)?;
        // SymbolFile {}
        todo!()
    }

    pub fn build_id(&self) -> u64 {
        0
    }

    pub fn address_mapper(&self) {}
}
