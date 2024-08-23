use anyhow::Result;
use memmap2::Mmap;
use std::fs::File;

pub struct OpenedFile {
    file: File,
    mmap_ref: Mmap,
}

impl OpenedFile {
    pub fn new(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mmap_ref = unsafe { memmap2::Mmap::map(&file)? };

        Ok(Self { mmap_ref, file })
    }

    pub fn object_file(&self) -> object::File {
        object::File::parse(&*self.mmap_ref).expect("failed to parse elf file")
    }
}
