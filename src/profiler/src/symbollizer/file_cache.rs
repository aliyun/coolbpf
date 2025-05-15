use super::elf::ElfFile;
use super::file_id::FileId;
use super::file_id::FileId64;
use crate::process::maps::DiskFileKey;
use crate::process::maps::ProcessMapsEntry;
use anyhow::Result;
use lru::LruCache;
use read_process_memory::copy_address;
use read_process_memory::Pid;
use read_process_memory::ProcessHandle;
use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::SystemTime;
#[derive(Debug)]
pub struct ProgramAddress {
    pub offset: u64,
    pub vaddr: u64,
    pub filezs: u64,
}

#[derive(Debug)]
pub struct FileInfo {
    pub file: File,
    pub last_modified: SystemTime,
    pub file_id: FileId64,
    pub pas: Vec<ProgramAddress>,
}

impl FileInfo {
    pub fn new(file: File, last_modified: SystemTime, file_id: FileId64) -> Result<Self> {
        Ok(Self {
            last_modified,
            file_id,
            pas: ElfFile::parse_ph(&file)?,
            file,
        })
    }

    pub fn file_offset_to_virtual_address(&self, offset: u64) -> Option<u64> {
        log::debug!("{:x?}", self.pas);
        for p in &self.pas {
            let aligned_offset = p.offset & (!4095);
            if offset >= aligned_offset && offset < p.offset + p.filezs {
                return Some(p.vaddr - (p.offset - offset));
            }
        }

        None
    }

    pub fn from_path(path: &str) -> Result<Self> {
        let mut file = File::open(&path)?;
        let file_id = FileId64::from(&FileId::try_from_file(&mut file)?);
        let modified = file.metadata()?.modified()?;
        FileInfo::new(file, modified, file_id)
    }
}

pub struct FileCache {
    cache: LruCache<DiskFileKey, FileInfo>,
}

impl Deref for FileCache {
    type Target = LruCache<DiskFileKey, FileInfo>;

    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

impl DerefMut for FileCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cache
    }
}

impl FileCache {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
        }
    }

    pub fn get_or_insert(&mut self, pid: u32, map: &ProcessMapsEntry) -> Result<&FileInfo> {
        let key = map.disk_file_key();

        self.cache.try_get_or_insert(key, || -> Result<FileInfo> {
            let path = map.file_path(pid);
            let mut file = if map.is_vdso() {
                let handle: ProcessHandle = (pid as Pid).try_into()?;
                let data =
                    copy_address(map.start as usize, (map.end - map.start) as usize, &handle)?;
                let mut file = tempfile::tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            } else {
                File::open(&path)?
            };
            let last_modified = {
                if path.is_empty() {
                    SystemTime::UNIX_EPOCH
                } else {
                    file.metadata()?.modified()?
                }
            };
            let fd = FileId64::from(&FileId::try_from_file(&mut file)?);
            let new_info = FileInfo::new(file, last_modified, fd)?;
            Ok(new_info)
        })
    }
}
