/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::ops::Deref;
use std::path::Path;

use anyhow::Result;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use sha2::Digest;
use sha2::Sha256;

#[derive(Debug, Clone, Copy)]
pub struct FileId {
    pub hi: u64,
    pub lo: u64,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct FileId64(pub u64);

impl From<&FileId> for FileId64 {
    fn from(value: &FileId) -> Self {
        FileId64(value.hi)
    }
}

impl Into<u64> for FileId64 {
    fn into(self) -> u64 {
        self.0
    }
}

impl Deref for FileId64 {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FileId {
    pub fn try_from_reader<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let mut h = Sha256::new();

        // 读取并哈希头4KiB
        let mut buffer = [0; 4096];
        reader.read_exact(&mut buffer)?;
        h.update(&buffer);

        // 获取文件大小并定位到末尾
        let size = reader.seek(SeekFrom::End(0))? as usize;
        reader.seek(SeekFrom::Start(size.saturating_sub(4096) as u64))?;

        // 读取并哈希尾部4KiB
        reader.read_exact(&mut buffer)?;
        h.update(&buffer);

        // 哈希文件长度
        let mut length_array = [0u8; 8];
        BigEndian::write_u64(&mut length_array, size as u64);
        h.update(&length_array);

        // 取前16字节作为FileID
        let hash_result = h.finalize();
        Ok(FileId {
            hi: u64::from_be_bytes(hash_result[0..8].try_into().unwrap()),
            lo: u64::from_be_bytes(hash_result[8..16].try_into().unwrap()),
        })
    }

    pub fn try_from_path<P: AsRef<Path>>(file_name: P) -> Result<FileId> {
        let mut file = File::open(file_name)?;
        Self::try_from_reader(&mut file)
    }

    pub fn try_from_file(file: &mut File) -> Result<FileId> {
        Self::try_from_reader(file)
    }

    pub fn id(&self) {}
}

#[cfg(test)]
mod tests {
    use crate::symbollizer::file_id::FileId;

    #[test]
    fn test_smaple() {
        println!(
            "{:?}",
            FileId::try_from_path("/usr/lib/systemd/libsystemd-shared-239.so")
        );
    }
}
