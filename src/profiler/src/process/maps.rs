use crate::symbollizer::file_id::FileId64;
use anyhow::Result;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;

#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy)]
pub struct DiskFileKey {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug)]
pub struct ProcessMapsEntry {
    pub start: u64,
    pub end: u64,
    perm: String,
    pub offset: u64,
    pub device: u64,
    pub inode: u64,
    pub path: Option<String>,
}

impl fmt::Display for ProcessMapsEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}-{:#x} {} {:#x} {} {}",
            self.start, self.end, self.perm, self.offset, self.device, self.inode
        )?;
        if let Some(ref path) = self.path {
            write!(f, " {}", path)?;
        }
        Ok(())
    }
}

impl PartialEq for ProcessMapsEntry {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
            && self.end == other.end
            && self.offset == other.offset
            && self.device == other.device
            && self.inode == other.inode
    }
}

impl Eq for ProcessMapsEntry {}

impl From<String> for ProcessMapsEntry {
    fn from(value: String) -> Self {
        let parts: Vec<&str> = value.split_whitespace().collect();

        let address_parts: Vec<&str> = parts[0].split('-').collect();
        let start = u64::from_str_radix(address_parts[0], 16).unwrap();
        let end = u64::from_str_radix(address_parts[1], 16).unwrap();
        let perm = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16).unwrap();
        let device_parts: Vec<&str> = parts[3].split(':').collect();
        let device = u64::from_str_radix(device_parts[0], 16).unwrap()
            + u64::from_str_radix(device_parts[1], 16).unwrap();
        let inode = parts[4].parse().unwrap_or(0);
        let path = if parts.len() == 6 {
            Some(parts[5].to_string())
        } else {
            None
        };

        Self {
            start,
            end,
            perm,
            offset,
            device,
            inode,
            path,
        }
    }
}

impl ProcessMapsEntry {
    pub fn is_executable(&self) -> bool {
        self.perm.contains('x')
    }

    pub fn is_anonymous(&self) -> bool {
        self.path
            .as_ref()
            .map_or(true, |x| x.starts_with("/memfd:"))
    }

    pub fn is_readable(&self) -> bool {
        self.perm.contains('r')
    }

    pub fn disk_file_key(&self) -> DiskFileKey {
        DiskFileKey {
            device: self.device,
            inode: self.inode,
        }
    }

    pub fn is_vdso(&self) -> bool {
        self.path.as_ref().map_or(false, |f| f == "linux-vdso.1.so")
    }

    pub fn file_path(&self, pid: u32) -> String {
        if self.is_anonymous() || self.is_vdso() {
            "".to_owned()
        } else {
            format!("/proc/{}/root/{}", pid, self.path.as_ref().unwrap())
        }
    }
}

#[derive(Debug, Default)]
pub struct ProcessMaps {
    // entries: Vec<ProcessMapsEntry>,
    entries: HashMap<u64, ProcessMapsEntry>,
}

// 实现 Deref trait，允许 ProcessMaps 实例像 &HashMap 一样被解引用
impl Deref for ProcessMaps {
    type Target = HashMap<u64, ProcessMapsEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

// 实现 DerefMut trait，允许可变的 ProcessMaps 实例像 &mut HashMap 一样被解引用
impl DerefMut for ProcessMaps {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

impl ProcessMaps {
    pub fn new(pid: u32) -> Result<Self> {
        let maps_path = Path::new("/proc").join(pid.to_string()).join("maps");
        let file = File::open(maps_path)?;
        let reader = BufReader::new(file);

        let mut entries = HashMap::<u64, ProcessMapsEntry>::default();
        for line_result in reader.lines() {
            let line = line_result?;
            let mut entry = ProcessMapsEntry::from(line);
            if !entry.is_readable() || !entry.is_executable() {
                continue;
            }

            if entry.inode == 0 {
                let skip = entry.path.as_mut().map_or_else(
                    || true,
                    |p| {
                        if p.as_str().cmp("[vdso]") == Ordering::Equal {
                            p.clear();
                            p.push_str("linux-vdso.1.so");
                            entry.inode = 50;
                            entry.device = 0;
                            false
                        } else if p.len() > 0 {
                            true
                        } else {
                            false
                        }
                    },
                );
                if skip {
                    continue;
                }
            } else {
                entry.path.as_mut().map(|p| {
                    let _ = p.strip_suffix(" (deleted)");
                    if p.as_str().cmp("/dev/zero").is_eq() {
                        p.clear();
                    }
                });
            }
            entries.insert(entry.start, entry);
        }
        Ok(Self { entries })
    }

    /// Compares two `ProcessMaps` instances and returns the added and removed entries.
    pub fn diff(&self, other: &Self) -> (Vec<u64>, Vec<u64>) {
        let mut added = Vec::new();
        let mut removed = Vec::new();

        // 遍历 other 中的每个条目，检查是否为新增或内容变化
        for (key, other_entry) in &other.entries {
            match self.entries.get(key) {
                Some(self_entry) => {
                    // 检查内容是否相同
                    if !self_entry.eq(other_entry) {
                        // 内容不同，视为修改（这里作为新增处理，具体策略可根据需求调整）
                        added.push(*key);
                    }
                }
                None => {
                    // 键不在 self.entries 中，视为新增
                    added.push(*key);
                }
            }
        }

        // 遍历 self 中的每个条目，检查是否已被删除
        for (key, _) in &self.entries {
            if !other.entries.contains_key(key) {
                removed.push(*key);
            }
        }

        (added, removed)
    }

    pub fn find_so(&self, name: &str) -> Option<String> {
        for (_, entry) in self.entries.iter() {
            if entry.path.as_ref().map_or(false, |p| p.ends_with(name)) {
                return entry.path.clone();
            }
        }

        None
    }
}

#[derive(Debug)]
pub struct ExeMapsEntry {
    pub file_id: FileId64,
    pub vaddr: u64,
    pub offset: u64,
    pub bias: u64,
    pub length: u64,
    pub device: u64,
    pub inode: u64,
}

#[cfg(test)]
mod tests {
    use super::ProcessMaps;
    use super::ProcessMapsEntry;

    #[test]
    fn test_parse_process_maps() {
        assert!(!ProcessMaps::new(1).unwrap().is_empty());
    }

    #[test]
    fn test_parse_normal_entry() {
        let line = "7f36539f5000-7f36539f6000 ---p 00017000 fd:01 1182371                    /usr/lib64/libz.so.1.2.11".to_owned();

        let pme = ProcessMapsEntry::from(line);

        assert_eq!(pme.start, 0x7f36539f5000);
        assert_eq!(pme.end, 0x7f36539f6000);
        assert_eq!(pme.perm, "---p".to_owned());
        assert_eq!(pme.offset, 0x00017000);
        assert_eq!(pme.device, 0xfd + 1);
        assert_eq!(pme.inode, 1182371);
        assert_eq!(pme.path.unwrap(), "/usr/lib64/libz.so.1.2.11".to_owned());
    }

    #[test]
    fn test_maps_entry_method() {
        let line = "7f365403f000-7f3654043000 r-xp 00003000 fd:01 1181906                    /usr/lib64/librt-2.32.so".to_owned();
        let pme = ProcessMapsEntry::from(line);
        assert!(pme.is_executable());
        assert!(pme.is_readable());
    }
}
