use anyhow::{bail, Result};
use std::path::PathBuf;

pub fn btf_locate_path() -> Option<PathBuf> {
    let p = PathBuf::from(&"/sys/kernel/btf/vmlinux");
    if p.exists() {
        return Some(p);
    }

    if let Ok(info) = uname::uname() {
        let p = PathBuf::from(format!("/boot/vmlinux-{}", info.release));
        if p.exists() {
            return Some(p);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btf_locating() {
        assert!(btf_locate_path().is_some());
    }
}
