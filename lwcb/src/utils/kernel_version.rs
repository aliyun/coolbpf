use anyhow::Result;

pub fn kernel_version() -> Result<u32> {
    let release = uname::uname()?.release;

    let mut versions = vec![];
    let mut version = 0;
    for c in release.chars() {
        if c >= '0' && c <= '9' {
            version *= 10;
            version += (c as u32) - ('0' as u32);
            continue;
        }

        versions.push(version);
        version = 0;

        if c == '-' {
            break;
        }
    }

    assert!(versions.len() == 3);

    return Ok((versions[0] << 16)
        + (versions[1] << 8)
        + (if versions[2] > 255 { 255 } else { versions[2] }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version() {
        assert!(kernel_version().is_ok());
    }
}
