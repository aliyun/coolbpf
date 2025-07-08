use anyhow::bail;
use anyhow::Result;
use pagemap::MemoryRegion;
use procfs::page_size;

// user virtual address to page frame number(pfn)
pub fn v2p(pid: u32, virt: u64) -> Result<u64> {
    let mut maps = pagemap::PageMap::new(pid as u64)?;
    let page = page_size();

    let start = virt & !(page - 1);
    let end = start + page;

    let entries = maps.pagemap_region(&MemoryRegion::from((start, end)))?;

    if entries.len() != 1 {
        bail!("Number of entries is not 1")
    }

    let pfn = entries[0].pfn()?;
    Ok(pfn)
}

// user virtual address to kernel virtual address
// page_kv = (pfn << 12) + page_offset_base
// kv = page_kv + offset in page
pub fn v2kv(pid: u32, virt: u64, page_offset_base: u64) -> Result<u64> {
    let pfn = v2p(pid, virt)?;
    let page_kv = (pfn << 12) + page_offset_base;
    let page = page_size();
    let off = virt & (page - 1);
    Ok(page_kv + off)
}
