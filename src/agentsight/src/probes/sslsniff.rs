// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// SSL/TLS sniffer built on libbpf-rs.
// Exposes a `SslSniff` struct with a builder-style API.

use crate::{config, http_event::HTTPEvent, http_parser::HTTPParser};
use anyhow::{Context, Result, bail};
use libbpf_rs::{
    Link, RingBufferBuilder, UprobeOpts,
    skel::{OpenSkel, SkelBuilder},
};
use procfs::process::Process;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    mem::MaybeUninit,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

// ─── Generated skeleton ───────────────────────────────────────────────────────
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/sslsniff.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/sslsniff.rs"));
}
use bpf::*;

// ─── Constants ────────────────────────────────────────────────────────────────
const MAX_BUF_SIZE: usize = bpf::MAX_BUF_SIZE as usize;
const POLL_TIMEOUT_MS: u64 = 100;

pub type SslEvent = bpf::probe_SSL_data_t;

impl SslEvent {
    pub fn payload(&self) -> Option<&str> {
        std::str::from_utf8(&self.buf[..self.buf_size as usize]).ok()
    }
}

// ─── Main struct ──────────────────────────────────────────────────────────────
pub struct SslSniff {
    // We store the skel behind a Box so we can hold it alongside the
    // links without lifetime trouble.  The MaybeUninit holds the
    // OpenObject allocation that the skeleton borrows from.
    _open_object: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Box<SslsniffSkel<'static>>,
    _links: Vec<Link>,
    traced_files: HashSet<u64>,
    // Use Box<SslEvent> in channel to avoid large stack copies (SslEvent is ~512KB)
    tx: crossbeam_channel::Sender<Box<SslEvent>>,
    rx: crossbeam_channel::Receiver<Box<SslEvent>>,
}

impl SslSniff {
    pub fn new() -> Result<Self> {
        // ── Open + load skeleton ───────────────────────────────────────
        let mut builder = SslsniffSkelBuilder::default();
        builder.obj_builder.debug(config::verbose());
        // Keep MaybeUninit on the heap so its address is stable.
        let open_object = Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit());
        let open_skel = builder.open().context("failed to open BPF object")?;
        let skel = open_skel.load().context("failed to load BPF object")?;

        // SAFETY: skel borrows open_object which lives in a Box<MaybeUninit>
        // on the heap.  We pin both together inside Self and never move either,
        // so the 'static lifetime cast is sound for the lifetime of Self.
        let skel =
            unsafe { Box::from_raw(Box::into_raw(Box::new(skel)) as *mut SslsniffSkel<'static>) };

        let (tx, rx) = crossbeam_channel::unbounded();
        Ok(Self {
            _open_object: open_object,
            skel,
            _links: Vec::new(),
            traced_files: HashSet::default(),
            tx,
            rx,
        })
    }

    /// Attach SSL probes to a running process by reading its `/proc/<pid>/maps`.
    ///
    /// Detects which SSL libraries the process has mapped (OpenSSL, GnuTLS, NSS,
    /// or BoringSSL embedded in a binary), attaches uprobes, and skips any
    /// library whose inode has already been traced (dedup via `traced_files`).
    pub fn attach_process(&mut self, pid: i32) -> Result<()> {
        let libs = ssl_libs_from_maps(pid)?;
        if libs.is_empty() {
            log::warn!("[attach_process] pid={pid}: no SSL libraries found in maps");
            return Ok(());
        }

        for (path, inode, kind) in libs {
            // Skip libraries whose inode we already traced.
            if !self.traced_files.insert(inode) {
                log::debug!("[attach_process] pid={pid}: skipping already-traced {path}");
                continue;
            }

            log::debug!("[attach_process] pid={pid}: attaching {kind:?} → {path}");

            let result = match kind {
                SslLibKind::OpenSsl => attach_openssl(&mut self.skel, &path, pid),
                SslLibKind::GnuTls => attach_gnutls(&mut self.skel, &path, pid),
                SslLibKind::Nss => attach_nss(&mut self.skel, &path, pid),
                SslLibKind::Boring => {
                    // BoringSSL doesn't export named symbols; detect by byte pattern.
                    match find_boringssl_offsets(&path) {
                        Some(off) => {
                            attach_boringssl_by_offset(&mut self.skel, &path, &off, false, pid)
                        }
                        None => {
                            // Fall back to symbol-based attach (works for some builds).
                            attach_openssl(&mut self.skel, &path, pid)
                        }
                    }
                }
            };

            match result {
                Ok(ls) => self._links.extend(ls),
                Err(e) => eprintln!("Warning: attach_process pid={pid} {path}: {e:#}"),
            }
        }
        Ok(())
    }

    /// Spawn a background thread that polls the BPF ring buffer and sends
    /// decoded [`SslEvent`]s through an internal channel.
    ///
    /// Returns a [`SslPoller`] handle.  Drop it (or call [`SslPoller::stop`])
    /// to signal the poll thread to exit.
    pub fn run(&self) -> Result<SslPoller> {
        let min_sz = std::mem::size_of::<RawEvent>();
        let tx = self.tx.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_inner = Arc::clone(&stop_flag);

        // We need the ring-buffer map fd, which is owned by `self.skel`.
        // Build the RingBuffer here (on the calling thread) then move it
        // into the poll thread.
        let mut rb_builder = RingBufferBuilder::new();
        let binding = self.skel.maps();
        rb_builder
            .add(&binding.rb(), move |data: &[u8]| {
                if data.len() < min_sz {
                    return 0;
                }
                // SAFETY: eBPF side guarantees the layout and alignment.
                // Allocate on heap to avoid stack overflow (RawEvent is ~512KB due to buf field)
                let raw = unsafe { &*(data.as_ptr() as *const RawEvent) };
                let event: Box<SslEvent> =
                    Box::new(unsafe { std::ptr::read(raw as *const _ as *const SslEvent) });
                let _ = tx.send(event);
                0
            })
            .context("failed to add ring buffer")?;
        let rb = rb_builder.build().context("failed to build ring buffer")?;

        let handle = thread::Builder::new()
            .name("sslsniff-poll".into())
            .spawn(move || {
                let timeout = Duration::from_millis(POLL_TIMEOUT_MS);
                loop {
                    if stop_flag_inner.load(Ordering::Relaxed) {
                        break;
                    }
                    match rb.poll(timeout) {
                        Ok(_) => {}
                        Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
                        Err(e) => {
                            eprintln!("sslsniff poll error: {e:#}");
                            break;
                        }
                    }
                }
            })
            .context("failed to spawn poll thread")?;

        Ok(SslPoller {
            handle: Some(handle),
            stop_flag,
        })
    }

    /// Receive the next [`SslEvent`] from the background poll thread.
    ///
    /// Blocks until an event arrives or the sender is disconnected.
    pub fn recv(&self) -> Option<SslEvent> {
        self.rx.recv().ok().map(|boxed| *boxed)
    }

    /// Non-blocking variant of [`recv`](Self::recv).
    pub fn try_recv(&self) -> Option<SslEvent> {
        self.rx.try_recv().ok().map(|boxed| *boxed)
    }
}

// ─── Poll thread handle ─────────────────────────────────────────────────────

/// Handle returned by [`SslSniff::run`].
///
/// The background poll thread runs until this handle is dropped or
/// [`SslPoller::stop`] is called explicitly.
pub struct SslPoller {
    handle: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
}

impl SslPoller {
    /// Signal the poll thread to stop and wait for it to finish.
    pub fn stop(mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for SslPoller {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ─── Raw kernel event layout (matches sslsniff.h) ────────────────────────────

type RawEvent = bpf::probe_SSL_data_t;

// ─── BoringSSL pattern detection ─────────────────────────────────────────────

struct BoringSslOffsets {
    ssl_write: usize,
    ssl_read: usize,
    ssl_do_handshake: usize,
}

fn find_pattern(haystack: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return None;
    }
    haystack.windows(pattern.len()).position(|w| w == pattern)
}

fn find_boringssl_offsets(path: &str) -> Option<BoringSslOffsets> {
    const HANDSHAKE_PAT: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83,
        0xec, 0x28, 0x49, 0x89, 0xfc, 0x48, 0x8b, 0x47, 0x30,
    ];
    const READ_PAT: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50, 0x48, 0x83, 0xbf, 0x98, 0x00,
        0x00, 0x00, 0x00, 0x74,
    ];
    const WRITE_PAT: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83,
        0xec, 0x18, 0x41, 0x89, 0xd7, 0x49, 0x89, 0xf6, 0x48, 0x89, 0xfb,
    ];
    const READ_HANDSHAKE_DELTA: usize = 0x6F0;
    const WRITE_READ_DELTA: usize = 0xCA0;
    let verbose = config::verbose();

    let data = fs::read(path).ok()?;

    let read_off = find_pattern(&data, READ_PAT).or_else(|| {
        if verbose {
            eprintln!("BoringSSL: SSL_read pattern not found");
        }
        None
    })?;

    let hs_off = if read_off >= READ_HANDSHAKE_DELTA {
        let exp = read_off - READ_HANDSHAKE_DELTA;
        if data[exp..].starts_with(HANDSHAKE_PAT) {
            Some(exp)
        } else {
            find_pattern(&data, HANDSHAKE_PAT)
        }
    } else {
        find_pattern(&data, HANDSHAKE_PAT)
    }
    .or_else(|| {
        if verbose {
            eprintln!("BoringSSL: SSL_do_handshake pattern not found");
        }
        None
    })?;

    let exp_wr = read_off + WRITE_READ_DELTA;
    let wr_off = if exp_wr + WRITE_PAT.len() <= data.len() && data[exp_wr..].starts_with(WRITE_PAT)
    {
        Some(exp_wr)
    } else {
        let end = (read_off + 0x10000).min(data.len());
        find_pattern(&data[read_off..end], WRITE_PAT).map(|o| read_off + o)
    }
    .or_else(|| {
        if verbose {
            eprintln!("BoringSSL: SSL_write pattern not found near SSL_read");
        }
        None
    })?;

    log::debug!("BoringSSL detected in {path}:");
    log::debug!("  SSL_do_handshake: {hs_off:#x}");
    log::debug!("  SSL_read:         {read_off:#x}");
    log::debug!("  SSL_write:        {wr_off:#x}");

    Some(BoringSslOffsets {
        ssl_write: wr_off,
        ssl_read: read_off,
        ssl_do_handshake: hs_off,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// SSL library kind detected from `/proc/<pid>/maps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslLibKind {
    /// libssl.so  (OpenSSL / LibreSSL)
    OpenSsl,
    /// libgnutls.so
    GnuTls,
    /// libnspr4.so (NSS / Firefox)
    Nss,
    /// BoringSSL embedded in binary (e.g. Node.js, Chrome)
    Boring,
}

/// Classify a mapped file path into an `SslLibKind`, if it is an SSL library.
fn classify_ssl_lib(path: &str) -> Option<SslLibKind> {
    let name = Path::new(path).file_name()?.to_string_lossy();
    if name.starts_with("libssl.so") || name.starts_with("libssl-") {
        return Some(SslLibKind::OpenSsl);
    }
    if name.starts_with("libgnutls.so") || name.starts_with("libgnutls-") {
        return Some(SslLibKind::GnuTls);
    }
    if name.starts_with("libnspr4.so") || name.starts_with("libnspr4-") {
        return Some(SslLibKind::Nss);
    }
    // BoringSSL is typically linked statically into a binary (node, chrome, etc.).
    // Detect common binary names that are known to embed BoringSSL.
    if matches!(
        name.as_ref(),
        "node"
            | "nodejs"
            | "bun"
            | "deno"
            | "chrome"
            | "chromium"
            | "google-chrome"
            | "google-chrome-stable"
    ) {
        return Some(SslLibKind::Boring);
    }
    None
}

/// Parse `/proc/<pid>/maps` via `procfs` and return `(absolute_path, inode, SslLibKind)`
/// for every SSL-related library found.
///
/// Each unique inode is returned at most once.
fn ssl_libs_from_maps(pid: i32) -> Result<Vec<(String, u64, SslLibKind)>> {
    let proc = Process::new(pid).with_context(|| format!("failed to open /proc/{pid}"))?;
    let maps = proc
        .maps()
        .with_context(|| format!("failed to read /proc/{pid}/maps"))?;

    let mut seen_inodes: HashSet<u64> = HashSet::new();
    let mut results: Vec<(String, u64, SslLibKind)> = Vec::new();

    for entry in maps.iter() {
        // Only care about file-backed mappings.
        let path_str = match &entry.pathname {
            procfs::process::MMapPath::Path(p) => p.to_string_lossy().into_owned(),
            _ => continue,
        };
        // inode comes from the memory map entry's inode field.
        let inode = entry.inode;
        if inode == 0 || seen_inodes.contains(&inode) {
            continue;
        }
        if let Some(kind) = classify_ssl_lib(&path_str) {
            seen_inodes.insert(inode);
            results.push((path_str, inode, kind));
        }
    }

    Ok(results)
}

/// Convert a null-terminated `i8` array (from C `char comm[TASK_COMM_LEN]`) to a `String`.
fn comm_to_string(comm: &[i8]) -> String {
    let bytes: Vec<u8> = comm
        .iter()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ─── uprobe helpers ───────────────────────────────────────────────────────────

fn make_sym_opts(sym: &str, retprobe: bool) -> UprobeOpts {
    let mut o = UprobeOpts::default();
    o.func_name = sym.to_string();
    o.retprobe = retprobe;
    o
}

fn make_off_opts(retprobe: bool) -> UprobeOpts {
    let mut o = UprobeOpts::default();
    o.retprobe = retprobe;
    o
}

macro_rules! up {
    ($prog:expr, $pid:expr, $path:expr, $sym:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, 0, make_sym_opts($sym, false))
            .with_context(|| format!("uprobe {}@{}", $sym, $path))
    };
}
macro_rules! ur {
    ($prog:expr, $pid:expr, $path:expr, $sym:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, 0, make_sym_opts($sym, true))
            .with_context(|| format!("uretprobe {}@{}", $sym, $path))
    };
}
macro_rules! up_off {
    ($prog:expr, $pid:expr, $path:expr, $off:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, $off, make_off_opts(false))
            .with_context(|| format!("uprobe offset {:#x}@{}", $off, $path))
    };
}
macro_rules! ur_off {
    ($prog:expr, $pid:expr, $path:expr, $off:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, $off, make_off_opts(true))
            .with_context(|| format!("uretprobe offset {:#x}@{}", $off, $path))
    };
}

fn attach_openssl(skel: &mut SslsniffSkel<'_>, lib: &str, pid: i32) -> Result<Vec<Link>> {
    Ok(vec![
        up!(skel.progs_mut().probe_SSL_rw_enter(), pid, lib, "SSL_write")?,
        ur!(
            skel.progs_mut().probe_SSL_write_exit(),
            pid,
            lib,
            "SSL_write"
        )?,
        up!(skel.progs_mut().probe_SSL_rw_enter(), pid, lib, "SSL_read")?,
        ur!(skel.progs_mut().probe_SSL_read_exit(), pid, lib, "SSL_read")?,
        up!(
            skel.progs_mut().probe_SSL_write_ex_enter(),
            pid,
            lib,
            "SSL_write_ex"
        )?,
        ur!(
            skel.progs_mut().probe_SSL_write_ex_exit(),
            pid,
            lib,
            "SSL_write_ex"
        )?,
        up!(
            skel.progs_mut().probe_SSL_read_ex_enter(),
            pid,
            lib,
            "SSL_read_ex"
        )?,
        ur!(
            skel.progs_mut().probe_SSL_read_ex_exit(),
            pid,
            lib,
            "SSL_read_ex"
        )?,
        up!(
            skel.progs_mut().probe_SSL_do_handshake_enter(),
            pid,
            lib,
            "SSL_do_handshake"
        )?,
        ur!(
            skel.progs_mut().probe_SSL_do_handshake_exit(),
            pid,
            lib,
            "SSL_do_handshake"
        )?,
    ])
}

fn attach_gnutls(skel: &mut SslsniffSkel<'_>, lib: &str, pid: i32) -> Result<Vec<Link>> {
    Ok(vec![
        up!(
            skel.progs_mut().probe_SSL_rw_enter(),
            pid,
            lib,
            "gnutls_record_send"
        )?,
        ur!(
            skel.progs_mut().probe_SSL_write_exit(),
            pid,
            lib,
            "gnutls_record_send"
        )?,
        up!(
            skel.progs_mut().probe_SSL_rw_enter(),
            pid,
            lib,
            "gnutls_record_recv"
        )?,
        ur!(
            skel.progs_mut().probe_SSL_read_exit(),
            pid,
            lib,
            "gnutls_record_recv"
        )?,
    ])
}

fn attach_nss(skel: &mut SslsniffSkel<'_>, lib: &str, pid: i32) -> Result<Vec<Link>> {
    Ok(vec![
        up!(skel.progs_mut().probe_SSL_rw_enter(), pid, lib, "PR_Write")?,
        ur!(
            skel.progs_mut().probe_SSL_write_exit(),
            pid,
            lib,
            "PR_Write"
        )?,
        up!(skel.progs_mut().probe_SSL_rw_enter(), pid, lib, "PR_Send")?,
        ur!(skel.progs_mut().probe_SSL_write_exit(), pid, lib, "PR_Send")?,
        up!(skel.progs_mut().probe_SSL_rw_enter(), pid, lib, "PR_Read")?,
        ur!(skel.progs_mut().probe_SSL_read_exit(), pid, lib, "PR_Read")?,
        up!(skel.progs_mut().probe_SSL_rw_enter(), pid, lib, "PR_Recv")?,
        ur!(skel.progs_mut().probe_SSL_read_exit(), pid, lib, "PR_Recv")?,
    ])
}

fn attach_boringssl_by_offset(
    skel: &mut SslsniffSkel<'_>,
    lib: &str,
    off: &BoringSslOffsets,
    handshake: bool,
    pid: i32,
) -> Result<Vec<Link>> {
    let mut links = vec![
        up_off!(
            skel.progs_mut().probe_SSL_rw_enter(),
            pid,
            lib,
            off.ssl_write
        )?,
        ur_off!(
            skel.progs_mut().probe_SSL_write_exit(),
            pid,
            lib,
            off.ssl_write
        )?,
        up_off!(
            skel.progs_mut().probe_SSL_rw_enter(),
            pid,
            lib,
            off.ssl_read
        )?,
        ur_off!(
            skel.progs_mut().probe_SSL_read_exit(),
            pid,
            lib,
            off.ssl_read
        )?,
    ];
    if handshake {
        links.push(up_off!(
            skel.progs_mut().probe_SSL_do_handshake_enter(),
            pid,
            lib,
            off.ssl_do_handshake
        )?);
        links.push(ur_off!(
            skel.progs_mut().probe_SSL_do_handshake_exit(),
            pid,
            lib,
            off.ssl_do_handshake
        )?);
    }
    Ok(links)
}
