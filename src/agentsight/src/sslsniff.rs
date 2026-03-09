// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on sslsniff from BCC by Adrian Lopez & Mark Drayton.
// Rust port using libbpf-rs.

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
    UprobeOpts,
};
use std::{
    fs,
    io::Write,
    mem::MaybeUninit,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};

// ─── Generated skeleton ───────────────────────────────────────────────────────
mod skel {
    include!(concat!(env!("OUT_DIR"), "/sslsniff.skel.rs"));
}

use skel::*;

// ─── Constants ────────────────────────────────────────────────────────────────
const MAX_BUF_SIZE: usize = 512 * 1024; // 512 KB — must match sslsniff.h
const INVALID_UID: i32 = -1;
const INVALID_PID: i32 = -1;
const PERF_POLL_TIMEOUT_MS: u64 = 100;

// ─── CLI ──────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    name = "sslsniff",
    version = "0.1",
    about = "Sniff SSL data and output in JSON format.\n\n\
             OUTPUT: Each SSL event is a JSON object on its own line.\n\
             eBPF capture is limited to 512 KB per event.\n\n\
             EXAMPLES:\n\
             \t./sslsniff              # sniff OpenSSL\n\
             \t./sslsniff -p 181       # PID 181 only\n\
             \t./sslsniff -u 1000      # UID 1000 only\n\
             \t./sslsniff -c curl      # curl only\n\
             \t./sslsniff --no-openssl # skip OpenSSL\n\
             \t./sslsniff --handshake  # include handshake events\n\
             \t./sslsniff --binary-path /path/to/node"
)]
struct Args {
    /// Sniff this PID only
    #[arg(short, long, default_value_t = INVALID_PID)]
    pid: i32,

    /// Sniff this UID only
    #[arg(short, long, default_value_t = INVALID_UID)]
    uid: i32,

    /// Filter by process name
    #[arg(short, long)]
    comm: Option<String>,

    /// Do not attach to OpenSSL (libssl.so)
    #[arg(short = 'o', long = "no-openssl")]
    no_openssl: bool,

    /// Do not attach to GnuTLS (libgnutls.so)
    #[arg(short = 'g', long = "no-gnutls")]
    no_gnutls: bool,

    /// Do not attach to NSS (libnspr4.so)
    #[arg(short = 'n', long = "no-nss")]
    no_nss: bool,

    /// Also emit handshake events
    #[arg(long)]
    handshake: bool,

    /// Verbose libbpf debug output
    #[arg(short, long)]
    verbose: bool,

    /// Attach to a specific binary (e.g. Node.js, Bun)
    #[arg(long = "binary-path")]
    binary_path: Option<String>,
}

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

fn find_boringssl_offsets(path: &str, verbose: bool) -> Option<BoringSslOffsets> {
    // Byte-sequence prologues derived from Bun v1.3.x profile builds.
    const HANDSHAKE_PAT: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
        0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
        0x28, 0x49, 0x89, 0xfc, 0x48, 0x8b, 0x47, 0x30,
    ];
    const READ_PAT: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
        0x53, 0x50, 0x48, 0x83, 0xbf, 0x98, 0x00, 0x00,
        0x00, 0x00, 0x74,
    ];
    const WRITE_PAT: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
        0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
        0x18, 0x41, 0x89, 0xd7, 0x49, 0x89, 0xf6, 0x48,
        0x89, 0xfb,
    ];
    const READ_HANDSHAKE_DELTA: usize = 0x6F0;
    const WRITE_READ_DELTA: usize = 0xCA0;

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {path}: {e}");
            return None;
        }
    };

    let read_off = find_pattern(&data, READ_PAT)?;

    // SSL_do_handshake: try expected relative position first
    let hs_off = if read_off >= READ_HANDSHAKE_DELTA {
        let exp = read_off - READ_HANDSHAKE_DELTA;
        if data[exp..].starts_with(HANDSHAKE_PAT) {
            Some(exp)
        } else {
            find_pattern(&data, HANDSHAKE_PAT)
        }
    } else {
        find_pattern(&data, HANDSHAKE_PAT)
    };

    let hs_off = hs_off.or_else(|| {
        if verbose {
            eprintln!("BoringSSL: SSL_do_handshake pattern not found");
        }
        None
    })?;

    // SSL_write: try expected relative position first, then nearby window
    let wr_off = {
        let exp = read_off + WRITE_READ_DELTA;
        if exp + WRITE_PAT.len() <= data.len() && data[exp..].starts_with(WRITE_PAT) {
            Some(exp)
        } else {
            let end = (read_off + 0x10000).min(data.len());
            find_pattern(&data[read_off..end], WRITE_PAT).map(|o| read_off + o)
        }
    };

    let wr_off = wr_off.or_else(|| {
        if verbose {
            eprintln!("BoringSSL: SSL_write pattern not found near SSL_read");
        }
        None
    })?;

    if verbose {
        eprintln!("BoringSSL detected in {path}:");
        eprintln!("  SSL_do_handshake offset: {hs_off:#x}");
        eprintln!("  SSL_read offset:         {read_off:#x}");
        eprintln!("  SSL_write offset:        {wr_off:#x}");
    }

    Some(BoringSslOffsets {
        ssl_write: wr_off,
        ssl_read: read_off,
        ssl_do_handshake: hs_off,
    })
}

// ─── Library path lookup ──────────────────────────────────────────────────────

fn find_library_path(libname: &str) -> Option<String> {
    let out = std::process::Command::new("sh")
        .args(["-c", &format!("ldconfig -p | grep {libname}")])
        .output()
        .ok()?;

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(pos) = line.rfind("=> ") {
            let p = line[pos + 3..].trim().to_string();
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    None
}

// ─── uprobe attachment helpers ────────────────────────────────────────────────

fn make_uprobe_opts(sym: &str, retprobe: bool) -> UprobeOpts {
    let mut opts = UprobeOpts::default();
    opts.func_name = sym.to_string();
    opts.retprobe = retprobe;
    opts
}

fn make_offset_opts(retprobe: bool) -> UprobeOpts {
    let mut opts = UprobeOpts::default();
    opts.retprobe = retprobe;
    opts
}

/// Attach by symbol.  Returns the link or an error.
macro_rules! up {
    ($prog:expr, $pid:expr, $path:expr, $sym:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, 0, make_uprobe_opts($sym, false))
            .with_context(|| format!("uprobe {}@{}", $sym, $path))
    };
}
macro_rules! ur {
    ($prog:expr, $pid:expr, $path:expr, $sym:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, 0, make_uprobe_opts($sym, true))
            .with_context(|| format!("uretprobe {}@{}", $sym, $path))
    };
}

/// Attach by raw file offset.
macro_rules! up_off {
    ($prog:expr, $pid:expr, $path:expr, $off:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, $off, make_offset_opts(false))
            .with_context(|| format!("uprobe offset {:#x}@{}", $off, $path))
    };
}
macro_rules! ur_off {
    ($prog:expr, $pid:expr, $path:expr, $off:expr) => {
        $prog
            .attach_uprobe_with_opts($pid, $path, $off, make_offset_opts(true))
            .with_context(|| format!("uretprobe offset {:#x}@{}", $off, $path))
    };
}

fn attach_openssl(
    skel: &mut SslsniffSkel<'_>,
    lib: &str,
    pid: i32,
) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();
    links.push(up!(skel.progs.probe_SSL_rw_enter,        pid, lib, "SSL_write")?);
    links.push(ur!(skel.progs.probe_SSL_write_exit,      pid, lib, "SSL_write")?);
    links.push(up!(skel.progs.probe_SSL_rw_enter,        pid, lib, "SSL_read")?);
    links.push(ur!(skel.progs.probe_SSL_read_exit,       pid, lib, "SSL_read")?);
    links.push(up!(skel.progs.probe_SSL_write_ex_enter,  pid, lib, "SSL_write_ex")?);
    links.push(ur!(skel.progs.probe_SSL_write_ex_exit,   pid, lib, "SSL_write_ex")?);
    links.push(up!(skel.progs.probe_SSL_read_ex_enter,   pid, lib, "SSL_read_ex")?);
    links.push(ur!(skel.progs.probe_SSL_read_ex_exit,    pid, lib, "SSL_read_ex")?);
    links.push(up!(skel.progs.probe_SSL_do_handshake_enter, pid, lib, "SSL_do_handshake")?);
    links.push(ur!(skel.progs.probe_SSL_do_handshake_exit,  pid, lib, "SSL_do_handshake")?);
    Ok(links)
}

fn attach_gnutls(
    skel: &mut SslsniffSkel<'_>,
    lib: &str,
    pid: i32,
) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();
    links.push(up!(skel.progs.probe_SSL_rw_enter,   pid, lib, "gnutls_record_send")?);
    links.push(ur!(skel.progs.probe_SSL_write_exit, pid, lib, "gnutls_record_send")?);
    links.push(up!(skel.progs.probe_SSL_rw_enter,   pid, lib, "gnutls_record_recv")?);
    links.push(ur!(skel.progs.probe_SSL_read_exit,  pid, lib, "gnutls_record_recv")?);
    Ok(links)
}

fn attach_nss(
    skel: &mut SslsniffSkel<'_>,
    lib: &str,
    pid: i32,
) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();
    links.push(up!(skel.progs.probe_SSL_rw_enter,   pid, lib, "PR_Write")?);
    links.push(ur!(skel.progs.probe_SSL_write_exit, pid, lib, "PR_Write")?);
    links.push(up!(skel.progs.probe_SSL_rw_enter,   pid, lib, "PR_Send")?);
    links.push(ur!(skel.progs.probe_SSL_write_exit, pid, lib, "PR_Send")?);
    links.push(up!(skel.progs.probe_SSL_rw_enter,   pid, lib, "PR_Read")?);
    links.push(ur!(skel.progs.probe_SSL_read_exit,  pid, lib, "PR_Read")?);
    links.push(up!(skel.progs.probe_SSL_rw_enter,   pid, lib, "PR_Recv")?);
    links.push(ur!(skel.progs.probe_SSL_read_exit,  pid, lib, "PR_Recv")?);
    Ok(links)
}

fn attach_boringssl_by_offset(
    skel: &mut SslsniffSkel<'_>,
    lib: &str,
    offsets: &BoringSslOffsets,
    handshake: bool,
    pid: i32,
) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();
    links.push(up_off!(skel.progs.probe_SSL_rw_enter,   pid, lib, offsets.ssl_write)?);
    links.push(ur_off!(skel.progs.probe_SSL_write_exit, pid, lib, offsets.ssl_write)?);
    links.push(up_off!(skel.progs.probe_SSL_rw_enter,   pid, lib, offsets.ssl_read)?);
    links.push(ur_off!(skel.progs.probe_SSL_read_exit,  pid, lib, offsets.ssl_read)?);
    if handshake {
        links.push(up_off!(skel.progs.probe_SSL_do_handshake_enter, pid, lib, offsets.ssl_do_handshake)?);
        links.push(ur_off!(skel.progs.probe_SSL_do_handshake_exit,  pid, lib, offsets.ssl_do_handshake)?);
    }
    Ok(links)
}

// ─── UTF-8 validation ─────────────────────────────────────────────────────────

/// Returns the byte length of a valid UTF-8 sequence starting at `bytes[0]`,
/// or 0 if invalid.
fn validate_utf8_char(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let c = bytes[0];
    let expected = if c < 0x80 {
        return 1;
    } else if c & 0xE0 == 0xC0 {
        2usize
    } else if c & 0xF0 == 0xE0 {
        3
    } else if c & 0xF8 == 0xF0 {
        4
    } else {
        return 0;
    };

    if bytes.len() < expected {
        return 0;
    }
    for &b in &bytes[1..expected] {
        if b & 0xC0 != 0x80 {
            return 0;
        }
    }

    let cp: u32 = match expected {
        2 => (((c & 0x1F) as u32) << 6) | ((bytes[1] & 0x3F) as u32),
        3 => (((c & 0x0F) as u32) << 12)
            | (((bytes[1] & 0x3F) as u32) << 6)
            | ((bytes[2] & 0x3F) as u32),
        4 => (((c & 0x07) as u32) << 18)
            | (((bytes[1] & 0x3F) as u32) << 12)
            | (((bytes[2] & 0x3F) as u32) << 6)
            | ((bytes[3] & 0x3F) as u32),
        _ => return 0,
    };

    let ok = match expected {
        2 => cp >= 0x80,
        3 => cp >= 0x800 && !(0xD800..=0xDFFF).contains(&cp),
        4 => (0x10000..=0x10FFFF).contains(&cp),
        _ => false,
    };
    if ok { expected } else { 0 }
}

fn write_json_data(out: &mut impl Write, buf: &[u8]) -> std::io::Result<()> {
    let mut i = 0;
    while i < buf.len() {
        let c = buf[i];
        match c {
            b'"'    => out.write_all(b"\\\"")?,
            b'\\'   => out.write_all(b"\\\\")?,
            b'\n'   => out.write_all(b"\\n")?,
            b'\r'   => out.write_all(b"\\r")?,
            b'\t'   => out.write_all(b"\\t")?,
            b'\x08' => out.write_all(b"\\b")?,
            b'\x0C' => out.write_all(b"\\f")?,
            0x20..=0x7E => out.write_all(&[c])?,
            0x80.. => {
                let seq = validate_utf8_char(&buf[i..]);
                if seq > 0 {
                    out.write_all(&buf[i..i + seq])?;
                    i += seq;
                    continue;
                }
                write!(out, "\\u{c:04x}")?;
            }
            _ => write!(out, "\\u{c:04x}")?,
        }
        i += 1;
    }
    Ok(())
}

// ─── Event data layout (must match sslsniff.h) ───────────────────────────────

#[repr(C)]
struct ProbeSSLDataT {
    timestamp_ns: u64,
    delta_ns:     u64,
    pid:          u32,
    tid:          u32,
    uid:          u32,
    len:          u32,
    buf_size:     u32,
    buf_filled:   i32,
    rw:           i32,
    comm:         [u8; 16],
    buf:          [u8; MAX_BUF_SIZE],
    is_handshake: i32,
}

fn comm_to_str(comm: &[u8; 16]) -> &str {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end]).unwrap_or("<invalid>")
}

fn print_event(event: &ProbeSSLDataT, filter_comm: Option<&str>) {
    let comm = comm_to_str(&event.comm);
    if let Some(fc) = filter_comm {
        if fc != comm {
            return;
        }
    }

    let rw_label = match event.rw {
        0 => "READ/RECV",
        1 => "WRITE/SEND",
        _ => "HANDSHAKE",
    };
    let buf_size = if event.buf_filled == 1 {
        (event.buf_size as usize).min(MAX_BUF_SIZE)
    } else {
        0
    };
    let buf = &event.buf[..buf_size];
    let latency_ms = if event.delta_ns > 0 {
        event.delta_ns as f64 / 1_000_000.0
    } else {
        0.0
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let _ = write!(
        out,
        "{{\"function\":\"{rw_label}\",\
         \"timestamp_ns\":{},\
         \"comm\":\"{comm}\",\
         \"pid\":{},\
         \"len\":{},\
         \"buf_size\":{buf_size},\
         \"uid\":{},\
         \"tid\":{},\
         \"latency_ms\":{latency_ms:.3},\
         \"is_handshake\":{},",
        event.timestamp_ns,
        event.pid,
        event.len,
        event.uid,
        event.tid,
        if event.is_handshake != 0 { "true" } else { "false" },
    );

    if buf_size > 0 {
        let _ = out.write_all(b"\"data\":\"");
        let _ = write_json_data(&mut out, buf);
        let _ = out.write_all(b"\",");
        if (buf_size as u32) < event.len {
            let lost = event.len - buf_size as u32;
            let _ = write!(out, "\"truncated\":true,\"bytes_lost\":{lost}");
        } else {
            let _ = out.write_all(b"\"truncated\":false");
        }
    } else {
        let _ = out.write_all(b"\"data\":null,\"truncated\":false");
    }

    let _ = out.write_all(b"}\n");
}

// ─── Entry point ──────────────────────────────────────────────────────────────

pub fn run() -> Result<()> {
    let args = Args::parse();
    let verbose = args.verbose;

    // Configure libbpf verbosity
    fn libbpf_print(_level: libbpf_rs::PrintLevel, msg: String) {
        eprint!("{msg}");
    }
    libbpf_rs::set_print(Some((
        if verbose {
            libbpf_rs::PrintLevel::Debug
        } else {
            libbpf_rs::PrintLevel::Warn
        },
        libbpf_print,
    )));

    // ── Open skeleton ─────────────────────────────────────────────────────
    let mut skel_builder = SslsniffSkelBuilder::default();
    if verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("failed to open BPF object")?;

    // Set rodata filters (read by BPF program)
    open_skel.maps.rodata_data.targ_uid = args.uid;
    open_skel.maps.rodata_data.targ_pid = if args.pid == INVALID_PID { 0 } else { args.pid };

    let mut skel = open_skel.load().context("failed to load BPF object")?;

    // ── Ctrl-C handler ───────────────────────────────────────────────────
    let exiting = Arc::new(AtomicBool::new(false));
    {
        let ex = exiting.clone();
        ctrlc::set_handler(move || ex.store(true, Ordering::Relaxed))
            .context("failed to set Ctrl-C handler")?;
    }

    // ── Attach probes ────────────────────────────────────────────────────
    let pid = args.pid;
    let mut _links: Vec<libbpf_rs::Link> = Vec::new();

    if !args.no_openssl {
        match find_library_path("libssl.so") {
            Some(path) => {
                if verbose { eprintln!("OpenSSL path: {path}"); }
                match attach_openssl(&mut skel, &path, pid) {
                    Ok(ls)  => _links.extend(ls),
                    Err(e)  => eprintln!("Warning: failed to attach OpenSSL: {e:#}"),
                }
            }
            None => eprintln!("Warning: OpenSSL library not found"),
        }
    }

    if !args.no_gnutls {
        match find_library_path("libgnutls.so") {
            Some(path) => {
                if verbose { eprintln!("GnuTLS path: {path}"); }
                match attach_gnutls(&mut skel, &path, pid) {
                    Ok(ls)  => _links.extend(ls),
                    Err(e)  => eprintln!("Warning: failed to attach GnuTLS: {e:#}"),
                }
            }
            None => eprintln!("Warning: GnuTLS library not found"),
        }
    }

    if !args.no_nss {
        match find_library_path("libnspr4.so") {
            Some(path) => {
                if verbose { eprintln!("NSS path: {path}"); }
                match attach_nss(&mut skel, &path, pid) {
                    Ok(ls)  => _links.extend(ls),
                    Err(e)  => eprintln!("Warning: failed to attach NSS: {e:#}"),
                }
            }
            None => eprintln!("Warning: NSS library not found"),
        }
    }

    // Custom binary (NVM Node, Bun, etc.)
    if let Some(ref extra_path) = args.binary_path {
        if !Path::new(extra_path).exists() {
            bail!("binary not found: {extra_path}");
        }
        if verbose { eprintln!("Attaching to binary: {extra_path}"); }

        // Probe whether the binary has an SSL_write symbol
        let test_result = skel
            .progs
            .probe_SSL_rw_enter
            .attach_uprobe_with_opts(pid, extra_path, 0, make_uprobe_opts("SSL_write", false));

        if let Ok(test_link) = test_result {
            // Symbol present — use full symbol-based attachment
            drop(test_link); // detach the test probe
            if verbose { eprintln!("Using symbol-based attachment for {extra_path}"); }
            match attach_openssl(&mut skel, extra_path, pid) {
                Ok(ls)  => _links.extend(ls),
                Err(e)  => eprintln!("Warning: symbol attach failed: {e:#}"),
            }
        } else {
            // No symbols — try BoringSSL pattern detection
            if verbose { eprintln!("Symbols not found, trying BoringSSL pattern detection..."); }
            match find_boringssl_offsets(extra_path, verbose) {
                Some(offsets) => {
                    eprintln!("BoringSSL detected! Attaching by offset...");
                    match attach_boringssl_by_offset(&mut skel, extra_path, &offsets, args.handshake, pid) {
                        Ok(ls)  => _links.extend(ls),
                        Err(e)  => eprintln!("Warning: offset attach failed: {e:#}"),
                    }
                }
                None => eprintln!(
                    "Warning: failed to attach to {extra_path}: \
                     no SSL symbols or BoringSSL patterns found"
                ),
            }
        }
    }

    // ── Ring buffer ───────────────────────────────────────────────────────
    let filter_comm: Option<String> = args.comm.clone();
    let handshake = args.handshake;
    let min_event_sz = std::mem::size_of::<ProbeSSLDataT>();

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder
        .add(&skel.maps.rb, move |data: &[u8]| {
            if data.len() < min_event_sz {
                return 0;
            }
            // SAFETY: eBPF side guarantees the layout and alignment.
            let event = unsafe { &*(data.as_ptr() as *const ProbeSSLDataT) };
            if event.is_handshake != 0 {
                if handshake {
                    print_event(event, filter_comm.as_deref());
                }
            } else {
                print_event(event, filter_comm.as_deref());
            }
            0
        })
        .context("failed to add ring buffer map")?;

    let rb = rb_builder.build().context("failed to build ring buffer")?;

    // ── Poll loop ──────────────────────────────────────────────────────────
    let timeout = Duration::from_millis(PERF_POLL_TIMEOUT_MS);
    while !exiting.load(Ordering::Relaxed) {
        match rb.poll(timeout) {
            Ok(_) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
            Err(e) => {
                eprintln!("error polling ring buffer: {e}");
                break;
            }
        }
    }

    // _links and skel are dropped here, cleanly detaching all probes.
    Ok(())
}
