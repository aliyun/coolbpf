#[path = "bpf/.output/example.skel.rs"]
mod exampleskel;
use exampleskel::*;

#[path = "bpf/.output/bindings.rs"]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings;
use bindings::*;
use anyhow::{bail, Result};
use libbpf_rs::PerfBufferBuilder;
use structopt::StructOpt;
use std::fmt;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, StructOpt)]
struct Command {
    /// Verbose debug output
    #[structopt(short, long)]
    verbose: bool,
}

struct Example {
    data: Vec<u8>,
    ptr: *const example,
}

impl Example {
    pub fn new(data: Vec<u8>) -> Example {
        Example {
            ptr: &data[0] as *const u8 as *const example,
            data,
        }
    }

    pub fn pid(&self) -> i32 {
        unsafe { (*self.ptr).pid }
    }

    pub fn comm(&self) -> String {
        unsafe { String::from_utf8_unchecked((*self.ptr).comm.to_vec()) }
    }

    pub fn addr_pair(&self) -> (SocketAddr, SocketAddr) {
        let daddr = unsafe { (*self.ptr).daddr };
        let dport = unsafe { (*self.ptr).dport };
        let saddr = unsafe { (*self.ptr).saddr };
        let sport = unsafe { (*self.ptr).sport };
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(saddr))), sport);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(daddr))), dport);
        (src, dst)
    }
}

impl fmt::Display for Example {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ap = self.addr_pair();
        write!(f, "(PID){}:{} (LOCAL){} -> (REMOTE){}", self.pid(), self.comm(), ap.0, ap.1,)
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let example = Example::new(Vec::from(data));
    println!("{}", example);
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()>{
    let opts = Command::from_args();
    let mut skel_builder = ExampleSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;
    skel.attach()?;
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
