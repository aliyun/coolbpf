use crate::is_system_profiling;
use crate::process::maps::ProcessMaps;

use super::event::ProbeEvent;
use super::event::RawStack;
use super::event::RawUserStack;
use super::interpreter_offset::InterpreterOffsetMap;
use super::nspid::NsPidMap;
use super::pid_maps_info::PidMapsInfoMap;
use super::stack::StackMap;
use super::stack_delta::create_inner_map;
use super::stack_delta::StackDeltaMap;
use super::stack_delta::StackDeltaPageMap;
use super::system_config::get_system_config;
use super::types::any_as_u8_slice;
use super::types::bpf;
use super::types::bpf::TracePrograms_PROG_UNWIND_HOTSPOT;
use super::types::bpf::TracePrograms_PROG_UNWIND_NATIVE;
use super::types::bpf::TracePrograms_PROG_UNWIND_PYTHON;
use super::types::bpf::TracePrograms_PROG_UNWIND_STOP;
use super::types::bpf::STACK_DELTA_COMMAND_FLAG;
use super::types::bpf::UNWIND_OPCODE_COMMAND;
use super::types::SystemAnalysis;
use super::types::{self};
use super::unwind_info::UnwindInfo;
use super::unwind_info::UnwindInfoMap;
use anyhow::bail;
use anyhow::Result;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use libbpf_rs::libbpf_sys;
use libbpf_rs::num_possible_cpus;
use libbpf_rs::skel::*;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Link;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::MapType;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::UprobeOpts;
use once_cell::sync::Lazy;
use perf_event_open_sys::bindings::perf_event_attr;
use perf_event_open_sys::bindings::PERF_COUNT_SW_CPU_CLOCK;
use perf_event_open_sys::bindings::PERF_FLAG_FD_CLOEXEC;
use perf_event_open_sys::bindings::PERF_TYPE_SOFTWARE;
use perf_event_open_sys::perf_event_open;
use std::collections::HashMap;
use std::env::current_exe;
use std::ffi::CString;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::panicking;
use std::thread::JoinHandle;

mod native {
    include!(concat!(env!("OUT_DIR"), "/native_stack.skel.rs"));
}

mod system_config {
    include!(concat!(env!("OUT_DIR"), "/system_config.skel.rs"));
}

mod dispatcher {
    include!(concat!(env!("OUT_DIR"), "/interpreter_dispatcher.skel.rs"));
}

mod hotspot {
    include!(concat!(env!("OUT_DIR"), "/hotspot.skel.rs"));
}

mod sched {
    include!(concat!(env!("OUT_DIR"), "/sched_monitor.skel.rs"));
}

mod nspid_pid {
    include!(concat!(env!("OUT_DIR"), "/nspid_pid.skel.rs"));
}

mod python {
    include!(concat!(env!("OUT_DIR"), "/python.skel.rs"));
}

/// Handling Perf buffer loss events
pub fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

pub static SYSAK_BTF_PATH: Lazy<Option<CString>> = Lazy::new(|| {
    if let Ok(sysak) = std::env::var("SYSAK_WORK_PATH") {
        if let Ok(info) = uname::uname() {
            if info.release.starts_with("5.10") {
                return None;
            }
            return Some(
                CString::new(format!("{}/tools/vmlinux-{}", sysak, info.release)).unwrap(),
            );
        }
    }
    None
});

macro_rules! btf_path_ptr_macro {
    () => {{
        SYSAK_BTF_PATH
            .as_ref()
            .map_or(std::ptr::null(), |x| x.as_ptr())
    }};
}

macro_rules! load_skel {
    ($maps: ident, $skel: path) => {{
        use $skel as builder;
        let mut builder = builder::default();
        if log::log_enabled!(log::Level::Debug) {
            builder.obj_builder.debug(true);
        } else {
            builder.obj_builder.debug(false);
        }
        let mut opts = builder.obj_builder.opts().clone();
        opts.btf_custom_path = btf_path_ptr_macro!();
        let mut openskel = builder.open_opts(opts).unwrap();
        for (name, map) in &$maps {
            if let Some(target_map) = openskel.obj.map_mut(name) {
                target_map.reuse_fd(map.as_fd()).unwrap();
            }
        }
        openskel.load().unwrap()
    }};
}

static THREAD_NEED_EXIT: AtomicBool = AtomicBool::new(false);

fn thread_need_exit() -> bool {
    THREAD_NEED_EXIT.load(Ordering::SeqCst)
}

fn reset_thread_need_exit() {
    THREAD_NEED_EXIT.store(false, Ordering::SeqCst);
}

fn set_thread_need_exit() {
    THREAD_NEED_EXIT.store(true, Ordering::SeqCst);
}

fn get_self_path() -> PathBuf {
    let pid = unsafe { libc::getpid() };
    let pm = ProcessMaps::new(pid as u32).unwrap();
    if let Some(p) = pm.find_so("libmullprof.so") {
        return PathBuf::from(p);
    }

    if let Some(p) = pm.find_so("libnofp.so") {
        return PathBuf::from(p);
    }

    current_exe().expect("failed to find executable name")
}

#[inline(never)]
#[no_mangle]
extern "C" fn get_hostpid(nspid: u32, map: &NsPidMap) -> u32 {
    map.lookup(nspid).unwrap().unwrap()
}

pub struct Probes<'a> {
    skel: native::NativeStackSkel<'a>,
    sched_skel: sched::SchedMonitorSkel<'a>,
    pub hotspot_skel: hotspot::HotspotSkel<'a>,
    pub python_skel: python::PythonSkel<'a>,
    interpreter_dispatcher_skel: dispatcher::InterpreterDispatcherSkel<'a>,
    links: Vec<Link>,
    pub rx: Receiver<ProbeEvent>,
    pub pid_maps_info_map: PidMapsInfoMap,
    pub stack_delta_map: StackDeltaMap,
    pub stack_delta_page_map: StackDeltaPageMap,
    pub unwind_info_map: UnwindInfoMap,
    pub unwind_info_cache: HashMap<UnwindInfo, u16>,
    pub stack_map: StackMap,
    pub interpreter_offset_map: InterpreterOffsetMap,
    has_generic_batchop: bool,

    pid: u32,
    nspid: u32,

    trace_thread_handle: Option<JoinHandle<()>>,
    report_thread_handle: Option<JoinHandle<()>>,
}

impl<'a> Probes<'a> {
    pub fn new() -> Self {
        reset_thread_need_exit();
        let has_generic_batchop = probe_has_generic_batch_ops();
        let mut builder = native::NativeStackSkelBuilder::default();
        if log::log_enabled!(log::Level::Debug) {
            builder.obj_builder.debug(true);
        } else {
            builder.obj_builder.debug(false);
        }
        let mut opts = builder.obj_builder.opts().clone();
        opts.btf_custom_path = btf_path_ptr_macro!();
        let mut openskel = builder.open_opts(opts).unwrap();

        let mut inners = vec![];
        for i in
            types::bpf::STACK_DELTA_BUCKET_SMALLEST..(types::bpf::STACK_DELTA_BUCKET_LARGEST + 1)
        {
            let inner = create_inner_map(i).unwrap();
            let map = openskel
                .obj
                .map_mut(&format!("exe_id_to_{}_stack_deltas", i))
                .unwrap();
            let obj = map.as_libbpf_object();
            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map__set_inner_map_fd(
                    obj.as_ptr(),
                    inner.as_fd().as_raw_fd(),
                )
            };

            if ret < 0 {
                panic!("failed to set inner map");
            }

            inners.push(inner);
        }

        let mut skel = openskel
            .load()
            .expect("failed to load bpf program, please check btf if exists");
        let mut maps: HashMap<String, MapHandle> = HashMap::default();

        for map in skel.obj.maps_iter() {
            maps.insert(map.name().to_owned(), MapHandle::try_clone(map).unwrap());
        }

        let unwind_info_map =
            UnwindInfoMap::new(MapHandle::try_clone(skel.maps().unwind_info_array()).unwrap());

        let pid_maps_info_map = PidMapsInfoMap::new(
            MapHandle::try_clone(skel.maps().pid_page_to_mapping_info()).unwrap(),
        );

        let stack_delta_page_map = StackDeltaPageMap::new(
            MapHandle::try_clone(skel.maps().stack_delta_page_to_info()).unwrap(),
        );

        let mut exeid2stack_maps = vec![];
        for i in
            types::bpf::STACK_DELTA_BUCKET_SMALLEST..(types::bpf::STACK_DELTA_BUCKET_LARGEST + 1)
        {
            let map = skel
                .obj
                .map_mut(&format!("exe_id_to_{}_stack_deltas", i))
                .unwrap();
            exeid2stack_maps.push(MapHandle::try_clone(map).unwrap());
        }
        let stack_delta_map = StackDeltaMap::new(exeid2stack_maps, has_generic_batchop);

        let mut system_config_skel = load_skel!(maps, system_config::SystemConfigSkelBuilder);
        let interpreter_dispatcher_skel =
            load_skel!(maps, dispatcher::InterpreterDispatcherSkelBuilder);
        let hotspot_skel = load_skel!(maps, hotspot::HotspotSkelBuilder);
        let python_skel = load_skel!(maps, python::PythonSkelBuilder);

        let (tx, rx) = crossbeam_channel::unbounded();

        let trace_thread_handle = {
            let mut cloned_tx = tx.clone();
            let stack_map =
                StackMap::new(MapHandle::try_clone(skel.maps().kernel_stackmap()).unwrap());
            let handle_event = move |cpu: i32, data: &[u8]| {
                thread_poll_trace_event(&stack_map, &mut cloned_tx, cpu, data);
            };

            let perf = PerfBufferBuilder::new(&skel.maps_mut().trace_events())
                .sample_cb(handle_event)
                .lost_cb(handle_lost_events)
                .build()
                .unwrap();

            std::thread::Builder::new()
                .name("profiler-trace".into())
                .spawn(move || {
                    log::debug!("start trace event polling thread");
                    loop {
                        perf.consume().unwrap();
                        if thread_need_exit() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                })
                .unwrap()
        };

        let sched_skel = load_skel!(maps, sched::SchedMonitorSkelBuilder);
        let report_thread_handle = {
            let mut cloned_tx = tx.clone();
            let handle_event = move |cpu: i32, data: &[u8]| {
                thread_poll_report_event(&mut cloned_tx, cpu, data);
            };

            let perf = PerfBufferBuilder::new(&skel.maps_mut().report_events())
                .sample_cb(handle_event)
                .lost_cb(handle_lost_events)
                .pages(8)
                .build()
                .unwrap();

            std::thread::Builder::new()
                .name("profiler-report".into())
                .spawn(move || {
                    log::debug!("start report event polling thread");
                    loop {
                        perf.poll(std::time::Duration::from_millis(200)).unwrap();
                        if thread_need_exit() {
                            break;
                        }
                    }
                })
                .unwrap()
        };

        let mut nspid_skel = load_skel!(maps, nspid_pid::NspidPidSkelBuilder);
        let nspid_map =
            NsPidMap::new(MapHandle::try_clone(&nspid_skel.maps().nspid_pid()).unwrap());

        let nspid = unsafe { libc::getpid() };
        let path = get_self_path();
        let func_offset = 0;
        let opts = UprobeOpts {
            func_name: "get_hostpid".to_string(),
            ..Default::default()
        };
        let _link = nspid_skel
            .progs_mut()
            .uprobe_get_hostpid()
            .attach_uprobe_with_opts(-1, path, func_offset, opts)
            .expect("failed to attach uprobe `get_hostpid` prog");

        let pid = get_hostpid(nspid as u32, &nspid_map);

        log::debug!("nspid: {nspid}, hostpid: {pid}");
        let mut probe = Self {
            stack_map: StackMap::new(MapHandle::try_clone(skel.maps().kernel_stackmap()).unwrap()),
            interpreter_offset_map: InterpreterOffsetMap::new(
                MapHandle::try_clone(skel.maps().interpreter_offsets()).unwrap(),
            ),

            skel,
            sched_skel,
            hotspot_skel,
            python_skel,
            interpreter_dispatcher_skel,
            links: vec![],
            rx,
            unwind_info_map,
            stack_delta_map,
            stack_delta_page_map,
            pid_maps_info_map,
            unwind_info_cache: Default::default(),
            has_generic_batchop,

            pid,
            nspid: nspid as u32,
            trace_thread_handle: Some(trace_thread_handle),
            report_thread_handle: Some(report_thread_handle),
        };

        if probe.pid != probe.nspid && is_system_profiling() {
            panic!("System-level profiling in pid namespace is not supported!!!");
        }

        probe.load_system_config(system_config_skel);
        probe.attach_sched_monitor();
        probe.load_unwinders();
        let ms = profile_period() as u64;
        probe.attach_perf_event(ms * 1000000);
        probe
    }

    fn attach_sched_monitor(&mut self) {
        self.sched_skel.attach().unwrap();
    }

    fn attach_perf_event(&mut self, sample_period: u64) {
        let cpus = num_possible_cpus().unwrap();

        for i in 0..cpus {
            let mut attrs = perf_event_attr::default();
            attrs.size = std::mem::size_of::<perf_event_attr>() as u32;
            attrs.config = PERF_COUNT_SW_CPU_CLOCK as u64;
            attrs.type_ = PERF_TYPE_SOFTWARE;
            attrs.set_freq(0);
            attrs.__bindgen_anon_1.sample_period = sample_period;

            let pfd = unsafe {
                perf_event_open(&mut attrs, -1, i as i32, -1, PERF_FLAG_FD_CLOEXEC as u64)
            };

            if pfd <= 0 {
                log::error!("failed to create perf event on cpu: {}", i);
                continue;
            }

            let link = self
                .skel
                .progs_mut()
                .native_tracer_entry()
                .attach_perf_event(pfd)
                .unwrap();
            self.links.push(link);
        }
    }

    fn load_system_config(&mut self, mut system_config_skel: system_config::SystemConfigSkel) {
        let _link = system_config_skel
            .progs_mut()
            .read_task_struct()
            .attach()
            .unwrap();
        let mut sc = get_system_config();
        let key: u32 = 0;
        let mut value = SystemAnalysis::default();
        value.set_pid(self.pid);
        value.set_address(sc.task_stack_offset as u64);
        system_config_skel
            .maps_mut()
            .system_analysis()
            .update(&key.to_ne_bytes(), value.slice(), MapFlags::ANY)
            .unwrap();

        let value = system_config_skel
            .maps_mut()
            .system_analysis()
            .lookup(&key.to_ne_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();

        let ret_value = SystemAnalysis::from(value);
        assert!(ret_value.raw.pid == 0);
        sc.set_stack_ptregs_offset((ret_value.raw.address - ret_value.code_u64()) as u32);
        sc.set_has_pid_namespace(self.pid != self.nspid);

        system_config_skel
            .maps_mut()
            .system_config()
            .update(&key.to_ne_bytes(), sc.slice(), MapFlags::ANY)
            .unwrap();
    }

    pub fn recv(&self) -> ProbeEvent {
        self.rx.recv().unwrap()
    }

    pub fn get_unwind_info_index(&mut self, info: &UnwindInfo) -> Result<u16> {
        if info.raw.opcode == UNWIND_OPCODE_COMMAND as u8 {
            return Ok(info.raw.param as u16 | STACK_DELTA_COMMAND_FLAG as u16);
        }

        if let Some(&idx) = self.unwind_info_cache.get(&info) {
            return Ok(idx);
        }

        let idx = self.unwind_info_cache.len() as u16;
        self.unwind_info_map.update(idx as u32, info)?;
        self.unwind_info_cache.insert(info.clone(), idx);
        Ok(idx)
    }

    pub fn load_unwinders(&mut self) {
        let fd = self
            .interpreter_dispatcher_skel
            .progs()
            .unwind_stop()
            .as_fd()
            .as_raw_fd();
        self.skel
            .maps_mut()
            .progs()
            .update(
                &TracePrograms_PROG_UNWIND_STOP.to_ne_bytes(),
                &fd.to_ne_bytes(),
                MapFlags::ANY,
            )
            .unwrap();

        let fd = self.skel.progs().unwind_native().as_fd().as_raw_fd();
        self.skel
            .maps_mut()
            .progs()
            .update(
                &TracePrograms_PROG_UNWIND_NATIVE.to_ne_bytes(),
                &fd.to_ne_bytes(),
                MapFlags::ANY,
            )
            .unwrap();
        let fd = self
            .hotspot_skel
            .progs()
            .unwind_hotspot()
            .as_fd()
            .as_raw_fd();
        self.skel
            .maps_mut()
            .progs()
            .update(
                &TracePrograms_PROG_UNWIND_HOTSPOT.to_ne_bytes(),
                &fd.to_ne_bytes(),
                MapFlags::ANY,
            )
            .unwrap();
        let fd = self.python_skel.progs().unwind_python().as_fd().as_raw_fd();
        self.skel
            .maps_mut()
            .progs()
            .update(
                &TracePrograms_PROG_UNWIND_PYTHON.to_ne_bytes(),
                &fd.to_ne_bytes(),
                MapFlags::ANY,
            )
            .unwrap();
    }
}

impl<'a> Drop for Probes<'a> {
    fn drop(&mut self) {
        set_thread_need_exit();
        if let Some(thread) = self.trace_thread_handle.take() {
            thread.join().unwrap();
        }

        if let Some(thread) = self.report_thread_handle.take() {
            thread.join().unwrap();
        }
    }
}

fn thread_poll_report_event(tx: &mut Sender<ProbeEvent>, _cpu: i32, data: &[u8]) {
    let raw = data.as_ptr() as *const bpf::Event;
    let ty = unsafe { (*raw).event_type };
    match ty {
        bpf::EVENT_TYPE_PROCESS_EXIT => {
            let pid = unsafe { (*raw).pid };
            let _ = tx.send(ProbeEvent::ProcessExit(pid));
        }
        _ => {}
    }
}

fn thread_poll_trace_event(map: &StackMap, tx: &mut Sender<ProbeEvent>, _cpu: i32, data: &[u8]) {
    let raw = data.as_ptr() as *const bpf::Trace;
    let rs = unsafe {
        let stack_len = (*raw).stack_len as usize;
        let pid = (*raw).pid;
        let kernel_stackid = (*raw).kernel_stack_id;
        let user_stackid = (*raw).user_stack_id;

        let user_stack = if user_stackid == i32::MAX {
            RawUserStack::Native((*raw).__bindgen_anon_1.user_stack[..stack_len].to_vec())
        } else {
            RawUserStack::Dynamic((*raw).__bindgen_anon_1.frames[..stack_len].to_vec())
        };

        let kernel_stack = if kernel_stackid >= 0 {
            map.lookup(kernel_stackid)
        } else {
            vec![]
        };

        RawStack {
            pid,
            kernel: kernel_stack,
            user: user_stack,
        }
    };
    let _ = tx.send(ProbeEvent::Trace(rs));
}

fn probe_has_batch_ops(map_type: MapType) -> bool {
    // Create a map for iteration test.
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    let entries = 4;
    match libbpf_rs::MapHandle::create::<&str>(map_type, None, 4, 4, entries, &opts) {
        Ok(map) => {
            let mut keys = vec![];
            let mut vals = vec![];
            for i in 0..entries {
                keys.extend(i.to_ne_bytes());
                vals.extend(i.to_ne_bytes());
            }
            let ret = map.update_batch(&keys, &vals, entries, MapFlags::ANY, MapFlags::ANY);
            ret.is_ok()
        }
        Err(_e) => false,
    }
}

fn probe_has_generic_batch_ops() -> bool {
    probe_has_batch_ops(MapType::Hash)
}

fn profile_period() -> u32 {
    match std::env::var("PROFILE_PERIOD_MS") {
        Ok(value) => {
            let period = match u32::from_str(&value) {
                Ok(num) => num,
                Err(_) => 50,
            };
            period
        }
        Err(_) => 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_threads_exit() {
        loop {
            let mut probe = Probes::new();
            drop(probe);
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
