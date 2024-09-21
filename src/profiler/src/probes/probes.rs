use super::event::ProbeEvent;
use super::event::RawStack;
use super::event::RawUserStack;
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
use perf_event_open_sys::bindings::perf_event_attr;
use perf_event_open_sys::bindings::PERF_COUNT_SW_CPU_CLOCK;
use perf_event_open_sys::bindings::PERF_FLAG_FD_CLOEXEC;
use perf_event_open_sys::bindings::PERF_TYPE_SOFTWARE;
use perf_event_open_sys::perf_event_open;
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

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

/// Handling Perf buffer loss events
pub fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

macro_rules! load_skel {
    ($maps: ident, $skel: path) => {{
        use $skel as builder;
        let mut builder = builder::default();
        builder.obj_builder.debug(true);
        let mut openskel = builder.open().unwrap();
        for (name, map) in &$maps {
            if let Some(target_map) = openskel.obj.map_mut(name) {
                target_map.reuse_fd(map.as_fd()).unwrap();
            }
        }
        openskel.load().unwrap()
    }};
}

pub struct Probes<'a> {
    skel: native::NativeStackSkel<'a>,
    pub hotspot_skel: hotspot::HotspotSkel<'a>,
    interpreter_dispatcher_skel: dispatcher::InterpreterDispatcherSkel<'a>,
    links: Vec<Link>,
    pub rx: Receiver<ProbeEvent>,
    pub pid_maps_info_map: PidMapsInfoMap,
    pub stack_delta_map: StackDeltaMap,
    pub stack_delta_page_map: StackDeltaPageMap,
    pub unwind_info_map: UnwindInfoMap,
    pub unwind_info_cache: HashMap<UnwindInfo, u16>,
    pub stack_map: StackMap,
    has_generic_batchop: bool,
}

impl<'a> Probes<'a> {
    pub fn new() -> Self {
        let has_generic_batchop = probe_has_generic_batch_ops();
        let mut builder = native::NativeStackSkelBuilder::default();
        builder.obj_builder.debug(false);
        let mut openskel = builder.open().unwrap();

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

        let mut skel = openskel.load().unwrap();
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

        let (tx, rx) = crossbeam_channel::unbounded();
        {
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

            std::thread::spawn(move || {
                log::debug!("start trace event polling thread");
                loop {
                    perf.consume().unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            });
        }

        let mut probe = Self {
            stack_map: StackMap::new(MapHandle::try_clone(skel.maps().kernel_stackmap()).unwrap()),
            skel,
            hotspot_skel,
            interpreter_dispatcher_skel,
            links: vec![],
            rx,
            unwind_info_map,
            stack_delta_map,
            stack_delta_page_map,
            pid_maps_info_map,
            unwind_info_cache: Default::default(),
            has_generic_batchop,
        };
        probe.load_system_config(system_config_skel);
        probe.load_unwinders();
        probe.attach_perf_event(10000000);
        probe
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
        value.set_pid(unsafe { libc::getpid() as u32 });
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
    tx.send(ProbeEvent::Trace(rs)).unwrap();
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
