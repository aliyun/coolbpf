use crate::executable::ExecutableCache;
use crate::interpreter::Interpreter;
use crate::probes::event::ProbeEvent;
use crate::probes::probes::Probes;
use crate::process::maps::ExeMapsEntry;
use crate::process::maps::ProcessMaps;
use crate::process::process::Process;
use crate::stack::Stack;
use crate::stack::StackAggregator;
use crate::stack::SymbolizedStack;
use crate::symbollizer::file_cache::FileCache;
use crate::symbollizer::symbolizer::Symbolizer;
use crate::MIN_PROCESS_SAMPLES;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

pub struct Profiler<'a> {
    pids: HashMap<u32, Process>,
    probes: Probes<'a>,
    caches: FileCache,
    executables: ExecutableCache,
    symbolizer: Symbolizer,
    interpreters: HashMap<u32, Interpreter>,
}

impl<'a> Profiler<'a> {
    pub fn new() -> Self {
        let mut symer = Symbolizer::new();
        symer.add_kernel("/proc/kallsyms");
        Profiler {
            pids: HashMap::new(),
            probes: Probes::new(),
            caches: FileCache::new(),
            executables: ExecutableCache::default(),
            symbolizer: symer,
            interpreters: HashMap::new(),
        }
    }

    pub fn poll(&mut self) {
        loop {
            match self.probes.recv() {
                ProbeEvent::Trace(data) => {
                    let stack =
                        Stack::new(&mut self.symbolizer, &data, &mut self.interpreters, 1).unwrap();
                    if !stack.empty() {
                        println!("{}", stack.to_string());
                    }
                }
            }
        }
    }

    pub fn read(&mut self) -> Vec<SymbolizedStack> {
        let mut stack_agg = StackAggregator::default();
        loop {
            match self.probes.rx.try_recv() {
                Ok(ProbeEvent::Trace(data)) => {
                    stack_agg.add(data);
                }
                Err(_e) => break,
            }
        }
        stack_agg.filter(MIN_PROCESS_SAMPLES);
        let stacks = stack_agg.symbolize(&mut self.symbolizer, &mut self.interpreters);
        stacks
    }

    pub fn populate_pids(&mut self, pids: Vec<u32>) -> Result<()> {
        let start = Instant::now();
        for pid in pids {
            let ret = self.sync_process(pid);
            log::debug!("populate pid: {pid}, result: {:?}", ret);
        }
        log::info!("populate all processes time: {:?}", start.elapsed());
        Ok(())
    }

    fn sync_process(&mut self, pid: u32) -> Result<()> {
        log::debug!("sync process pid: {pid}");
        match ProcessMaps::new(pid) {
            Ok(maps) => {
                if maps.is_empty() {
                    log::warn!("/proc/{pid}/maps is empty or no permission");
                    self.process_exit();
                } else {
                    self.sync_maps(pid, &maps)?;
                }
            }
            Err(e) => {
                self.process_exit();
                log::error!("failed to open /proc/{pid}/maps: {e}")
            }
        }

        Ok(())
    }

    fn process_exit(&mut self) {}

    fn sync_maps(&mut self, pid: u32, maps: &ProcessMaps) -> Result<()> {
        // 同步进程的地址映射信息
        let mut proc = self.pids.entry(pid).or_insert_with(|| {
            let mut proc = Process::default();
            proc.pid = pid;
            self.probes.pid_maps_info_map.insert_dummy(pid);
            proc
        });

        let mut added: Vec<u64> = vec![];
        let mut removed = vec![];

        // 1. 计算新添加的maps entry
        for (k, v) in maps.iter() {
            if v.is_anonymous() || !v.is_executable() {
                continue;
            }
            match proc.maps.get(k) {
                Some(exe_map) => {
                    if v.device == exe_map.device
                        && v.inode == exe_map.inode
                        && v.offset == exe_map.offset
                        && v.end - v.start == exe_map.length
                    {
                        // do nothing;
                    } else {
                        // maps entry有更新
                        added.push(*k);
                        removed.push(*k);
                    }
                }
                None => {
                    // 键不在 self.entries 中，视为新增
                    added.push(*k);
                }
            }
        }

        // 2. 计算被删除的maps entry
        for key in proc.maps.keys() {
            // 最新的maps里面不包含该地址
            if !maps.contains_key(key) {
                removed.push(*key);
            }
        }

        // 1. 从进程中删除已经被删除/更新的映射
        // 2. 删除eBPF map pid_page_to_mapping_info 中该进程的映射关系
        proc.remove_maps_entries(&mut self.probes, &removed)?;

        for add in added {
            let map = maps.get(&add).unwrap();
            if map.inode == 0 && !map.is_vdso() {
                continue;
            }

            log::debug!("handle new maps entry: {}", map);
            let info = match self.caches.get_or_insert(pid, &map) {
                Ok(x) => x,
                Err(e) => {
                    log::warn!("failed to parse file: {:?}, err: {e}", map);
                    continue;
                }
            };

            let va = info.file_offset_to_virtual_address(map.offset).unwrap();
            let exe = self
                .executables
                .get_or_insert(&mut self.probes, info, map)?
                .unwrap();
            let bias = map.start - va;
            self.symbolizer
                .add_file(info.file_id, info.elf.object_file());

            // 计算该maps对应的
            let exe_map = ExeMapsEntry {
                file_id: info.file_id,
                vaddr: map.start,
                offset: map.offset,
                bias,
                length: map.end - map.start,
                device: map.device,
                inode: map.inode,
            };
            proc.add_maps_entry(info, &mut self.probes, exe_map)?;

            if let Some(i_info) = &mut exe.i_info {
                let mut instance = Interpreter::parse(i_info, proc, bias)?;
                instance.sync_maps(&mut self.probes).unwrap();
                self.interpreters.insert(proc.pid, instance);
            }
        }
        Ok(())
    }
}
