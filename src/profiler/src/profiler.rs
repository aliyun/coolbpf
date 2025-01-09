use crate::executable::ExecutableCache;
use crate::interpreter::Interpreter;
use crate::is_enable_symbolizer;
use crate::is_system_profiling;
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
use crate::utils::lpm::Prefix;
use crate::MIN_PROCESS_SAMPLES;
use crate::SYSTEM_PROFILING;
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

    all_system_profiling: bool,
    enable_symbolizer: bool,
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
            all_system_profiling: is_system_profiling(),
            enable_symbolizer: is_enable_symbolizer(),
        }
    }

    pub fn poll(&mut self) {
        loop {
            match self.probes.recv() {
                ProbeEvent::Trace(data) => {
                    let stack =
                        Stack::new(&mut self.symbolizer, &data, &mut self.interpreters, 1).unwrap();
                    if !stack.empty() {
                        // println!("raw: {:?}", data);
                        println!("stack: {}", stack.to_string());
                    }
                }

                ProbeEvent::ProcessExit(pid) => {}
            }
        }
    }

    pub fn read(&mut self) -> Vec<SymbolizedStack> {
        let mut stack_agg = StackAggregator::default();
        let mut exited_pids = vec![];
        loop {
            match self.probes.rx.try_recv() {
                Ok(event) => match event {
                    ProbeEvent::Trace(data) => stack_agg.add(data),
                    ProbeEvent::ProcessExit(pid) => exited_pids.push(pid),
                },
                Err(_e) => break,
            }
        }

        if self.all_system_profiling {
            stack_agg.filter(MIN_PROCESS_SAMPLES);
        }
        let stacks = stack_agg.symbolize(&mut self.symbolizer, &mut self.interpreters);

        for pid in exited_pids {
            let _ = self.process_exit(pid);
        }
        stacks
    }

    pub fn read2(&mut self) -> Vec<u8> {
        let mut stack_agg = StackAggregator::default();
        let mut exited_pids = vec![];
        loop {
            match self.probes.rx.try_recv() {
                Ok(event) => match event {
                    ProbeEvent::Trace(data) => stack_agg.add(data),
                    ProbeEvent::ProcessExit(pid) => exited_pids.push(pid),
                },
                Err(_e) => break,
            }
        }
        let ret = stack_agg.serialize(&mut self.symbolizer, &mut self.interpreters);
        for pid in exited_pids {
            let _ = self.process_exit(pid);
        }
        ret
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
                    self.process_exit(pid);
                } else {
                    self.sync_maps(pid, &maps)?;
                }
            }
            Err(e) => {
                self.process_exit(pid);
                log::error!("failed to open /proc/{pid}/maps: {e}")
            }
        }

        Ok(())
    }

    pub fn process_exit(&mut self, pid: u32) -> Result<()> {
        self.probes
            .pid_maps_info_map
            .delete(pid, &vec![Prefix::dummy()])?;
        if let Some(mut proc) = self.pids.remove(&pid) {
            proc.exit(&mut self.probes, &mut self.executables)?;
        }

        if let Some(mut int) = self.interpreters.remove(&pid) {
            int.exit(&mut self.probes)?;
        }

        Ok(())
    }

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
        proc.remove_maps_entries(&mut self.probes, &mut self.executables, &removed)?;

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

            let va = match info.file_offset_to_virtual_address(map.offset) {
                Some(x) => x,
                None => {
                    log::warn!("executable program headers not found, skip it");
                    continue;
                }
            };
            let bias = map.start - va;
            let exe = match self
                .executables
                .get_or_insert(&mut self.probes, info, map, bias)
            {
                Ok(Some(a)) => a,
                Ok(None) | Err(_) => continue,
            };
            if self.enable_symbolizer {
                let mmap_ref = unsafe { memmap2::Mmap::map(&info.file)? };
                let object = object::File::parse(&*mmap_ref).expect("failed to parse elf file");
                self.symbolizer.add_file(info.file_id, object, bias);
            } else {
                self.symbolizer.bias_cache.insert(info.file_id, bias);
            }

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

            if let Some(tsd) = &exe.tsd_info {
                proc.tsd_info = Some(tsd.clone());
                self.interpreters.entry(proc.pid).and_modify(|x| {
                    x.update_tsd_info(&self.probes, proc.pid(), tsd.clone())
                        .unwrap();
                });
            }

            if let Some(i_info) = &exe.i_info {
                let mut instance = Interpreter::parse(i_info, proc, bias)?;
                if let Some(tsd) = &proc.tsd_info {
                    instance.update_tsd_info(&self.probes, proc.pid(), tsd.clone())?;
                }

                if let Ok(mut instance) = Interpreter::parse(i_info, proc, bias) {
                    instance.sync_maps(&mut self.probes).unwrap();
                    self.interpreters.insert(proc.pid, instance);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_exit() {
        let mut prof = Profiler::new();
        prof.sync_process(1).unwrap();
        prof.process_exit(1).unwrap();

        assert!(prof.pids.is_empty());
        assert!(prof.executables.executables.is_empty());
        assert!(prof.interpreters.is_empty());

        assert!(prof.probes.pid_maps_info_map.is_empty());
        assert!(prof.probes.stack_delta_page_map.is_empty());
        assert!(prof.probes.stack_delta_map.is_empty());
    }


    #[test]
    fn test_java_process_exit() {
        let mut prof = Profiler::new();
        prof.sync_process(1158).unwrap();
        prof.process_exit(1158).unwrap();

        assert!(prof.pids.is_empty());
        assert!(prof.executables.executables.is_empty());
        assert!(prof.interpreters.is_empty());

        assert!(prof.probes.pid_maps_info_map.is_empty());
        assert!(prof.probes.stack_delta_page_map.is_empty());
        assert!(prof.probes.stack_delta_map.is_empty());

        // test eBPF map of java
        assert!(prof.interpreters.is_empty());
        assert!(prof.probes.pid_maps_info_map.is_empty());
        assert!(prof.probes.hotspot_skel.maps().hotspot_procs().keys().next().is_none());
    }
}
