/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

use super::demangle::demangle_java_method2;
use super::file_info::HotspotFileInfo;
use super::file_info::HotspotVmInfo;
use super::method::HotspotJITInfo;
use super::method::HotspotMethod;
use super::read_recorder::ReadRecorder;
use super::stubs::find_stub_bounds;
use super::stubs::StubRoutine;
use super::unsigned5::Unsigned5Decoder;
use crate::interpreter::hotspot::demangle::demangle_java_method;
use crate::probes::probes::Probes;
use crate::probes::types::bpf::Frame;
use crate::probes::types::bpf::TracePrograms_PROG_UNWIND_HOTSPOT;
use crate::probes::types::bpf::FRAME_HOTSPOT_INTERPRETER;
use crate::probes::types::bpf::FRAME_HOTSPOT_NATIVE;
use crate::probes::types::bpf::FRAME_HOTSPOT_STUB;
use crate::probes::types::bpf::FRAME_HOTSPOT_VTABLE;
use crate::probes::types::bpf::FRAME_MARKER_HOTSPOT;
use crate::probes::types::bpf::HS_TSID_SEG_MAP_BIT;
use crate::probes::types::bpf::HS_TSID_SEG_MAP_MASK;
use crate::probes::types::HotspotProcInfo;
use crate::process::memory::ProcessMemory;
use crate::process::process::Process;
use crate::stack::Stack;
use crate::symbollizer::file_id::FileId64;
use crate::symbollizer::symbolizer::Symbol;
use crate::utils::lpm::calculate_prefixes;
use crate::utils::lpm::Prefix;
use crate::utils::safe_reader::SafeReader;
use anyhow::bail;
use anyhow::Result;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use libbpf_rs::MapFlags;
use lru::LruCache;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::num::NonZeroUsize;
use std::rc::Rc;

pub struct HotspotInstance {
    pub info: Rc<HotspotFileInfo>,
    pub vm: Rc<HotspotVmInfo>,
    pm: ProcessMemory,

    bias: u64,

    addr_symbol: LruCache<u64, String>,
    addr_method: LruCache<u64, HotspotMethod>,
    addr_jitinfo: LruCache<u64, HotspotJITInfo>,
    addr_stub_name: LruCache<u64, String>,

    heap_areas: Vec<JitArea>,

    prefixes: HashSet<Prefix>,
    pid: u32,

    stubs: HashMap<u64, StubRoutine>,
    verbose: bool,
}

impl HotspotInstance {
    pub fn new(info: Rc<HotspotFileInfo>, proc: &Process, bias: u64) -> Result<Self> {
        let pm = proc.memory()?;
        Ok(HotspotInstance {
            vm: Rc::new(HotspotVmInfo::new(&info, &pm, bias)?),
            info,
            pm,
            bias,
            addr_symbol: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            addr_method: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            addr_jitinfo: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            addr_stub_name: LruCache::new(NonZeroUsize::new(128).unwrap()),

            prefixes: HashSet::default(),
            heap_areas: vec![],
            pid: proc.pid(),

            stubs: HashMap::default(),
            verbose: false,
        })
    }

    pub fn exit(&mut self, probes: &mut Probes) -> Result<()> {
        probes
            .hotspot_skel
            .maps_mut()
            .hotspot_procs()
            .delete(&self.pid.to_ne_bytes())?;
        for prefix in &self.prefixes {
            probes
                .pid_maps_info_map
                .__delete(self.pid, &prefix)
                .unwrap();
        }

        Ok(())
    }

    pub fn sync_maps(&mut self, probes: &mut Probes) -> Result<()> {
        self.sync_main_maps(probes).unwrap();
        self.sync_stup_maps();
        Ok(())
    }

    pub fn symbolize(&mut self, frame: &Frame, stack: &mut Stack) -> Result<()> {
        if frame.kind != FRAME_MARKER_HOTSPOT as u8 {
            return Ok(());
        }
        let ptr = frame.file_id;
        let subtype = (frame.addr_or_line >> 60) as u32 & 0xf;
        let rip_or_bci = (frame.addr_or_line >> 32) as i32 & 0x0fffffff;
        let ptr_check = frame.addr_or_line as u32;

        match subtype {
            FRAME_HOTSPOT_STUB | FRAME_HOTSPOT_VTABLE => {
                stack.push(Symbol::new(self.get_stub_name(rip_or_bci, ptr)?));
            }
            FRAME_HOTSPOT_INTERPRETER => {
                let method = self.get_method(ptr)?;
                stack.push(Symbol::new(method.method_name.clone()));
            }
            FRAME_HOTSPOT_NATIVE => {
                self.get_jit_info(ptr, ptr_check)?;
                let methods = self
                    .addr_jitinfo
                    .peek(&ptr)
                    .unwrap()
                    .get_methods(rip_or_bci, &self)?;
                for (method, _) in methods {
                    let method = self.get_method(method)?;
                    stack.push(Symbol::new(method.method_name.clone()));
                }
            }
            _ => {
                bail!("hotspot frame subtype {} is not supported", subtype)
            }
        }
        Ok(())
    }

    fn sync_main_maps(&mut self, probes: &mut Probes) -> Result<()> {
        let info = self.gather_heapinfo()?;

        for hr in &info.ranges {
            let tsid = (hr.segmap_start & HS_TSID_SEG_MAP_MASK) << HS_TSID_SEG_MAP_BIT;

            let area = JitArea {
                start: hr.code_start,
                end: hr.code_end,
                code_start: hr.code_start,
                tsid,
            };

            self.add_jit_area(probes, self.pid, &area)?;
            self.heap_areas.push(area);
        }

        let mut pinfo = HotspotProcInfo::default();
        let vms = &self.vm.vm_structs;
        pinfo.raw.compiledmethod_deopt_handler = vms.compiled_method.deopt_handler_begin as u16;
        pinfo.raw.nmethod_compileid = vms.nmethod.compile_id as u16;
        pinfo.raw.nmethod_orig_pc_offset = vms.nmethod.orig_pc_offset as u16;
        pinfo.raw.codeblob_name = vms.code_blob.name as u8;
        pinfo.raw.codeblob_codestart = vms.code_blob.code_begin as u8;
        pinfo.raw.codeblob_codeend = vms.code_blob.code_end as u8;
        pinfo.raw.codeblob_framecomplete = vms.code_blob.frame_complete_offset as u8;
        pinfo.raw.codeblob_framesize = vms.code_blob.frame_size as u8;
        pinfo.raw.cmethod_size = vms.const_method.sizeof as u8;
        pinfo.raw.heapblock_size = vms.heap_block.sizeof as u8;
        pinfo.raw.method_constmethod = vms.method.const_method as u8;
        pinfo.raw.jvm_version = (self.vm.version >> 24) as u8;
        pinfo.raw.segment_shift = info.segment_shift as u8;
        if vms.code_cache.low_bound == 0 {
            pinfo.raw.codecache_start = info.ranges[0].code_start;
            pinfo.raw.codecache_end = info.ranges[0].code_end;
        } else {
            pinfo.raw.codecache_start = self.pm.ptr(vms.code_cache.low_bound + self.bias).unwrap();
            pinfo.raw.codecache_end = self.pm.ptr(vms.code_cache.high_bound + self.bias).unwrap();
        }

        probes.hotspot_skel.maps_mut().hotspot_procs().update(
            &self.pid.to_ne_bytes(),
            pinfo.slice(),
            MapFlags::ANY,
        )?;

        Ok(())
    }

    fn sync_stup_maps(&mut self) {
        let vms = &self.vm.vm_structs;
        for stub in find_stub_bounds(vms, self.bias, &self.pm) {
            if self.stubs.contains_key(&stub.start) {
                continue;
            }

            self.stubs.insert(stub.start, stub);
        }
    }

    fn add_jit_area(&mut self, probes: &mut Probes, pid: u32, area: &JitArea) -> Result<()> {
        let prefixes = calculate_prefixes(area.start, area.end)?;
        for prefix in prefixes.iter() {
            if self.prefixes.contains(&prefix) {
                continue;
            }

            probes.pid_maps_info_map.interpreter_update(
                pid,
                prefix,
                TracePrograms_PROG_UNWIND_HOTSPOT as u8,
                FileId64(area.tsid),
                area.code_start,
            )?;

            self.prefixes.insert(*prefix);
        }

        log::debug!(
            "HotSpot jitArea: pid: {}, code 0x{:x}-0x{:x} tsid: 0x{:x} ({}) tries",
            pid,
            area.start,
            area.end,
            area.tsid,
            prefixes.len()
        );

        Ok(())
    }

    fn gather_heapinfo(&self) -> Result<HeapInfo> {
        let vm = &self.vm;
        let mut info = HeapInfo::default();
        let ptr = |data: &Vec<u8>, offset: usize| {
            if offset + 8 > data.len() {
                return 0;
            }

            LittleEndian::read_u64(&data[offset..])
        };

        let ptr32 = |data: &Vec<u8>, offset: usize| {
            if offset + 4 > data.len() {
                return 0;
            }

            LittleEndian::read_u32(&data[offset..])
        };
        let mut heaps_num = 0;
        let mut heap_ptr_addr = 0;
        if vm.vm_structs.code_cache.heap != 0 {
            heaps_num = 1;
            heap_ptr_addr = vm.vm_structs.code_cache.heap + self.bias;
        } else {
            let mut buf = vec![0; vm.vm_structs.growable_array_int.sizeof as usize];
            self.pm.read_exact(
                self.pm.ptr(vm.vm_structs.code_cache.heaps + self.bias)?,
                &mut buf,
            )?;
            heaps_num = SafeReader::u32(&buf, vm.vm_structs.generic_growable_array.len as usize);
            heap_ptr_addr = SafeReader::ptr(&buf, vm.vm_structs.growable_array_int.data as usize);

            if heaps_num == 0 || heap_ptr_addr == 0 {
                bail!("java heaps not initilized")
            }
        }

        if heaps_num < 1 || heaps_num > 16 {
            bail!("invalid heaps num: {heaps_num}")
        }

        let mut heap = vec![0u8; vm.vm_structs.code_heap.sizeof as usize];
        let mut heap_ptrs = vec![0u8; 8 * heaps_num as usize];

        self.pm.read_at(heap_ptr_addr, &mut heap_ptrs)?;

        for i in 0..heaps_num {
            let heap_ptr = ptr(&heap_ptrs, (i * 8) as usize);
            if heap_ptr == 0 {
                bail!("java heaps not initilized")
            }
            self.pm.read_at(heap_ptr, &mut heap)?;

            info.segment_shift = ptr32(&heap, vm.vm_structs.code_heap.log2_segment_size as usize);

            let rng = HeapRange {
                code_start: ptr(
                    &heap,
                    (vm.vm_structs.code_heap.memory + vm.vm_structs.virtual_space.low_boundary)
                        as usize,
                ),

                code_end: ptr(
                    &heap,
                    (vm.vm_structs.code_heap.memory + vm.vm_structs.virtual_space.high_boundary)
                        as usize,
                ),

                segmap_start: ptr(
                    &heap,
                    (vm.vm_structs.code_heap.segmap + vm.vm_structs.virtual_space.low_boundary)
                        as usize,
                ),

                segmap_end: ptr(
                    &heap,
                    (vm.vm_structs.code_heap.segmap + vm.vm_structs.virtual_space.high_boundary)
                        as usize,
                ),
            };

            if rng.code_start == 0 || rng.code_end == 0 {
                bail!("wrong format for HeapRange")
            }

            info.ranges.push(rng);
        }

        Ok(info)
    }

    pub fn get_method(&mut self, addr: u64) -> Result<&mut HotspotMethod> {
        if self.addr_method.contains(&addr) {
            return Ok(self.addr_method.get_mut(&addr).unwrap());
        }
        let vms = &self.vm.clone().vm_structs;
        let const_method_addr = self.pm.ptr(addr + vms.method.const_method as u64)?;
        let mut const_method = vec![0; vms.const_method.sizeof as usize];
        self.pm.read_at(const_method_addr, &mut const_method)?;

        let cpool_addr = SafeReader::ptr(&const_method, vms.const_method.constants as usize);
        let mut cpool = vec![0; vms.constant_pool.sizeof as usize];
        self.pm.read_at(cpool_addr, &mut cpool)?;

        let instance_klass_addr = SafeReader::ptr(&cpool, vms.constant_pool.pool_holder as usize);
        let mut instance_klass = vec![0; vms.instance_klass.sizeof as usize];
        self.pm.read_at(instance_klass_addr, &mut instance_klass)?;

        let mut source_file_name = {
            if self.verbose {
                if vms.constant_pool.source_file_name_index != 0 {
                    self.get_pool_symbol(
                        cpool_addr,
                        SafeReader::u16(&cpool, vms.constant_pool.source_file_name_index as usize),
                    )?
                } else if vms.instance_klass.source_file_name_index != 0 {
                    self.get_pool_symbol(
                        cpool_addr,
                        SafeReader::u16(
                            &instance_klass,
                            vms.instance_klass.source_file_name_index as usize,
                        ),
                    )?
                } else {
                    self.get_symbol(SafeReader::ptr(
                        &instance_klass,
                        vms.instance_klass.source_file_name as usize,
                    ))?
                }
            } else {
                String::new()
            }
        };
        let mut klass_name =
            self.get_symbol(SafeReader::ptr(&instance_klass, vms.klass.name as usize))?;

        let method_name = self.get_pool_symbol(
            cpool_addr,
            SafeReader::u16(&const_method, vms.const_method.name_index as usize),
        )?;
        let signature = if self.verbose {
            self.get_pool_symbol(
                cpool_addr,
                SafeReader::u16(&const_method, vms.const_method.signature_index as usize),
            )?
        } else {
            String::new()
        };

        if self.verbose && source_file_name.is_empty() {
            source_file_name = "<unknown>".to_owned();
            // TODO: handle source file name
            klass_name = "+<hiddent>".to_owned();
        }

        let byte_code_size = SafeReader::u16(&const_method, vms.const_method.code_size as usize);
        // let mut bytecode = vec![0; byte_code_size as usize];
        // self.pm.read_at(
        //     const_method_addr + vms.const_method.sizeof as u64,
        //     &mut bytecode,
        // )?;

        let mut line_table = vec![];
        let mut start_line = !0;
        if self.verbose
            && SafeReader::u8(&const_method, vms.const_method.flags as usize) & 0x0001 != 0
        {
            let mut cur_bci = 0;
            let mut cur_line = 0;
            let mut pc_line_entry = [0u8; 4];
            let mut rr = ReadRecorder::new(
                self.pm,
                const_method_addr + vms.const_method.sizeof as u64 + byte_code_size as u64,
                256,
            );
            let mut dec = Unsigned5Decoder::new(&mut rr, self.vm.unsigned5_x);
            let mut is_eof = false;
            loop {
                if cur_line > 0 && cur_line < start_line {
                    start_line = cur_line;
                }

                match dec.decode_line_table_entry(&mut cur_bci, &mut cur_line) {
                    Ok(()) => {
                        BigEndian::write_u16(&mut pc_line_entry, cur_bci as u16);
                        BigEndian::write_u16(&mut pc_line_entry[2..], cur_line as u16);
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            is_eof = true;
                        }
                        break;
                    }
                }
            }
            if is_eof {
                line_table = rr.buf;
            }
        }

        if start_line == !0 {
            start_line = 0;
        }

        let method = HotspotMethod {
            source_file_name,
            method_name: if self.verbose {
                demangle_java_method(&klass_name, &method_name, &signature)
            } else {
                demangle_java_method2(&klass_name, &method_name)
            },
            bytecode_size: byte_code_size,
            start_line_no: start_line as u16,
            line_table,
            bci_seen: HashSet::new(),
        };

        self.addr_method.push(addr, method);

        Ok(self.addr_method.get_mut(&addr).unwrap())
    }

    fn get_pool_symbol(&mut self, addr: u64, ndx: u16) -> Result<String> {
        if ndx == 0 {
            return Ok(String::new());
        }

        let vms = &self.vm.vm_structs;
        let offs = vms.constant_pool.sizeof as u64 + (8 * ndx as u64);
        let cpool_val = self.pm.ptr(addr + offs).unwrap();
        self.get_symbol(cpool_val & (!1))
    }

    fn get_symbol(&mut self, addr: u64) -> Result<String> {
        if let Some(value) = self.addr_symbol.get(&addr) {
            return Ok(value.clone());
        }
        let vms = &self.vm.vm_structs;

        let mut buf = vec![0; 128];
        self.pm.read_at(addr, &mut buf)?;
        let sym_len = SafeReader::u16(&buf, vms.symbol.length as usize);
        if sym_len == 0 {
            return Ok(String::new());
        }

        let mut tmp = vec![0; sym_len as usize];
        let end = std::cmp::min(128, vms.symbol.body as usize + sym_len as usize);
        tmp[..(end - vms.symbol.body as usize)]
            .copy_from_slice(&buf[vms.symbol.body as usize..end]);
        if (vms.symbol.body as u16 + sym_len) as usize > buf.len() {
            let prefix_len = buf[vms.symbol.body as usize..].len();
            self.pm.read_at(
                addr + vms.symbol.body as u64 + prefix_len as u64,
                &mut tmp[prefix_len..],
            )?;
        }
        let s = String::from_utf8_lossy(&tmp).into_owned();
        self.addr_symbol.push(addr, s.clone());
        Ok(s)
    }

    fn get_jit_info(&mut self, addr: u64, addr_check: u32) -> Result<&HotspotJITInfo> {
        let mut get = false;
        if self.addr_jitinfo.contains(&addr) {
            let jit = self.addr_jitinfo.get(&addr).unwrap();
            if jit.compile_id == addr_check {
                get = true;
            }
        }

        if get {
            return Ok(self.addr_jitinfo.get(&addr).unwrap());
        }

        let vms = &self.vm.clone().vm_structs;

        let mut nmethod = vec![0; vms.nmethod.sizeof as usize];
        if let Err(err) = self.pm.read_at(addr, &mut nmethod) {
            bail!("invalid nmethod ptr: {}", err)
        }

        let compile_id = SafeReader::u32(&nmethod, vms.nmethod.compile_id as usize);
        if compile_id != addr_check {
            bail!("JIT info evicted since eBPF snapshot: {:x}", compile_id)
        }

        let metadata_off = SafeReader::u32(&nmethod, vms.nmethod.metadata_offset as usize) as u64;
        let mut scopes_off = if vms.compiled_method.scopes_data_begin != 0 {
            SafeReader::ptr(&nmethod, vms.compiled_method.scopes_data_begin as usize) - addr
        } else {
            SafeReader::u32(&nmethod, vms.nmethod.scopes_data_offset as usize) as u64
        };
        let mut scopes_pcs_off =
            SafeReader::u32(&nmethod, vms.nmethod.scopes_pcs_offset as usize) as u64;
        let deps_off = SafeReader::u32(&nmethod, vms.nmethod.dependencies_offset as usize) as u64;

        if metadata_off > scopes_off || scopes_off > scopes_pcs_off || scopes_pcs_off > deps_off {
            bail!(
                "unexpected nmethod layout: {} <= {} <= {} <= {}",
                metadata_off,
                scopes_off,
                scopes_pcs_off,
                deps_off
            )
        }
        let method = SafeReader::ptr(&nmethod, vms.compiled_method.method as usize);
        let _method = self.get_method(method)?;

        let buf_size = deps_off - metadata_off;
        let mut buf = vec![0; buf_size as usize];
        self.pm.read_at(addr + metadata_off, &mut buf)?;

        scopes_off -= metadata_off;
        scopes_pcs_off -= metadata_off;

        let jit_info = HotspotJITInfo {
            compile_id,
            method,
            metadata: buf[0..scopes_off as usize].to_vec(),
            scopes_data: buf[scopes_off as usize..scopes_pcs_off as usize].to_vec(),
            scopes_pcs: buf[scopes_pcs_off as usize..].to_vec(),
        };

        self.addr_jitinfo.push(addr, jit_info);
        Ok(self.addr_jitinfo.get(&addr).unwrap())
    }

    fn get_stub_name(&mut self, rip_or_bci: i32, addr: u64) -> Result<String> {
        if self.addr_stub_name.contains(&addr) {
            return Ok(self.addr_stub_name.get(&addr).unwrap().clone());
        }

        let vms = &self.vm.clone().vm_structs;
        let const_stub_name_addr = self.pm.ptr(addr + vms.code_blob.name as u64)?;
        let mut stub_name = self
            .pm
            .string(const_stub_name_addr)
            .unwrap_or(String::new());

        let a = self.pm.ptr(addr + vms.code_blob.code_begin as u64)? + rip_or_bci as u64;
        for (_, stub) in &self.stubs {
            if stub.start <= a && stub.end > a {
                let new_stub_name = format!("{} [{}]", stub_name, stub.name);
                stub_name = new_stub_name.clone();
                break;
            }
        }
        self.addr_stub_name.push(addr, stub_name);
        Ok(self.addr_stub_name.get(&addr).unwrap().clone())
    }

    pub fn unsigned5_decoder<R: Read>(&self, r: R) -> Unsigned5Decoder<R> {
        Unsigned5Decoder::new(r, self.vm.unsigned5_x)
    }
}

#[derive(Debug, Default)]
struct HeapRange {
    code_start: u64,
    code_end: u64,
    segmap_start: u64,
    segmap_end: u64,
}

#[derive(Debug, Default)]
struct HeapInfo {
    segment_shift: u32,
    ranges: Vec<HeapRange>,
}

#[derive(Debug, Default)]
struct JitArea {
    start: u64,
    end: u64,
    code_start: u64,
    tsid: u64,
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use crate::process::maps::ProcessMaps;
    use crate::process::process::Process;
    use crate::symbollizer::elf::ElfFile;
    use crate::symbollizer::file_cache::FileInfo;

    use super::HotspotFileInfo;
    use super::HotspotInstance;

    #[test]
    fn test_get_method() {
        let proc = Process::new(3311232);
        let pm = proc.memory().unwrap();

        let maps = ProcessMaps::new(proc.pid()).unwrap();

        for (_, entry) in maps.iter() {
            if entry.is_executable() && entry.path.as_ref().unwrap().contains("libjvm.so") {
                let file_info = FileInfo::from_path(&entry.file_path(proc.pid())).unwrap();
                let bias = entry.start
                    - file_info
                        .file_offset_to_virtual_address(entry.offset)
                        .unwrap();
                let elf = ElfFile::new(&entry.file_path(proc.pid())).unwrap();
                let elf_file = elf.object_file();

                let mut jvm_file_info =
                    HotspotFileInfo::new(&"sdsa".to_owned(), &elf_file).unwrap();

                let mut hi = HotspotInstance::new(Rc::new(jvm_file_info), &proc, bias).unwrap();

                let method = hi.get_method(139838026623040).unwrap();

                println!("{:?}", method);
            }
        }
    }

    #[test]
    fn test_get_jit() {
        let proc = Process::new(1233);
        let pm = proc.memory().unwrap();

        let maps = ProcessMaps::new(proc.pid()).unwrap();

        for (_, entry) in maps.iter() {
            if entry.is_executable() && entry.path.as_ref().unwrap().contains("libjvm.so") {
                let file_info = FileInfo::from_path(&entry.file_path(proc.pid())).unwrap();
                let bias = entry.start
                    - file_info
                        .file_offset_to_virtual_address(entry.offset)
                        .unwrap();
                let elf = ElfFile::new(&entry.file_path(proc.pid())).unwrap();
                let elf_file = elf.object_file();

                let mut jvm_file_info =
                    HotspotFileInfo::new(&"sdsa".to_owned(), &elf_file).unwrap();

                let mut hi = HotspotInstance::new(Rc::new(jvm_file_info), &proc, bias).unwrap();
                let jit = hi.get_jit_info(0x7ff26c660790, 5399).unwrap();
                // let jit = hi.get_method(0x7ff26c456d56).unwrap();
                println!("{:?}", jit);
            }
        }
    }
}
