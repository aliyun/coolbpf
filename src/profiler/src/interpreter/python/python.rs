/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
// Rewrite with gpt

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use byteorder::ByteOrder;
use byteorder::NativeEndian;
use byteorder::ReadBytesExt;
use libbpf_rs::MapFlags;
use lru::LruCache;
use object::elf;
use object::read::elf::Dyn;
use object::Object;
use object::ObjectSymbol;
use object::ReadRef;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Cursor;
use std::io::Read;
use std::num::NonZero;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::sync::Mutex;

use crate::probes::probes::Probes;
use crate::probes::types::any_as_u8_slice;
use crate::probes::types::bpf;
use crate::probes::types::bpf::TracePrograms_PROG_UNWIND_PYTHON;
use crate::process::memory::ProcessMemory;
use crate::process::process::Process;
use crate::stack::Stack;
use crate::symbollizer::elf::ElfFile;
use crate::symbollizer::file_id::FileId64;
use crate::symbollizer::symbolizer::Symbol;

use super::decode::decode_stub_argument_wrapper;

#[derive(Debug, Clone)]
pub struct PythonData {
    version: u16,

    auto_tls_key: u64,

    // vm_structs 反映了我们从 Python 运行时中提取的解释器内省数据。
    // 字段名称与 Python 代码中的名称相同。最终，这些字段将从 Python 内省数据中读取，
    // 并使用反射名称进行匹配。
    vm_structs: VmStructs,
}

#[derive(Debug, Clone)]
pub struct VmStructs {
    // https://github.com/python/cpython/blob/deaf509e8fc6e0363bd6f26d52ad42f976ec42f2/Include/cpython/object.h#L148
    py_type_object: PyTypeObject,

    // https://github.com/python/cpython/blob/deaf509e8fc6e0363bd6f26d52ad42f976ec42f2/Include/structmember.h#L18
    py_member_def: PyMemberDef,

    // https://github.com/python/cpython/blob/deaf509e8fc6e0363bd6f26d52ad42f976ec42f2/Include/cpython/unicodeobject.h#L72
    py_ascii_object: PyASCIIObject,

    py_code_object: PyCodeObject,

    // https://github.com/python/cpython/blob/deaf509e8fc6e0363bd6f26d52ad42f976ec42f2/Include/object.h#L109
    py_var_object: PyVarObject,

    py_bytes_object: PyBytesObject,

    // https://github.com/python/cpython/blob/deaf509e8fc6e0363bd6f26d52ad42f976ec42f2/Include/cpython/pystate.h#L82
    py_thread_state: PyThreadState,

    py_frame_object: PyFrameObject,

    // https://github.com/python/cpython/blob/deaf509e8fc6e0363bd6f26d52ad42f976ec42f2/Include/cpython/pystate.h#L38
    py_c_frame: PyCFrame,
}

fn decode_stub(
    elf: &object::File,
    addr_base: u64,
    symbol_name: &str,
    arg_number: u8,
) -> Result<u64> {
    let symbol_value = ElfFile::lookup_symbol(elf, symbol_name)?;
    let code = ElfFile::read_at(elf, symbol_value.address(), 64)?;
    let value = decode_stub_argument_wrapper(&code, arg_number, symbol_value.address(), addr_base);

    // 检查值的范围和对齐
    if value % 4 != 0 {
        bail!("address not aligned")
    }
    // 如果基础符号 (_PyRuntime) 未提供，接受任何找到的值
    if addr_base == 0 && value != 0 {
        return Ok(value);
    }
    // 检查找到的值是否在给定符号的合理范围内
    if value > addr_base && value < addr_base + 4096 {
        return Ok(value);
    }

    bail!("failed to find target symbol")
}

impl PythonData {
    fn read_introspection_data1(
        &mut self,
        elf: &object::File,
        bias: u64,
        symbol: &str,
    ) -> Result<()> {
        let type_data = ElfFile::lookup_symbol(elf, symbol)?.address();
        let vms = &mut self.vm_structs;
        let type_data_address = type_data;

        if let Ok(data) =
            ElfFile::read_at(elf, type_data_address + vms.py_type_object.basic_size, 8)
        {
            vms.py_code_object.sizeof = NativeEndian::read_u64(data) as u32;
            println!("sizeof: {}", vms.py_code_object.sizeof);
        }

        let members_ptr =
            ElfFile::read_u64(elf, type_data_address + vms.py_type_object.members)? - bias;
        if members_ptr == 0 {
            return Ok(());
        }

        let mut addr = members_ptr;
        loop {
            let start = ElfFile::read_u64(elf, addr + vms.py_member_def.name as u64)? - bias;
            let name = ElfFile::read_string(elf, start, 124)?;
            if name.is_empty() {
                break;
            }
            let offset = ElfFile::read_u32(elf, addr + vms.py_member_def.offset as u64)?;
            vms.py_code_object.set_field(&name, offset);

            addr += vms.py_member_def.sizeof;
        }

        Ok(())
    }

    fn read_introspection_data2(
        &mut self,
        elf: &object::File,
        bias: u64,
        symbol: &str,
    ) -> Result<()> {
        let type_data = ElfFile::lookup_symbol(elf, symbol)?.address();

        let vms = &mut self.vm_structs;
        let type_data_address = type_data;

        let members_ptr =
            ElfFile::read_u64(elf, type_data_address + vms.py_type_object.members)? - bias;
        if members_ptr == 0 {
            return Ok(());
        }

        let mut addr = members_ptr;
        loop {
            let start = ElfFile::read_u64(elf, addr + vms.py_member_def.name as u64)? - bias;
            let name = ElfFile::read_string(elf, start, 124)?;
            if name.is_empty() {
                break;
            }
            let offset = ElfFile::read_u32(elf, addr + vms.py_member_def.offset as u64)?;
            vms.py_frame_object.set_field(&name, offset);

            addr += vms.py_member_def.sizeof;
        }

        Ok(())
    }

    fn read_introspection_data3(
        &mut self,
        elf: &object::File,
        bias: u64,
        symbol: &str,
    ) -> Result<()> {
        let type_data = ElfFile::lookup_symbol(elf, symbol)?.address();

        let vms = &mut self.vm_structs;
        let type_data_address = type_data;
        if let Ok(data) = ElfFile::read_u64(elf, type_data_address + vms.py_type_object.basic_size)
        {
            vms.py_bytes_object.sizeof = data as u32;
        }
        Ok(())
    }
    pub fn new(
        name: &str,
        elf: &object::File,
        id: FileId64,
        bias: u64,
        probes: &Probes,
    ) -> Result<Self> {
        let python_regex: Regex = Regex::new(r"^(?:.*/)?python(\d)\.(\d+)(d|m|dm)?$").unwrap();
        let libpython_regex: Regex = Regex::new(r"^(?:.*/)?libpython(\d)\.(\d+)[^/]*").unwrap();
        let mut main_dso = false;
        let matches = match libpython_regex.captures(name) {
            Some(m) => m,
            None => {
                main_dso = true;
                match python_regex.captures(name) {
                    Some(m) => m,
                    None => bail!("not python object"),
                }
            }
        };

        if main_dso {
            todo!()
            // let rm = match elf {
            //     let mut dyn_strings = vec![];
            //     object::File::Elf64(e) => {
            //         let (dyncs, _) = e.elf_section_table().dynamic(e.endian(), e.data())?.unwrap();
            //         for dysn in dyncs {
            //             if dysn.d_tag(e.endian()) == elf::DT_NEEDED as u64 {

            //             }
            //         }
            //     },
            //     _ => unreachable!(),
            // };
            // // let needed = elf.dyn_string(elf::DT_NEEDED)?;
            // let needed = todo!();
            // for n in needed {
            //     if libpython_regex.is_match(n) {
            //         return Ok(None);
            //     }
            // }
        }

        let mut pyruntime_addr: Option<u64> = None;
        let major = matches[1].parse::<i32>()?;
        let minor = matches[2].parse::<i32>()?;
        let version = python_ver(major, minor);

        let min_ver = python_ver(3, 6);
        let max_ver = python_ver(3, 12);
        if version < min_ver || version > max_ver {
            bail!(
                "unsupported Python {}.{} (need >= {}.{} and <= {}.{}",
                major,
                minor,
                (min_ver >> 8) & 0xff,
                min_ver & 0xff,
                (max_ver >> 8) & 0xff,
                max_ver & 0xff
            )
        }

        if version >= python_ver(3, 7) {
            if let Ok(sym) = ElfFile::lookup_symbol(elf, "_PyRuntime") {
                pyruntime_addr = Some(sym.address());
            } else {
                bail!("_PyRuntime not defined")
            }
        }
        let mut auto_tls_key = decode_stub(
            elf,
            pyruntime_addr.unwrap_or(0),
            "PyGILState_GetThisThreadState",
            0,
        )?;
        if version >= python_ver(3, 7) && auto_tls_key % 8 == 0 {
            auto_tls_key += 4;
        }

        let interp_ranges = match ElfFile::lookup_symbol(elf, "_PyEval_EvalFrameDefault") {
            Ok(sym) => sym.address()..(sym.address() + sym.size()),
            Err(_) => ElfFile::lookup_symbol(elf, "PyEval_EvalFrameEx")
                .map(|x| x.address()..(x.address() + x.size()))?,
        };

        let mut pd = PythonData {
            version,
            auto_tls_key,
            vm_structs: VmStructs {
                py_type_object: PyTypeObject {
                    basic_size: 32,
                    members: 240,
                },
                py_member_def: PyMemberDef {
                    name: 0,
                    offset: 16,
                    sizeof: 40,
                },
                py_ascii_object: PyASCIIObject { data: 48 },
                py_code_object: PyCodeObject::default(),
                py_var_object: PyVarObject { ob_size: 16 },
                py_bytes_object: PyBytesObject { sizeof: 0 },
                py_thread_state: PyThreadState { frame: 24 },
                py_frame_object: PyFrameObject {
                    code: 0,
                    last_i: 0,
                    back: 0,
                    entry_member: 0,
                    entry_val: 0,
                },
                py_c_frame: PyCFrame { current_frame: 0 },
            },
        };

        if version == python_ver(3, 11) {
            pd.vm_structs.py_frame_object.code = 32;
            pd.vm_structs.py_frame_object.last_i = 56;
            pd.vm_structs.py_frame_object.back = 48;
            pd.vm_structs.py_frame_object.entry_member = 68;
            pd.vm_structs.py_frame_object.entry_val = 1;
            pd.vm_structs.py_thread_state.frame = 56;
            pd.vm_structs.py_c_frame.current_frame = 8;
        } else if version == python_ver(3, 12) {
            pd.vm_structs.py_frame_object.code = 0;
            pd.vm_structs.py_frame_object.last_i = 56;
            pd.vm_structs.py_frame_object.back = 8;
            pd.vm_structs.py_frame_object.entry_member = 70;
            pd.vm_structs.py_frame_object.entry_val = 3;
            pd.vm_structs.py_thread_state.frame = 56;
            pd.vm_structs.py_c_frame.current_frame = 0;
            pd.vm_structs.py_ascii_object.data = 40;
        }
        pd.read_introspection_data1(elf, 0, "PyCode_Type")?;
        pd.read_introspection_data2(elf, 0, "PyFrame_Type")?;
        pd.read_introspection_data3(elf, 0, "PyBytes_Type")?;

        log::debug!("{:?}", pd.vm_structs);
        probes.interpreter_offset_map.update(
            TracePrograms_PROG_UNWIND_PYTHON as u16,
            id,
            &interp_ranges,
        )?;
        Ok(pd)
    }
}

#[derive(Debug, Clone)]
pub struct PyTypeObject {
    basic_size: u64,
    members: u64,
}

#[derive(Debug, Clone)]
pub struct PyMemberDef {
    sizeof: u64,
    name: u32,
    offset: u32,
}

#[derive(Debug, Clone)]
pub struct PyASCIIObject {
    data: u32,
}

#[derive(Debug, Default, Clone)]
pub struct PyCodeObject {
    sizeof: u32,
    arg_count: u32,
    kw_only_arg_count: u32,
    flags: u32,
    first_lineno: u32,
    filename: u32,
    name: u32,
    lnotab: u32,
    linetable: u32, // Python 3.10+
    qualname: u32,  // Python 3.11+
}

impl PyCodeObject {
    fn set_field(&mut self, name: &str, val: u32) {
        match name {
            "Sizeof" => self.sizeof = val,
            "co_argcount" => self.arg_count = val,
            "co_kwonlyargcount" => self.kw_only_arg_count = val,
            "co_flags" => self.flags = val,
            "co_firstlineno" => self.first_lineno = val,
            "co_filename" => self.filename = val,
            "co_name" => self.name = val,
            "co_lnotab" => self.lnotab = val,
            "co_linetable" => self.linetable = val,
            "co_qualname" => self.qualname = val,
            _ => return,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PyVarObject {
    ob_size: u32,
}

#[derive(Debug, Clone)]
pub struct PyBytesObject {
    sizeof: u32,
}

impl PyBytesObject {
    fn set_field(&mut self, name: &str, val: u32) {
        match name {
            "Sizeof" => self.sizeof = val,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PyThreadState {
    frame: u32,
}

#[derive(Debug, Clone)]
pub struct PyFrameObject {
    back: u32,
    code: u32,
    last_i: u32,
    entry_member: u32, // 字段取决于 Python 版本
    entry_val: u32,    // 值取决于 Python 版本
}

impl PyFrameObject {
    fn set_field(&mut self, name: &str, val: u32) {
        match name {
            "f_back" => self.back = val,
            "f_code" => self.code = val,
            "f_lasti" => self.last_i = val,
            "EntryMember" => self.entry_member = val,
            "EntryVal" => self.entry_val = val,
            _ => return,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PyCFrame {
    current_frame: u32,
}

impl std::fmt::Display for PythonData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let major = self.version >> 8;
        let minor = self.version & 0xff;
        write!(f, "Python {}.{}", major, minor)
    }
}

pub type GetFuncOffsetFunc = fn(m: &PythonCodeObject, bci: u32) -> u32;

#[derive(Debug)]
pub struct PythonInstance {
    // Python symbolization metrics
    success_count: AtomicU64,
    fail_count: AtomicU64,

    d: PythonData,
    rm: ProcessMemory,
    bias: u64,

    // addrToCodeObject maps a Python Code object to a pythonCodeObject which caches
    // the needed data from it.
    addr_to_code_object: LruCache<u64, Arc<PythonCodeObject>>,

    // getFuncOffset provides fast access in order to get the function offset for different
    // Python interpreter versions.
    get_func_offset: GetFuncOffsetFunc,

    // procInfoInserted tracks whether we've already inserted process info into BPF maps.
    proc_info_inserted: bool,
}

// 将字节码索引映射到行号
pub fn map_byte_code_index_to_line(m: &PythonCodeObject, bci: u32) -> u32 {
    // The co_lntab format is specified in python Objects/lnotab_notes.txt
    let mut lineno: u32 = 0;
    let mut addr: u32 = 0;
    let lnotab = &m.line_table;

    for i in (0..lnotab.len()).step_by(2) {
        addr += u32::from(lnotab[i]);
        if addr > bci {
            return lineno;
        }
        lineno += u32::from(lnotab[i + 1]);
        if lnotab[i + 1] >= 0x80 {
            lineno -= 0x100;
        }
    }

    lineno
}

// 计算 Python 版本号
fn python_ver(major: i32, minor: i32) -> u16 {
    (major as u16) * 0x100 + (minor as u16)
}

impl PythonInstance {
    pub fn new(info: PythonData, proc: &Process, bias: u64) -> Result<Self> {
        let get_func_offset = if info.version >= python_ver(3, 11) {
            walk_location_table
        } else if info.version >= python_ver(3, 10) {
            walk_line_table
        } else {
            map_byte_code_index_to_line
        };

        let i = PythonInstance {
            success_count: AtomicU64::new(0),
            fail_count: AtomicU64::new(0),
            d: info,
            rm: proc.memory()?,
            bias,
            addr_to_code_object: LruCache::new(NonZeroUsize::new(1024).unwrap()),
            get_func_offset,
            proc_info_inserted: false,
        };
        Ok(i)
    }

    pub fn update_tsd_info(
        &mut self,
        probes: &Probes,
        pid: u32,
        tsd_info: bpf::TSDInfo,
    ) -> Result<()> {
        let d = &self.d;
        let vm = &d.vm_structs;

        let cdata = bpf::PyProcInfo {
            autoTLSKeyAddr: self.d.auto_tls_key + self.bias,
            version: d.version as u16,

            tsdInfo: bpf::TSDInfo {
                offset: tsd_info.offset,
                multiplier: tsd_info.multiplier,
                indirect: tsd_info.indirect,
            },

            PyThreadState_frame: vm.py_thread_state.frame as u8,
            PyCFrame_current_frame: vm.py_c_frame.current_frame as u8,
            PyFrameObject_f_back: vm.py_frame_object.back as u8,
            PyFrameObject_f_code: vm.py_frame_object.code as u8,
            PyFrameObject_f_lasti: vm.py_frame_object.last_i as u8,
            PyFrameObject_entry_member: vm.py_frame_object.entry_member as u8,
            PyFrameObject_entry_val: vm.py_frame_object.entry_val as u8,
            PyCodeObject_co_argcount: vm.py_code_object.arg_count as u8,
            PyCodeObject_co_kwonlyargcount: vm.py_code_object.kw_only_arg_count as u8,
            PyCodeObject_co_flags: vm.py_code_object.flags as u8,
            PyCodeObject_co_firstlineno: vm.py_code_object.first_lineno as u8,
            PyCodeObject_sizeof: vm.py_code_object.sizeof as u8,
        };

        probes.python_skel.maps().py_procs().update(
            &pid.to_ne_bytes(),
            unsafe { any_as_u8_slice(&cdata) },
            MapFlags::ANY,
        )?;
        self.proc_info_inserted = true;
        Ok(())
    }

    fn get_code_object(&mut self, addr: u64, ebpf_checksum: u32) -> Result<&PythonCodeObject> {
        if addr == 0 {
            bail!("failed to read code object: null pointer");
        }

        // if let Some(value) = self.addr_to_code_object.get(&addr) {
        //     if value.ebpf_checksum == ebpf_checksum {
        //         return Ok(value);
        //     }
        // }

        let vms = &self.d.vm_structs;
        let mut cobj = vec![0; vms.py_code_object.sizeof as usize];
        self.rm.read_exact(addr, &mut cobj)?;

        let first_line_no =
            NativeEndian::read_u32(&cobj[(vms.py_code_object.first_lineno as usize)..]);
        let arg_count = NativeEndian::read_u32(&cobj[(vms.py_code_object.arg_count as usize)..]);
        let kwonly_arg_count =
            NativeEndian::read_u32(&cobj[(vms.py_code_object.kw_only_arg_count as usize)..]);
        let flags = NativeEndian::read_u32(&cobj[(vms.py_code_object.flags as usize)..]);

        let data = vms.py_ascii_object.data as u64;

        let line_info_ptr = if self.d.version < python_ver(3, 10) {
            NativeEndian::read_u64(&cobj[(vms.py_code_object.lnotab as usize)..])
        } else {
            NativeEndian::read_u64(&cobj[(vms.py_code_object.linetable as usize)..])
        };

        let name = if vms.py_code_object.qualname != 0 {
            self.rm.string(
                data + NativeEndian::read_u64(&cobj[(vms.py_code_object.qualname as usize)..]),
            )?
        } else {
            self.rm.string(
                data + NativeEndian::read_u64(&cobj[(vms.py_code_object.name as usize)..]),
            )?
        };

        if !name.is_ascii() {
            log::debug!(
                "Extracted invalid Python method/function name at 0x{:x} '{}'",
                addr,
                name
            );
            bail!(
                "extracted invalid Python method/function name from address 0x{:x}",
                addr
            )
        }

        let source_path = self.rm.string(
            data + NativeEndian::read_u64(&cobj[(vms.py_code_object.filename as usize)..]),
        )?;
        let source_file_name = frozen_name_to_file_name(&source_path).unwrap_or(source_path);

        if !source_file_name.is_ascii() {
            log::debug!(
                "Extracted invalid Python source file name at 0x{:x} '{}'",
                addr,
                source_file_name
            );
            bail!(
                "extracted invalid Python source file name from address 0x{:x}",
                addr
            )
        }

        let ebpf_checksum_calculated =
            (arg_count << 25) + (kwonly_arg_count << 18) + (flags << 10) + first_line_no;
        if ebpf_checksum != ebpf_checksum_calculated {
            bail!(
                "read code object was stale: {:x} != {:x}",
                ebpf_checksum,
                ebpf_checksum_calculated
            )
        }

        let line_table_size = self
            .rm
            .u64(line_info_ptr + vms.py_var_object.ob_size as u64)?;
        if line_table_size >= 0x10000
            || (self.d.version < python_ver(3, 11) && line_table_size & 1 != 0)
        {
            bail!("invalid line table size ({})", line_table_size)
        }

        let mut line_table = vec![0; line_table_size as usize];
        self.rm.read_exact(
            line_info_ptr + vms.py_bytes_object.sizeof as u64 - 1,
            &mut line_table,
        )?;

        // let mut hasher = FnvHasher::default();
        // hasher.write(source_file_name.as_bytes());
        // hasher.write(name.as_bytes());
        // hasher.write(&cobj[vms.py_code_object.first_lineno..vms.py_code_object.first_lineno + 4]);
        // hasher.write(&cobj[vms.py_code_object.arg_count..vms.py_code_object.arg_count + 4]);
        // hasher.write(&cobj[vms.py_code_object.kw_only_arg_count..vms.py_code_object.kw_only_arg_count + 4]);
        // hasher.write(&line_table);
        // let file_id = FileIDFromBytes(hasher.finish().to_be_bytes())?;

        let pco = PythonCodeObject {
            version: self.d.version,
            name,
            source_file_name,
            first_line_no,
            line_table,
            ebpf_checksum,
            file_id: FileId64(0),
            bci_seen: HashSet::new(),
        };
        self.addr_to_code_object.push(addr, Arc::new(pco));
        Ok(self.addr_to_code_object.get(&addr).unwrap())
    }

    pub fn symbolize(&mut self, frame: &bpf::Frame, trace: &mut Stack) -> Result<()> {
        let ptr = frame.file_id;
        let last_i = (frame.addr_or_line >> 32) & 0x0fffffff;
        let object_id = frame.addr_or_line as u32;

        // let sf_counter = successfailurecounter::new(&mut p.success_count, &mut p.fail_count);
        // defer!(sf_counter.default_to_failure());

        let method = self.get_code_object(ptr, object_id)?;

        method.symbolize(0, trace);
        // method.symbolize(symbol_reporter, last_i, p.get_func_offset, trace)?;

        // sf_counter.report_success();
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PythonCodeObject {
    // As of Python 3.10 elements of PyCodeObject have changed and so we need
    // to handle them differently. To be able to do so we keep track of the python version.
    version: u16,

    // name is the extracted co_name (the unqualified method or function name)
    name: String,

    // sourceFileName is the extracted co_filename field
    source_file_name: String,

    // For Python version < 3.10 line_table is the extracted co_lnotab, and contains the
    // "bytecode index" to "line number" mapping data.
    // For Python version >= 3.10 line_table is the extracted co_linetable.
    line_table: Vec<u8>,

    // first_line_no is the extracted co_firstlineno field, and contains the line
    // number where the method definition in source code starts
    first_line_no: u32,

    // ebpf_checksum is the simple hash of few PyCodeObject fields sent from eBPF
    // to verify that the data we extracted from remote process is still valid
    ebpf_checksum: u32,

    // file_id is a more complete hash of various PyCodeObject fields, which is
    // used as the global ID of the PyCodeObject. It is stored as the FileID
    // part of the Frame in the DB.
    file_id: FileId64,

    // bci_seen is a set of "lastI" or byte code index (bci) values we have
    // already symbolized and sent to the collection agent
    bci_seen: HashSet<u32>,
}

impl PythonCodeObject {
    fn symbolize(
        &self,
        bci: u32,
        // get_func_offset: &dyn Fn(&PythonCodeObject, u32) -> u32,
        trace: &mut Stack,
    ) -> Result<()> {
        trace.push(Symbol::new(self.name.clone()));
        // trace.append_frame(libpf::PythonFrame, m.file_id, libpf::AddressOrLineno(bci));

        // Check if this is already symbolized
        // if m.bci_seen.contains_key(&bci) {
        //     return Ok(());
        // }

        // let line_no = m.first_line_no + get_func_offset(m, bci);
        // let line_no = util::SourceLineno(line_no);

        // symbol_reporter.frame_metadata(
        //     m.file_id,
        //     libpf::AddressOrLineno(bci),
        //     line_no,
        //     get_func_offset(m, bci),
        //     &m.name,
        //     &m.source_file_name,
        // );

        // // FIXME: The above FrameMetadata might fail, but we have no idea of it
        // // due to the requests being queued and send attempts being done asynchronously.
        // // Until the reporting API gets a way to notify failures, just assume it worked.
        // m.bci_seen.insert(bci, ());

        // log::debug!(
        //     "[{}] [{}] {}+{} at {}:{}. (bci {})",
        //     trace.frame_types.len(),
        //     hex::encode(m.file_id),
        //     m.name,
        //     get_func_offset(m, bci),
        //     m.source_file_name,
        //     line_no,
        //     bci
        // );

        Ok(())
    }
}

// 读取无符号变长整数
fn read_varint<R: Read>(r: &mut R) -> Result<u32> {
    let mut val: u32 = 0;
    let mut b: u8 = 0x40;
    let mut shift = 0;

    while b & 0x40 != 0 {
        let mut bytes = [0; 1];
        r.read_exact(&mut bytes)?;
        let byte = bytes[0];
        if byte & 0x80 != 0 {
            bail!("invalid varint encoding");
        }
        val |= u32::from(byte & 0x3F) << shift;
        b = byte;
        shift += 6;
    }

    Ok(val)
}
// 读取有符号变长整数
fn read_signed_varint<R: Read>(r: &mut R) -> Result<i32> {
    let uval = read_varint(r)?;
    if uval & 1 != 0 {
        Ok(-((uval >> 1) as i32))
    } else {
        Ok((uval >> 1) as i32)
    }
}

// walk_location_table 实现了从位置表中读取条目的算法
// 这是在 Python 3.11 中引入的。
pub fn walk_location_table(m: &PythonCodeObject, bci: u32) -> u32 {
    let mut r = Cursor::new(&m.line_table);
    let mut cur_i: u32 = 0;
    let mut line: i32 = 0;

    while cur_i <= bci {
        let first_byte = match r.read_u8() {
            Ok(byte) => byte,
            Err(_) => {
                log::debug!("first byte: sync lost () or error");
                return 0;
            }
        };

        if first_byte & 0x80 == 0 {
            log::debug!("first byte: sync lost ({:x}) or error", first_byte);
            return 0;
        }

        let code = (first_byte >> 3) & 15;
        cur_i += u32::from(first_byte & 7) + 1;

        match code {
            0..=9 => {
                // PY_CODE_LOCATION_INFO_SHORT 不包含行信息
                let _ = r.read_u8();
            }
            10..=12 => {
                // PY_CODE_LOCATION_INFO_ONE_LINE 将行信息嵌入代码
                // 跟随两个字节的新列
                line += i32::try_from(code - 10).unwrap();
                let _ = r.read_u8();
                let _ = r.read_u8();
            }
            13 => {
                // PY_CODE_LOCATION_INFO_NO_COLUMNS
                line += read_signed_varint(&mut r).unwrap_or(0);
            }
            14 => {
                // PY_CODE_LOCATION_INFO_LONG
                line += read_signed_varint(&mut r).unwrap_or(0);
                let _ = read_varint(&mut r);
                let _ = read_varint(&mut r);
                let _ = read_varint(&mut r);
            }
            15 => {
                // PY_CODE_LOCATION_INFO_NONE 不包含行信息
                line = -1;
            }
            _ => {
                log::debug!("Unexpected PyCodeLocationInfoKind {}", code);
                return 0;
            }
        }
    }

    if line < 0 {
        line = 0;
    }
    line as u32
}

// walk_line_table 实现了 Python 3.10 引入的行号表遍历算法
pub fn walk_line_table(m: &PythonCodeObject, addrq: u32) -> u32 {
    // The co_linetab format is specified in python Objects/lnotab_notes.txt
    if addrq == 0 {
        return 0;
    }

    let line_table = &m.line_table;
    let mut line = m.first_line_no;
    let mut start: u32 = 0;
    let mut end: u32 = 0;

    for i in (0..line_table.len()).step_by(2) {
        let s_delta = line_table[i];
        let l_delta = line_table[i + 1] as i8;

        if l_delta == 0 {
            end += u32::from(s_delta);
            continue;
        }

        start = end;
        end = start + u32::from(s_delta);

        if l_delta == -128 {
            // A line delta of -128 is a special indicator mentioned in
            // Objects/lnotab_notes.txt and indicates an invalid line number.
            continue;
        }

        line += l_delta as u32;

        if end == start {
            continue;
        }

        if end > addrq {
            return line;
        }
    }

    0
}

fn frozen_name_to_file_name(source_file_name: &str) -> Result<String> {
    if !source_file_name.starts_with("<frozen ") {
        return Ok(source_file_name.to_string());
    }

    if !source_file_name.ends_with('>') {
        bail!("missing terminator in frozen file '{}'", source_file_name)
    }

    let b = source_file_name.rfind('.').map_or(8, |pos| pos + 1);

    let f_name = &source_file_name[b..source_file_name.len() - 1];
    if f_name.is_empty() {
        bail!("unexpected empty frozen file '{}'", source_file_name)
    }

    Ok(format!("{}.py", f_name))
}
