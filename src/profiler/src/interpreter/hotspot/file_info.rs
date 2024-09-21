/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

use super::unsigned5::Unsigned5Decoder;
use crate::process::memory::ProcessMemory;
use anyhow::bail;
use anyhow::Result;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;

#[derive(Default, Clone)]
pub struct HotspotFileInfo {
    type_ptrs: HotspotIntrospectionTable,
    struct_ptrs: HotspotIntrospectionTable,
    jvmci_struct_ptrs: HotspotIntrospectionTable,
}

impl HotspotFileInfo {
    pub fn new(file: &str, elf: &object::File) -> Result<Self> {
        let mut info = HotspotFileInfo::default();
        info.struct_ptrs.resolve_symbols(
            elf,
            &vec![
                "gHotSpotVMStructs",
                "gHotSpotVMStructEntryArrayStride",
                "gHotSpotVMStructEntryTypeNameOffset",
                "gHotSpotVMStructEntryFieldNameOffset",
                "gHotSpotVMStructEntryOffsetOffset",
                "gHotSpotVMStructEntryAddressOffset",
            ],
        )?;

        info.type_ptrs.resolve_symbols(
            elf,
            &vec![
                "gHotSpotVMTypes",
                "gHotSpotVMTypeEntryArrayStride",
                "gHotSpotVMTypeEntryTypeNameOffset",
                "",
                "gHotSpotVMTypeEntrySizeOffset",
                "",
            ],
        )?;

        if let Ok(base) = locate_jvmci_vm_structs(elf) {
            info.jvmci_struct_ptrs = info.struct_ptrs;
            info.jvmci_struct_ptrs.base = base;
            info.jvmci_struct_ptrs.skip_base_dref = true;
        }
        

        Ok(info)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HotspotIntrospectionTable {
    skip_base_dref: bool,
    base: u64,
    stride: u64,
    type_offset: u64,
    field_offset: u64,
    value_offset: u64,
    address_offset: u64,
}

impl HotspotIntrospectionTable {
    pub fn resolve_symbols(&mut self, elf: &object::File, symbols: &Vec<&str>) -> Result<()> {
        let mut addrs = vec![0; symbols.len()];
        for (i, sym) in symbols.iter().enumerate() {
            if sym.is_empty() {
                continue;
            }
            match elf.symbol_by_name(sym) {
                Some(s) => {
                    addrs[i] = s.address();
                }
                None => {
                    bail!("failed to find symbol: {}", sym);
                }
            }
        }
        self.base = addrs[0];
        self.stride = addrs[1];
        self.type_offset = addrs[2];
        self.field_offset = addrs[3];
        self.value_offset = addrs[4];
        self.address_offset = addrs[5];
        Ok(())
    }
}

fn locate_jvmci_vm_structs(ef: &object::File) -> Result<u64> {
    let rodata_sec = ef.section_by_name(".rodata").unwrap();
    let offs = rodata_sec
        .data()
        .unwrap()
        .windows(25)
        .position(|window| window == b"Klass_vtable_start_offset");
    if let Some(offs) = offs {
        let ptr = rodata_sec.address() + offs as u64;
        let ptr_encoded = ptr.to_le_bytes();

        let data_sec = ef.section_by_name(".data").unwrap();
        let offs = data_sec
            .data()
            .unwrap()
            .windows(8)
            .position(|window| window == &ptr_encoded);
        if let Some(offs) = offs {
            return Ok(data_sec.address() + offs as u64 - 8);
        }
    }

    bail!("unable to find string pointer")
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct HotspotVmInfo {
    pub version: u32,
    pub version_str: String,
    pub unsigned5_x: u8,
    pub vm_structs: VmStructs,
}

impl HotspotVmInfo {
    pub fn new(file_info: &HotspotFileInfo, pm: &ProcessMemory, bias: u64) -> Result<Self> {
        let mut info = HotspotVmInfo::default();
        info.vm_structs = VmStructs::new();
        info.parse_introspection(&file_info.type_ptrs, pm, bias)
            .unwrap();

        info.parse_introspection(&file_info.struct_ptrs, pm, bias)?;

        if file_info.jvmci_struct_ptrs.base != 0 {
            info.parse_introspection(&file_info.jvmci_struct_ptrs, pm, bias)?;
        }

        let (major, minor, security) = {
            if info.vm_structs.jdk_version.current != !0 {
                let jdk_version = pm.u32(info.vm_structs.jdk_version.current + bias)?;
                let major = jdk_version & 0xff;
                let minor = (jdk_version >> 8) & 0xff;
                let security = (jdk_version >> 16) & 0xff;
                info.vm_structs.abstract_vm_version.vm_major_version = 0;
                info.vm_structs.abstract_vm_version.vm_minor_version = 0;
                info.vm_structs.abstract_vm_version.vm_security_version = 0;
                (major, minor, security)
            } else {
                let major = pm.u32(info.vm_structs.abstract_vm_version.vm_major_version + bias)?;
                let minor = pm.u32(info.vm_structs.abstract_vm_version.vm_minor_version + bias)?;
                let security =
                    pm.u32(info.vm_structs.abstract_vm_version.vm_security_version + bias)?;
                info.vm_structs.jdk_version.current = 0;
                (major, minor, security)
            }
        };
        let build = pm.u32(info.vm_structs.abstract_vm_version.vm_build_number + bias)?;
        info.version = (major << 24) | (minor << 16) | (security << 8) | build;
        info.version_str = pm.string(info.vm_structs.abstract_vm_version.s_vm_release + bias)?;

        if major < 7 {
            bail!(
                "JVM version {}.{}.{}+{} (minimum is 7)",
                major,
                minor,
                security,
                build
            );
        }

        if info.vm_structs.constant_pool.source_file_name_index != !0 {
            // JDK15: Use ConstantPool.SourceFileNameIndex
            info.vm_structs.instance_klass.source_file_name_index = 0;
            info.vm_structs.instance_klass.source_file_name = 0;
        } else if info.vm_structs.instance_klass.source_file_name_index != !0 {
            // JDK8-14: Use InstanceKlass.SourceFileNameIndex
            info.vm_structs.constant_pool.source_file_name_index = 0;
            info.vm_structs.instance_klass.source_file_name = 0;
        } else {
            // JDK7: File name is direct Symbol*, adjust offsets with OopDesc due
            // to the base pointer type changes
            info.vm_structs.instance_klass.source_file_name += info.vm_structs.oop_desc.sizeof;
            if info.vm_structs.klass.name != !0 {
                info.vm_structs.klass.name += info.vm_structs.oop_desc.sizeof;
            }
            info.vm_structs.constant_pool.source_file_name_index = 0;
            info.vm_structs.instance_klass.source_file_name_index = 0;
        }

        // JDK-8: Only single CodeCache Heap, some CodeBlob and Nmethod changes
        if info.vm_structs.code_cache.heap != !0 {
            // Validate values that can be missing, fixup CompiledMethod offsets
            info.vm_structs.code_cache.heaps = 0;
            info.vm_structs.code_cache.high_bound = 0;
            info.vm_structs.code_cache.low_bound = 0;
            info.vm_structs.compiled_method.sizeof = info.vm_structs.nmethod.sizeof;
            info.vm_structs.compiled_method.deopt_handler_begin =
                info.vm_structs.nmethod.deoptimize_offset;
            info.vm_structs.compiled_method.method = info.vm_structs.nmethod.method;
            info.vm_structs.compiled_method.scopes_data_begin = 0;
        } else {
            // Reset the compatibility symbols not needed
            info.vm_structs.code_cache.heap = 0;
            info.vm_structs.nmethod.method = 0;
            info.vm_structs.nmethod.deoptimize_offset = 0;
            info.vm_structs.nmethod.scopes_data_offset = 0;
        }
        // JDK12+: Use Symbol.Length_and_refcount for Symbol.Length
        if info.vm_structs.symbol.length_and_refcount != !0 {
            // The symbol _length was merged and renamed to _symbol_length_and_refcount.
            // Calculate the _length offset from it.
            info.vm_structs.symbol.length = info.vm_structs.symbol.length_and_refcount + 2;
        } else {
            // Reset the non-used symbols so the check below does not fail
            info.vm_structs.symbol.length_and_refcount = 0;
        }

        // JDK16: use GenericGrowableArray as in JDK9-15 case
        if info.vm_structs.growable_array_base.len != !0 {
            info.vm_structs.generic_growable_array.len = info.vm_structs.growable_array_base.len;
        } else {
            // Reset the non-used symbols so the check below does not fail
            info.vm_structs.growable_array_base.len = 0;
        }

        // JDK20+: UNSIGNED5 encoding change (since 20.0.15)
        // https://github.com/openjdk/jdk20u/commit/8d3399bf5f354931b0c62d2ed8095e554be71680
        if info.version >= 0x1400000f {
            info.unsigned5_x = 1;
        }
        // TODO: check vm_structs
        Ok(info)
    }

    pub fn parse_introspection(
        &mut self,
        it: &HotspotIntrospectionTable,
        pm: &ProcessMemory,
        bias: u64,
    ) -> Result<()> {
        let stride = pm.u64(it.stride + bias)?;
        let type_offset = pm.u64(it.type_offset + bias)?;
        let addr_offset = pm.u64(it.address_offset + bias)?;
        let field_offset = pm.u64(it.field_offset + bias)?;
        let val_offset = pm.u64(it.value_offset + bias)?;
        let mut base = it.base + bias;

        if !it.skip_base_dref {
            base = pm.ptr(base)?;
        }

        let ptr = |data: &Vec<u8>, offset: usize| {
            if offset + 8 > data.len() {
                return 0;
            }

            LittleEndian::read_u64(&data[offset..])
        };

        if base == 0 || stride == 0 {
            bail!("bad introspection table data ({:#x} / {})", base, stride)
        }

        let mut e = vec![0; stride as usize];
        let mut addr = base;
        while let Ok(_) = pm.read_exact(addr, &mut e) {
            addr += stride;
            let type_name_ptr = ptr(&e, type_offset as usize);
            if type_name_ptr == 0 {
                break;
            }

            let type_name = self.vm_structs.fix_name(pm.string(type_name_ptr).unwrap());
            let fields = match self.vm_structs.type_fields.get(&type_name) {
                Some(x) => x,
                None => continue,
            };

            let field_name = {
                if it.field_offset != 0 {
                    let field_name_ptr = ptr(&e, field_offset as usize);
                    let field_name = pm.string(field_name_ptr).unwrap();
                    if field_name.is_empty() || !field_name.starts_with("_") {
                        continue;
                    } else {
                        self.vm_structs.fix_name(field_name)
                    }
                } else {
                    "Sizeof".to_owned()
                }
            };

            if type_name != "StubRoutines" && !fields.contains(&field_name) {
                continue;
            }

            let mut value = ptr(&e, addr_offset as usize);
            if value != 0 {
                value -= bias;
            } else {
                value = ptr(&e, val_offset as usize);
            }
            log::debug!(
                "type_name: {}, field_name: {}, value: {}",
                type_name,
                field_name,
                value
            );
            self.vm_structs.insert(type_name, field_name, value);
        }

        Ok(())
    }

    pub fn unsigned5_decoder<R: Read>(&self, r: R) -> Unsigned5Decoder<R> {
        Unsigned5Decoder::new(r, self.unsigned5_x)
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct VmStructs {
    pub type_fields: HashMap<String, HashSet<String>>,
    pub abstract_vm_version: AbstractVMVersion,
    pub jdk_version: JdkVersion,
    pub code_blob: CodeBlob,
    pub code_cache: CodeCache,
    pub code_heap: CodeHeap,
    pub compiled_method: CompiledMethod,
    pub constant_pool: ConstantPool,
    pub const_method: ConstMethod,
    pub generic_growable_array: GenericGrowableArray,
    pub growable_array_base: GrowableArrayBase,
    pub growable_array_int: GrowableArrayInt,
    pub heap_block: HeapBlock,
    pub instance_klass: InstanceKlass,
    pub klass: Klass,
    pub method: Method,
    pub nmethod: Nmethod,
    pub oop_desc: OopDesc,
    pub pc_desc: PcDesc,
    pub stub_routines: StubRoutines,
    pub symbol: Symbol,
    pub virtual_space: VirtualSpace,
}

impl VmStructs {
    pub fn new() -> Self {
        let fields = vec![
            ("Abstract_VM_Version", "_s_vm_release", 0),
            ("Abstract_VM_Version", "_vm_major_version", 0),
            ("Abstract_VM_Version", "_vm_minor_version", 0),
            ("Abstract_VM_Version", "_vm_security_version", 0),
            ("Abstract_VM_Version", "_vm_build_number", 0),
            ("JDK_Version", "_current", 0),
            ("CodeBlob", "Sizeof", 0),
            ("CodeBlob", "_name", 0),
            ("CodeBlob", "_frame_complete_offset", 0),
            ("CodeBlob", "_frame_size", 0),
            ("CodeBlob", "_code_begin", 0),
            ("CodeBlob", "_code_end", 0),
            ("CodeCache", "_heap", 0),
            ("CodeCache", "_heaps", 0),
            ("CodeCache", "_high_bound", 0),
            ("CodeCache", "_low_bound", 0),
            ("CodeHeap", "Sizeof", 0),
            ("CodeHeap", "_log2_segment_size", 0),
            ("CodeHeap", "_memory", 0),
            ("CodeHeap", "_segmap", 0),
            ("CompiledMethod", "Sizeof", 0),
            ("CompiledMethod", "_deopt_handler_begin", 0),
            ("CompiledMethod", "_method", 0),
            ("CompiledMethod", "_scopes_data_begin", 0),
            ("ConstantPool", "Sizeof", 0),
            ("ConstantPool", "_pool_holder", 0),
            ("ConstantPool", "_source_file_name_index", 0),
            ("ConstMethod", "Sizeof", 0),
            ("ConstMethod", "_constants", 0),
            ("ConstMethod", "_code_size", 0),
            ("ConstMethod", "_flags", 0),
            ("ConstMethod", "_name_index", 0),
            ("ConstMethod", "_signature_index", 0),
            ("GenericGrowableArray", "_len", 0),
            ("GrowableArrayBase", "_len", 0),
            ("GrowableArray<int>", "Sizeof", 0),
            ("GrowableArray<int>", "_data", 0),
            ("HeapBlock", "Sizeof", 0),
            ("InstanceKlass", "Sizeof", 0),
            ("InstanceKlass", "_source_file_name_index", 0),
            ("InstanceKlass", "_source_file_name", 0),
            ("Klass", "Sizeof", 0),
            ("Klass", "_name", 0),
            ("Method", "_constMethod", 0),
            ("nmethod", "Sizeof", 0),
            ("nmethod", "_compile_id", 0),
            ("nmethod", "_metadata_offset", 0),
            ("nmethod", "_scopes_pcs_offset", 0),
            ("nmethod", "_dependencies_offset", 0),
            ("nmethod", "_orig_pc_offset", 0),
            ("nmethod", "_deoptimize_offset", 0),
            ("nmethod", "_method", 0),
            ("nmethod", "_scopes_data_offset", 0),
            ("oopDesc", "Sizeof", 0),
            ("PcDesc", "Sizeof", 0),
            ("PcDesc", "_pc_offset", 0),
            ("PcDesc", "_scope_decode_offset", 0),
            ("StubRoutines", "Sizeof", 0),
            ("StubRoutines", "*", 0),
            ("Symbol", "Sizeof", 0),
            ("Symbol", "_body", 0),
            ("Symbol", "_length", 0),
            ("Symbol", "_length_and_refcount", 0),
            ("VirtualSpace", "_high_boundary", 0),
            ("VirtualSpace", "_low_boundary", 0),
        ];

        let mut type_fields: HashMap<String, HashSet<String>> = HashMap::new();
        for (n1, n2, _) in fields {
            let fields = type_fields.entry(n1.to_owned()).or_insert(HashSet::new());
            fields.insert(n2.to_owned());
        }

        VmStructs {
            type_fields,
            ..Default::default()
        }
    }

    pub fn fix_name(&self, name: String) -> String {
        match name.as_str() {
            "_code_offset" => "_code_begin".to_owned(),
            "_data_offset" => "_code_end".to_owned(),
            "constantPoolOopDesc" => "ConstantPool".to_owned(),
            "_flags" => "_flags".to_owned(),
            "constMethodOopDesc" => "ConstMethod".to_owned(),
            "instanceKlass" => "InstanceKlass".to_owned(),
            "methodOopDesc" => "Method".to_owned(),
            "_oops_offset" => "_metadata_offset".to_owned(),
            _ => name,
        }
    }

    pub fn insert(&mut self, type_name: String, field_name: String, value: u64) {
        match type_name.as_str() {
            "Abstract_VM_Version" => self.abstract_vm_version.set_field(field_name, value),
            "JDK_Version" => self.jdk_version.set_field(field_name, value),
            "CodeBlob" => self.code_blob.set_field(field_name, value as u32),
            "CodeCache" => self.code_cache.set_field(field_name, value as u32),
            "CodeHeap" => self.code_heap.set_field(field_name, value as u32),
            "CompiledMethod" => self.compiled_method.set_field(field_name, value as u32),
            "ConstantPool" => self.constant_pool.set_field(field_name, value as u32),
            "ConstMethod" => self.const_method.set_field(field_name, value as u32),
            "GenericGrowableArray" => self
                .generic_growable_array
                .set_field(field_name, value as u32),
            "GrowableArrayBase" => self.growable_array_base.set_field(field_name, value as u32),
            "GrowableArray<int>" => self.growable_array_int.set_field(field_name, value as u32),
            "HeapBlock" => self.heap_block.set_field(field_name, value as u32),
            "InstanceKlass" => self.instance_klass.set_field(field_name, value as u32),
            "Klass" => self.klass.set_field(field_name, value as u32),
            "Method" => self.method.set_field(field_name, value as u32),
            "nmethod" => self.nmethod.set_field(field_name, value as u32),
            "oopDesc" => self.oop_desc.set_field(field_name, value as u32),
            "PcDesc" => self.pc_desc.set_field(field_name, value as u32),
            "StubRoutines" => self.stub_routines.set_field(field_name, value),
            "Symbol" => self.symbol.set_field(field_name, value as u32),
            "VirtualSpace" => self.virtual_space.set_field(field_name, value as u32),
            _ => panic!("Unknown type: {}", type_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AbstractVMVersion {
    pub s_vm_release: u64,
    pub vm_major_version: u64,
    pub vm_minor_version: u64,
    pub vm_security_version: u64,
    pub vm_build_number: u64,
}

impl Default for AbstractVMVersion {
    fn default() -> Self {
        Self {
            s_vm_release: !0,
            vm_major_version: !0,
            vm_minor_version: !0,
            vm_security_version: !0,
            vm_build_number: !0,
        }
    }
}

impl AbstractVMVersion {
    /// Set the value of a field by its name.
    pub fn set_field(&mut self, field_name: String, value: u64) {
        match field_name.as_str() {
            "_s_vm_release" => self.s_vm_release = value,
            "_vm_major_version" => self.vm_major_version = value,
            "_vm_minor_version" => self.vm_minor_version = value,
            "_vm_security_version" => self.vm_security_version = value,
            "_vm_build_number" => self.vm_build_number = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JdkVersion {
    pub current: u64,
}

impl Default for JdkVersion {
    fn default() -> Self {
        Self { current: !0 }
    }
}

impl JdkVersion {
    /// Set the value of a field by its name.
    pub fn set_field(&mut self, field_name: String, value: u64) {
        match field_name.as_str() {
            "_current" => self.current = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeBlob {
    pub sizeof: u32,
    pub name: u32,
    pub frame_complete_offset: u32,
    pub frame_size: u32,
    pub code_begin: u32,
    pub code_end: u32,
}

impl Default for CodeBlob {
    fn default() -> Self {
        Self {
            sizeof: !0,
            name: !0,
            frame_complete_offset: !0,
            frame_size: !0,
            code_begin: !0,
            code_end: !0,
        }
    }
}

impl CodeBlob {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_name" => self.name = value,
            "_frame_complete_offset" => self.frame_complete_offset = value,
            "_frame_size" => self.frame_size = value,
            "_code_begin" => self.code_begin = value,
            "_code_end" => self.code_end = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeCache {
    pub heap: u64,
    pub heaps: u64,
    pub high_bound: u64,
    pub low_bound: u64,
}

impl Default for CodeCache {
    fn default() -> Self {
        Self {
            heap: !0,
            heaps: !0,
            high_bound: !0,
            low_bound: !0,
        }
    }
}

impl CodeCache {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "_heap" => self.heap = value as u64,
            "_heaps" => self.heaps = value as u64,
            "_high_bound" => self.high_bound = value as u64,
            "_low_bound" => self.low_bound = value as u64,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeHeap {
    pub sizeof: u32,
    pub log2_segment_size: u32,
    pub memory: u32,
    pub segmap: u32,
}

impl Default for CodeHeap {
    fn default() -> Self {
        Self {
            sizeof: !0,
            log2_segment_size: !0,
            memory: !0,
            segmap: !0,
        }
    }
}

impl CodeHeap {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_log2_segment_size" => self.log2_segment_size = value,
            "_memory" => self.memory = value,
            "_segmap" => self.segmap = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledMethod {
    pub sizeof: u32,
    pub deopt_handler_begin: u32,
    pub method: u32,
    pub scopes_data_begin: u32,
}

impl Default for CompiledMethod {
    fn default() -> Self {
        Self {
            sizeof: !0,
            deopt_handler_begin: !0,
            method: !0,
            scopes_data_begin: !0,
        }
    }
}

impl CompiledMethod {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_deopt_handler_begin" => self.deopt_handler_begin = value,
            "_method" => self.method = value,
            "_scopes_data_begin" => self.scopes_data_begin = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConstantPool {
    pub sizeof: u32,
    pub pool_holder: u32,
    pub source_file_name_index: u32,
}

impl Default for ConstantPool {
    fn default() -> Self {
        Self {
            sizeof: !0,
            pool_holder: !0,
            source_file_name_index: !0,
        }
    }
}

impl ConstantPool {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_pool_holder" => self.pool_holder = value,
            "_source_file_name_index" => self.source_file_name_index = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConstMethod {
    pub sizeof: u32,
    pub constants: u32,
    pub code_size: u32,
    pub flags: u32,
    pub name_index: u32,
    pub signature_index: u32,
}

impl Default for ConstMethod {
    fn default() -> Self {
        Self {
            sizeof: !0,
            constants: !0,
            code_size: !0,
            flags: !0,
            name_index: !0,
            signature_index: !0,
        }
    }
}

impl ConstMethod {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_constants" => self.constants = value,
            "_code_size" => self.code_size = value,
            "_flags" => self.flags = value,
            "_name_index" => self.name_index = value,
            "_signature_index" => self.signature_index = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GenericGrowableArray {
    pub len: u32,
}

impl Default for GenericGrowableArray {
    fn default() -> Self {
        Self { len: !0 }
    }
}

impl GenericGrowableArray {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "_len" => self.len = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GrowableArrayBase {
    pub len: u32,
}

impl Default for GrowableArrayBase {
    fn default() -> Self {
        Self { len: !0 }
    }
}

impl GrowableArrayBase {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "_len" => self.len = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GrowableArrayInt {
    pub sizeof: u32,
    pub data: u32,
}

impl Default for GrowableArrayInt {
    fn default() -> Self {
        Self {
            sizeof: !0,
            data: !0,
        }
    }
}

impl GrowableArrayInt {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_data" => self.data = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeapBlock {
    pub sizeof: u32,
}

impl Default for HeapBlock {
    fn default() -> Self {
        Self { sizeof: !0 }
    }
}

impl HeapBlock {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstanceKlass {
    pub sizeof: u32,
    pub source_file_name_index: u32,
    pub source_file_name: u32, // JDK -7 only
}

impl Default for InstanceKlass {
    fn default() -> Self {
        Self {
            sizeof: !0,
            source_file_name_index: !0,
            source_file_name: !0,
        }
    }
}

impl InstanceKlass {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_source_file_name_index" => self.source_file_name_index = value,
            "_source_file_name" => self.source_file_name = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Klass {
    pub sizeof: u32,
    pub name: u32,
}

impl Default for Klass {
    fn default() -> Self {
        Self {
            sizeof: !0,
            name: !0,
        }
    }
}

impl Klass {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_name" => self.name = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Method {
    pub const_method: u32,
}

impl Default for Method {
    fn default() -> Self {
        Self { const_method: !0 }
    }
}

impl Method {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "_constMethod" => self.const_method = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Nmethod {
    pub sizeof: u32,
    pub compile_id: u32,
    pub metadata_offset: u32,
    pub scopes_pcs_offset: u32,
    pub dependencies_offset: u32,
    pub orig_pc_offset: u32,
    pub deoptimize_offset: u32,
    pub method: u32,
    pub scopes_data_offset: u32,
}

impl Default for Nmethod {
    fn default() -> Self {
        Self {
            sizeof: !0,
            compile_id: !0,
            metadata_offset: !0,
            scopes_pcs_offset: !0,
            dependencies_offset: !0,
            orig_pc_offset: !0,
            deoptimize_offset: !0,
            method: !0,
            scopes_data_offset: !0,
        }
    }
}

impl Nmethod {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_compile_id" => self.compile_id = value,
            "_metadata_offset" => self.metadata_offset = value,
            "_scopes_pcs_offset" => self.scopes_pcs_offset = value,
            "_dependencies_offset" => self.dependencies_offset = value,
            "_orig_pc_offset" => self.orig_pc_offset = value,
            "_deoptimize_offset" => self.deoptimize_offset = value,
            "_method" => self.method = value,
            "_scopes_data_offset" => self.scopes_data_offset = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OopDesc {
    pub sizeof: u32,
}

impl Default for OopDesc {
    fn default() -> Self {
        Self {
            sizeof: !0, // 使用按位取反操作符来设置所有位为1
        }
    }
}
impl OopDesc {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PcDesc {
    pub sizeof: u32,
    pub pc_offset: u32,
    pub scope_decode_offset: u32,
}

impl Default for PcDesc {
    fn default() -> Self {
        Self {
            sizeof: !0,
            pc_offset: !0,
            scope_decode_offset: !0,
        }
    }
}

impl PcDesc {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_pc_offset" => self.pc_offset = value,
            "_scope_decode_offset" => self.scope_decode_offset = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}
#[derive(Debug, Clone)]
pub struct StubRoutines {
    pub sizeof: u32,
    pub catch_all: HashMap<String, u64>,
}

impl Default for StubRoutines {
    fn default() -> Self {
        Self {
            sizeof: !0,
            catch_all: HashMap::new(),
        }
    }
}

impl StubRoutines {
    pub fn set_field(&mut self, field_name: String, value: u64) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value as u32,
            _ => {
                self.catch_all.insert(field_name, value);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub sizeof: u32,
    pub body: u32,
    pub length: u32,
    pub length_and_refcount: u32,
}

impl Default for Symbol {
    fn default() -> Self {
        Self {
            sizeof: !0,
            body: !0,
            length: !0,
            length_and_refcount: !0,
        }
    }
}

impl Symbol {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "Sizeof" => self.sizeof = value,
            "_body" => self.body = value,
            "_length" => self.length = value,
            "_length_and_refcount" => self.length_and_refcount = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VirtualSpace {
    pub high_boundary: u32,
    pub low_boundary: u32,
}

impl Default for VirtualSpace {
    fn default() -> Self {
        Self {
            high_boundary: !0,
            low_boundary: !0,
        }
    }
}

impl VirtualSpace {
    pub fn set_field(&mut self, field_name: String, value: u32) {
        match field_name.as_str() {
            "_high_boundary" => self.high_boundary = value,
            "_low_boundary" => self.low_boundary = value,
            _ => panic!("Unknown field: {}", field_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::process::maps::ProcessMaps;
    use crate::process::process::Process;
    use crate::symbollizer::elf::ElfFile;
    use crate::symbollizer::file_cache::FileInfo;

    use super::HotspotFileInfo;
    use super::HotspotVmInfo;

    #[test]
    fn test_java() {
        let path =
            "/usr/lib/jvm/java-11-openjdk-11.0.23.0.9-3.0.1.1.al8.x86_64/lib/server/libjvm.so";
        let elf = ElfFile::new(path).unwrap();
        let elf_file = elf.object_file();

        let _info = HotspotFileInfo::new(&"sda".to_owned(), &elf_file).unwrap();
    }

    #[test]
    fn test_vminfo() {
        let proc = Process::new(3001917);
        let pm = proc.memory().unwrap();

        let maps = ProcessMaps::new(proc.pid()).unwrap();

        for (_, entry) in maps.iter() {
            if entry.is_executable() && entry.path.as_ref().unwrap().contains("libjvm.so") {
                let file_info = FileInfo::from_path(&entry.file_path(proc.pid())).unwrap();
                let bias = entry.start
                    - file_info
                        .file_offset_to_virtual_address(entry.offset)
                        .unwrap();
                println!("bias: {}", bias);
                let elf = ElfFile::new(&entry.file_path(proc.pid())).unwrap();
                let elf_file = elf.object_file();

                let jvm_file_info = HotspotFileInfo::new(&"sdsa".to_owned(), &elf_file).unwrap();

                HotspotVmInfo::new(&jvm_file_info, &pm, bias).unwrap();
            }
        }
    }
}
