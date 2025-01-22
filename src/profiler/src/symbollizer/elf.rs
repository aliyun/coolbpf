use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use byteorder::ByteOrder;
use byteorder::NativeEndian;
use gimli::write::CommonInformationEntry;
use gimli::BaseAddresses;
use gimli::CfaRule;
use gimli::EhFrame;
use gimli::EhFrameHdr;
use gimli::EhHdrTable;
use gimli::Encoding;
use gimli::EndianReader;
use gimli::EvaluationResult;
use gimli::Operation;
use gimli::Reader;
use gimli::ReaderOffset as _;
use gimli::RegisterRule;
use gimli::RunTimeEndian;
use gimli::Section;
use gimli::UnwindContext;
use gimli::UnwindExpression;
use gimli::UnwindSection;
use gimli::UnwindTableRow;
use gimli::X86_64;
use memmap2::Mmap;
use object::elf::*;
use object::read::elf::*;
use object::Endianness;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::ObjectSymbolTable;
use object::ReadRef;
use object::Symbol;
use object::SymbolKind;
use regex::Regex;
use std::borrow;
use std::borrow::Cow;
use std::collections::HashMap;
use std::default;
use std::fmt;
use std::fs::File;
use std::io::ErrorKind;
use symbolic_common::Name;
use symbolic_demangle::demangle;
use symbolic_demangle::Demangle;
use symbolic_demangle::DemangleOptions;
use typed_arena::Arena;

use crate::probes::types::bpf::UNWIND_COMMAND_PLT;
use crate::probes::types::bpf::UNWIND_OPCODE_BASE_CFA;
use crate::probes::types::bpf::UNWIND_OPCODE_BASE_FP;
use crate::probes::types::bpf::UNWIND_OPCODE_BASE_REG;
use crate::probes::types::bpf::UNWIND_OPCODE_BASE_SP;
use crate::probes::types::bpf::UNWIND_OPCODE_COMMAND;
use crate::probes::unwind_info::UnwindInfo;

use super::file_cache::ProgramAddress;

const UNWIND_HINT_NONE: u8 = 0;
const UNWIND_HINT_KEEP: u8 = 1;
const UNWIND_HINT_GAP: u8 = 4;

#[derive(Debug, Default)]
struct RelocationMap(object::read::RelocationMap);

impl RelocationMap {
    fn add(&mut self, file: &object::File, section: &object::Section) {
        for (offset, relocation) in section.relocations() {
            if let Err(e) = self.0.add(file, offset, relocation) {
                eprintln!(
                    "Relocation error for section {} at offset 0x{:08x}: {}",
                    section.name().unwrap(),
                    offset,
                    e
                );
            }
        }
    }
}

impl<'a> gimli::read::Relocate for &'a RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

type Relocate<'a, R> = gimli::RelocateReader<R, &'a RelocationMap>;

pub const REG_UNDEFINED: u64 = 128;
pub const REG_CFA: u64 = 129;
pub const REG_CFA_VAL: u64 = 130;
pub const REG_SAME: u64 = 131;
pub const REG_EXPR_PLT: u64 = 256;
pub const REG_EXPR_REG_DEREF: u64 = 257;
pub const REG_EXPR_REG_REG_DEREF: u64 = 258;
pub const REG_EXPR_REG: u64 = 259;

#[derive(Clone)]
struct VMReg {
    reg: u64,
    off: i64,
}

impl Default for VMReg {
    fn default() -> Self {
        Self {
            reg: REG_UNDEFINED,
            off: 0,
        }
    }
}

#[derive(Default, Clone)]
struct VMRegs {
    cfa: VMReg,
    fp: VMReg,
    ra: VMReg,
}

#[derive(Debug, Clone)]
pub struct UserStackDelta {
    pub addr: u64,
    pub hint: u8,
    pub info: UnwindInfo,
}

impl fmt::Display for UserStackDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{Address:{} Hints:{} Info:{}}}",
            self.addr, self.hint, self.info
        )
    }
}

#[derive(Default)]
struct State {
    pc: u64,
    curr: VMRegs,
    stack: [VMRegs; 2],
    stack_idx: i32,
}

#[derive(Default, Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,
    pub start: u64,
    pub end: u64,
}

impl ElfSymbol {
    pub fn not_found(addr: u64) -> Self {
        ElfSymbol {
            name: format!("!{:x}", addr),
            start: u64::MAX,
            end: u64::MAX,
        }
    }
}

impl State {}
#[derive(Debug)]
pub struct ElfFile {
    pub file: File,
    mmap_ref: Mmap,
}

impl ElfFile {
    pub fn new(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mmap_ref = unsafe { memmap2::Mmap::map(&file)? };

        Ok(Self { mmap_ref, file })
    }

    pub fn from_file(file: File) -> Result<Self> {
        let mmap_ref = unsafe { memmap2::Mmap::map(&file)? };

        Ok(Self { mmap_ref, file })
    }

    pub fn object_file(&self) -> object::File {
        object::File::parse(&*self.mmap_ref).expect("failed to parse elf file")
    }

    pub fn parse_symbols(file: &File, dst: &mut Vec<ElfSymbol>) {
        let mmap_ref = unsafe { memmap2::Mmap::map(file).unwrap() };
        let elf = object::File::parse(&*mmap_ref).expect("failed to parse elf file");

        let start = dst.len();
        for sym in elf.symbols() {
            if sym.is_undefined() || sym.kind() != SymbolKind::Text {
                continue;
            }
            let es = ElfSymbol {
                name: sym.name().unwrap().to_string(),
                start: sym.address(),
                end: sym.address() + sym.size(),
            };
            dst.push(es);
        }

        dst[start..].sort_by_key(|a| a.start);
    }

    pub fn parse_symbols2(elf: object::File, dst: &mut Vec<ElfSymbol>) {
        let re = Regex::new(r#"<.*?>"#).unwrap();
        let start = dst.len();
        for sym in elf.symbols() {
            if sym.is_undefined() || sym.kind() != SymbolKind::Text {
                continue;
            }
            let demangle_name = Name::from(sym.name().unwrap())
                .demangle(DemangleOptions::name_only())
                .map_or_else(|| sym.name().unwrap().to_string(), |d| d);

            // let mut name = if let Some(idx) = demangle_name.rfind("::") {
            //     demangle_name[(idx + 2)..].to_string()
            // } else {
            //     demangle_name.clone()
            // };
            // if name.contains('<') {
            //     name = re.replace_all(&name, "").to_string();
            // }
            // assert!(
            //     !name.is_empty(),
            //     "demangle_name: {}, name: {}",
            //     demangle_name,
            //     name
            // );

            let es = ElfSymbol {
                name: demangle_name,
                start: sym.address(),
                end: sym.address() + sym.size(),
            };
            dst.push(es);
        }

        for sym in elf.dynamic_symbols() {
            if sym.is_undefined() || sym.kind() != SymbolKind::Text {
                continue;
            }
            let demangle_name = Name::from(sym.name().unwrap())
                .demangle(DemangleOptions::name_only())
                .map_or_else(|| sym.name().unwrap().to_string(), |d| d);

            // let mut name = if let Some(idx) = demangle_name.rfind("::") {
            //     demangle_name[(idx + 2)..].to_string()
            // } else {
            //     demangle_name.clone()
            // };

            // if name.contains('<') {
            //     name = re.replace_all(&name, "").to_string();
            // }

            // assert!(
            //     !name.is_empty(),
            //     "demangle_name: {}, name: {}",
            //     demangle_name,
            //     name
            // );
            let es = ElfSymbol {
                name: demangle_name,
                start: sym.address(),
                end: sym.address() + sym.size(),
            };
            dst.push(es);
        }

        dst[start..].sort_by_key(|a| a.start);
    }

    pub fn read_at<'a>(elf: &'a object::File, addr: u64, sz: usize) -> Result<&'a [u8]> {
        if let object::File::Elf64(elf) = elf {
            for ph in elf.elf_program_headers() {
                if ph.p_type(elf.endianness()) == PT_LOAD
                    && addr >= ph.p_vaddr(elf.endianness())
                    && addr < ph.p_vaddr(elf.endianness()) + ph.p_memsz(elf.endianness())
                {
                    let off = addr - ph.p_vaddr(elf.endianness());
                    if off < ph.p_filesz(elf.endianness()) {
                        let end = std::cmp::min(sz as u64, ph.p_filesz(elf.endianness()) - off);
                        match elf
                            .data()
                            .read_bytes_at(ph.p_offset(elf.endianness()) + off, sz as u64)
                        {
                            Ok(data) => {
                                return Ok(data);
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
        panic!("failed to read data")
    }

    pub fn read_u32(elf: &object::File, addr: u64) -> Result<u32> {
        let data = ElfFile::read_at(elf, addr, 4)?;
        Ok(NativeEndian::read_u32(data))
    }

    pub fn read_u64(elf: &object::File, addr: u64) -> Result<u64> {
        let data = ElfFile::read_at(elf, addr, 8)?;
        Ok(NativeEndian::read_u64(data))
    }

    pub fn read_string<'a>(elf: &'a object::File, addr: u64, sz: usize) -> Result<Cow<'a, str>> {
        if let object::File::Elf64(elf) = elf {
            for ph in elf.elf_program_headers() {
                if ph.p_type(elf.endianness()) == PT_LOAD
                    && addr >= ph.p_vaddr(elf.endianness())
                    && addr < ph.p_vaddr(elf.endianness()) + ph.p_memsz(elf.endianness())
                {
                    let off = addr - ph.p_vaddr(elf.endianness());
                    if off < ph.p_filesz(elf.endianness()) {
                        let start = ph.p_offset(elf.endianness()) + off;
                        let end =
                            start + std::cmp::min(sz as u64, ph.p_filesz(elf.endianness()) - off);
                        if let Ok(data) = elf.data().read_bytes_at_until(start..end, 0) {
                            return Ok(String::from_utf8_lossy(data));
                        }
                    }
                }
            }
        }
        bail!("failed to read string")
    }

    pub fn parse_ph(file: &File) -> Result<Vec<ProgramAddress>> {
        let mmap_ref = unsafe { memmap2::Mmap::map(file)? };
        let elf = FileHeader64::<Endianness>::parse(&*mmap_ref)?;
        let endian = elf.endian()?;
        let mut progs = vec![];
        for ph in elf.program_headers(elf.endian()?, &*mmap_ref)? {
            if ph.p_type(elf.endian()?) != PT_LOAD || ph.p_flags(elf.endian()?) & PF_X == 0 {
                continue;
            }

            progs.push(ProgramAddress {
                offset: ph.p_offset(elf.endian()?),
                vaddr: ph.p_vaddr(elf.endian()?),
                filezs: ph.p_filesz(elf.endian()?),
            });
        }

        Ok(progs)
    }

    pub fn lookup_symbol<'a>(elf: &'a object::File, name: &str) -> Result<Symbol<'a, 'a>> {
        let name_bytes = name.as_bytes();
        if let Some(sym) = elf
            .dynamic_symbols()
            .find(|x| x.name_bytes() == Ok(&name_bytes))
        {
            return Ok(sym);
        }

        elf.symbol_by_name_bytes(name_bytes)
            .ok_or(anyhow!("symbol {} not found", name))
    }

    // parse eh_frame and return stack_deltas
    pub fn parse_eh_frame(file: &File) -> Result<Vec<UserStackDelta>> {
        let mmap_ref = unsafe { memmap2::Mmap::map(file)? };
        let elf = object::File::parse(&*mmap_ref)?;
        let endian = if elf.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let arena_data = Arena::new();
        let arena_relocations = Arena::new();
        let mut load_section = |id: gimli::SectionId| -> Result<_> {
            load_file_section(id, &elf, endian, false, &arena_data, &arena_relocations)
        };
        let mut eh_frame = gimli::EhFrame::load(load_section).unwrap();

        let address_size = elf
            .architecture()
            .address_size()
            .map(|w| w.bytes())
            .unwrap_or(std::mem::size_of::<usize>() as u8);
        eh_frame.set_address_size(address_size);

        let mut bases = gimli::BaseAddresses::default();
        if let Some(section) = elf.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(section.address());
        }
        if let Some(section) = elf.section_by_name(".eh_frame") {
            bases = bases.set_eh_frame(section.address());
        }
        if let Some(section) = elf.section_by_name(".text") {
            bases = bases.set_text(section.address());
        }
        if let Some(section) = elf.section_by_name(".got") {
            bases = bases.set_got(section.address());
        }

        let mut entries = eh_frame.entries(&bases);
        let mut ctx = UnwindContext::new();
        let mut cies = HashMap::new();
        let mut deltas = vec![];
        loop {
            match entries.next()? {
                None => break,
                Some(gimli::CieOrFde::Cie(cie)) => {
                    let instructions = cie.instructions(&eh_frame, &bases);
                    // parse_cfi_instructions(&cie, instructions, true)?;
                }
                Some(gimli::CieOrFde::Fde(partial)) => {
                    let fde = match partial.parse(|_, bases, o| {
                        cies.entry(o)
                            .or_insert_with(|| eh_frame.cie_from_offset(bases, o))
                            .clone()
                    }) {
                        Ok(fde) => fde,
                        Err(e) => {
                            log::error!("Failed to parse FDE: {}", e);
                            continue;
                        }
                    };
                    let mut table = fde.rows(&eh_frame, &bases, &mut ctx)?;
                    let mut hint = UNWIND_HINT_KEEP;
                    while let Some(row) = table.next_row()? {
                        let delta = UserStackDelta {
                            addr: row.start_address(),
                            hint,
                            info: get_unwind_info(
                                row.start_address(),
                                &eh_frame,
                                fde.cie().encoding(),
                                row,
                            ),
                        };
                        deltas.push(delta);
                        hint = UNWIND_HINT_NONE;
                    }

                    let end = fde.initial_address() + fde.len();

                    deltas.push(UserStackDelta {
                        addr: end,
                        hint: UNWIND_HINT_GAP,
                        info: if end == elf.entry() {
                            UnwindInfo::stop()
                        } else {
                            UnwindInfo::invalid()
                        },
                    })
                }
            }
        }

        deltas.sort_by(|a, b| {
            if a.addr != b.addr {
                return a.addr.cmp(&b.addr);
            }
            return a.info.raw.opcode.cmp(&b.info.raw.opcode);
        });

        let total_deltas_len = deltas.len();
        log::debug!("total deltas: {}", total_deltas_len);

        let mut max_delta = 0;

        for i in 0..total_deltas_len {
            let mut curr = i;
            if max_delta > 0 {
                let mut prev = max_delta - 1;
                if deltas[prev].hint & UNWIND_HINT_GAP != 0
                    && deltas[prev].addr + 15 >= deltas[curr].addr
                {
                    if max_delta <= 1 || deltas[max_delta - 2].info != deltas[curr].info {
                        deltas[prev] = deltas[curr].clone();
                        continue;
                    }
                    prev = max_delta - 2;
                    max_delta -= 1;
                }
                if deltas[prev].info == deltas[curr].info {
                    deltas[prev].hint |= deltas[curr].hint & UNWIND_HINT_KEEP;
                    continue;
                }

                if deltas[prev].addr == deltas[curr].addr {
                    deltas[prev] = deltas[curr].clone();
                    continue;
                }
            }

            deltas[max_delta] = deltas[curr].clone();
            max_delta += 1;
        }

        deltas.truncate(max_delta);
        log::debug!("total number of deltas after cutting: {}", deltas.len());
        Ok(deltas)
    }
}

fn get_unwind_info<R: Reader>(
    addr: u64,
    eh_frame: &gimli::EhFrame<R>,
    enc: Encoding,
    row: &UnwindTableRow<R::Offset>,
) -> UnwindInfo {
    let ra = row.register(X86_64::RA);
    let fp = row.register(X86_64::RBP);
    let cfa = row.cfa();
    if ra == RegisterRule::Undefined {
        return UnwindInfo::stop();
    }

    if let RegisterRule::Offset(off) = ra {
        if let &CfaRule::RegisterAndOffset { register, offset } = cfa {
            if register == X86_64::RSP && off + offset < 0 {
                return UnwindInfo::stop();
            }
        } else {
            if off != -8 {
                return UnwindInfo::invalid();
            }
        }
    } else {
        return UnwindInfo::invalid();
    }

    let mut info = UnwindInfo::default();
    match fp {
        RegisterRule::Offset(off) => {
            let set_fp = {
                if let &CfaRule::RegisterAndOffset { register, offset } = cfa {
                    if register == X86_64::RSP {
                        if off < 0 && off >= -1 * offset {
                            true
                        } else {
                            false
                        }
                    } else {
                        true
                    }
                } else {
                    true
                }
            };

            if set_fp {
                info.set_fpopcode(UNWIND_OPCODE_BASE_CFA as u8);
                info.set_fpparam(off as i32);
            }
        }
        RegisterRule::Expression(expr) => {
            let expr = expr.get(eh_frame).unwrap();
            let mut eval = expr.evaluation(enc);
            let res = eval.evaluate().unwrap();
            match res {
                EvaluationResult::RequiresRegister {
                    register,
                    base_type,
                } => {
                    if register == X86_64::RBP {
                        info.set_fpopcode(UNWIND_OPCODE_BASE_FP as u8);
                    }
                }
                _ => {
                    log::error!(
                        "unsupported register expression, addr: {:x}, eval: {:?}",
                        addr,
                        res
                    )
                }
            }
        }

        _ => {}
    }

    match row.cfa() {
        &gimli::CfaRule::RegisterAndOffset { register, offset } => match register {
            X86_64::RBP => {
                info.set_opcode(UNWIND_OPCODE_BASE_FP as u8);
                info.set_param(offset as i32);
            }
            X86_64::RSP => {
                if offset != 0 {
                    info.set_opcode(UNWIND_OPCODE_BASE_SP as u8);
                    info.set_param(offset as i32);
                }
            }
            X86_64::RAX | X86_64::R9 | X86_64::R11 | X86_64::R15 => {
                if offset % 8 == 0 {
                    info.set_opcode(UNWIND_OPCODE_BASE_REG as u8);
                    info.set_param((register.0 as i32) + ((offset as i32) << 1));
                }
            }
            _ => {
                log::warn!(
                    "unsupported other cfa rule with other register: {:?}",
                    register
                )
            }
        },

        gimli::CfaRule::Expression(e) => {
            let mut iter = e.get(eh_frame).unwrap().operations(enc);
            let mut ops = vec![];
            loop {
                match iter.next().unwrap() {
                    Some(op) => match op {
                        Operation::RegisterOffset { .. } => {
                            ops.push(ExprOp::RegisterOffset);
                        }
                        Operation::UnsignedConstant { .. } => {
                            ops.push(ExprOp::UnsignedConstant);
                        }
                        Operation::And => {
                            ops.push(ExprOp::And);
                        }
                        Operation::Ge => {
                            ops.push(ExprOp::Ge);
                        }
                        Operation::Shl => {
                            ops.push(ExprOp::Shl);
                        }
                        Operation::Plus => {
                            ops.push(ExprOp::Plus);
                        }
                        Operation::Deref { .. } => {
                            ops.push(ExprOp::Deref);
                        }
                        Operation::PlusConstant { .. } => {
                            ops.push(ExprOp::PlusConstant);
                        }
                        Operation::Mul => {
                            ops.push(ExprOp::Mul);
                        }
                        _ => {
                            panic!("unexpected opertaion: {:?}", op)
                        }
                    },

                    None => break,
                }
            }

            if ops
                == vec![
                    ExprOp::RegisterOffset,
                    ExprOp::RegisterOffset,
                    ExprOp::UnsignedConstant,
                    ExprOp::And,
                    ExprOp::UnsignedConstant,
                    ExprOp::Ge,
                    ExprOp::UnsignedConstant,
                    ExprOp::Shl,
                    ExprOp::Plus,
                ]
            {
                info.set_opcode(UNWIND_OPCODE_COMMAND as u8);
                info.set_param(UNWIND_COMMAND_PLT as i32);
            } else if ops == vec![ExprOp::RegisterOffset] {
                // TODO: support this
            } else if ops == vec![ExprOp::RegisterOffset, ExprOp::Deref] {
                // TODO: support this
            } else if ops == vec![ExprOp::RegisterOffset, ExprOp::Deref, ExprOp::PlusConstant] {
                // TODO: support this
            } else if ops
                == vec![
                    ExprOp::RegisterOffset,
                    ExprOp::RegisterOffset,
                    ExprOp::UnsignedConstant,
                    ExprOp::Mul,
                    ExprOp::Plus,
                    ExprOp::Deref,
                    ExprOp::PlusConstant,
                ]
            {
                // TODO: support this
            } else {
                log::error!("unsupported cfa expression")
            }
        }
    }

    info
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprOp {
    RegisterOffset,
    UnsignedConstant,
    And,
    Ge,
    Shl,
    Plus,
    Deref,
    PlusConstant,
    Mul,
}

fn load_file_section<'input, 'arena, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    is_dwo: bool,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<Relocate<'arena, gimli::EndianSlice<'arena, Endian>>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo {
        id.dwo_name()
    } else if file.format() == object::BinaryFormat::Xcoff {
        id.xcoff_name()
    } else {
        Some(id.name())
    };

    let data = match name.and_then(|name| file.section_by_name(name)) {
        Some(ref section) => {
            // DWO sections never have relocations, so don't bother.
            if !is_dwo {
                relocations.add(file, section);
            }
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };
    let data_ref = arena_data.alloc(data);
    let section = gimli::EndianSlice::new(data_ref, endian);
    let relocations = arena_relocations.alloc(relocations);
    Ok(Relocate::new(section, relocations))
}

fn parse_eh_frame<R: Reader>(file: &object::File, mut eh_frame: gimli::EhFrame<R>) -> Result<()> {
    // TODO: this might be better based on the file format.
    let address_size = file
        .architecture()
        .address_size()
        .map(|w| w.bytes())
        .unwrap_or(std::mem::size_of::<usize>() as u8);
    eh_frame.set_address_size(address_size);

    // There are other things we could match but currently don't
    #[allow(clippy::single_match)]
    match file.architecture() {
        object::Architecture::Aarch64 => eh_frame.set_vendor(gimli::Vendor::AArch64),
        _ => {}
    }

    let mut bases = gimli::BaseAddresses::default();
    if let Some(section) = file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(section.address());
    }
    if let Some(section) = file.section_by_name(".eh_frame") {
        bases = bases.set_eh_frame(section.address());
    }
    if let Some(section) = file.section_by_name(".text") {
        bases = bases.set_text(section.address());
    }
    if let Some(section) = file.section_by_name(".got") {
        bases = bases.set_got(section.address());
    }

    let mut cies = HashMap::new();
    let mut state_cache: HashMap<u64, VMRegs> = HashMap::new();
    // let deltas = vec![];

    let mut entries = eh_frame.entries(&bases);
    let mut state = State::default();
    loop {
        match entries.next()? {
            None => return Ok(()),
            Some(gimli::CieOrFde::Cie(cie)) => {
                let instructions = cie.instructions(&eh_frame, &bases);
                // parse_cfi_instructions(&cie, instructions, true)?;
            }
            Some(gimli::CieOrFde::Fde(partial)) => {
                let off: u64 = partial.offset().into_u64();
                let fde = match partial.parse(|_, bases, o| {
                    cies.entry(o)
                        .or_insert_with(|| eh_frame.cie_from_offset(bases, o))
                        .clone()
                }) {
                    Ok(fde) => fde,
                    Err(e) => {
                        log::error!("Failed to parse FDE: {}", e);
                        continue;
                    }
                };
                let instructions = fde.instructions(&eh_frame, &bases);
                parse_cfi_instructions(
                    &mut state,
                    &eh_frame,
                    fde.cie(),
                    state_cache.get(&off).unwrap(),
                    instructions,
                    false,
                )?;
            }
        }
    }
}

fn parse_cfi_instructions<R: Reader>(
    state: &mut State,
    eh_frame: &gimli::EhFrame<R>,
    cie: &gimli::CommonInformationEntry<R>,
    initial_state: &VMRegs,
    mut insns: gimli::CallFrameInstructionIter<R>,
    is_initial: bool,
) -> Result<Option<()>> {
    use gimli::CallFrameInstruction::*;

    let code_align = cie.code_alignment_factor();
    let data_aligin = cie.data_alignment_factor();
    let encoding = cie.encoding();

    macro_rules! rule {
        ($reg: ident, $base: expr, $off: expr) => {
            if $reg == X86_64::RBP {
                state.curr.fp.reg = $base;
                state.curr.fp.off = $off * data_aligin;
            } else if $reg == X86_64::RA {
                state.curr.ra.reg = $base;
                state.curr.ra.off = $off * data_aligin;
            } else {
                panic!("unknow rule")
            }
        };
    }

    loop {
        match insns.next() {
            Err(e) => {
                log::error!("Failed to decode CFI instruction: {}", e);
                return Err(anyhow::Error::new(e));
            }
            Ok(None) => {
                return Ok(None);
            }
            Ok(Some(op)) => match op {
                SetLoc { address } => {
                    state.pc = address;
                    return Ok(Some(()));
                }
                AdvanceLoc { delta } => {
                    state.pc += (delta as u64) * code_align;
                    return Ok(Some(()));
                }
                DefCfa { register, offset } => {
                    state.curr.cfa.reg = register.0 as u64;
                    state.curr.cfa.off = offset as i64;
                }
                DefCfaSf {
                    register,
                    factored_offset,
                } => {
                    state.curr.cfa.reg = register.0 as u64;
                    state.curr.cfa.off = factored_offset as i64 * cie.data_alignment_factor();
                }
                DefCfaRegister { register } => {
                    state.curr.cfa.reg = register.0 as u64;
                }
                DefCfaOffset { offset } => {
                    state.curr.cfa.off = offset as i64;
                }
                DefCfaOffsetSf { factored_offset } => {
                    state.curr.cfa.off = factored_offset * data_aligin;
                }
                DefCfaExpression { expression: _ } => {
                    todo!("handle expression")
                }
                Undefined { register } => {
                    rule!(register, REG_UNDEFINED, 0);
                }
                SameValue { register } => {
                    rule!(register, REG_SAME, 0);
                }
                Offset {
                    register,
                    factored_offset,
                } => {
                    // rule(register, REG_CFA, factored_offset as i64);
                    todo!()
                }
                OffsetExtendedSf {
                    register,
                    factored_offset,
                } => {
                    rule!(register, REG_CFA, factored_offset);
                }
                ValOffset {
                    register,
                    factored_offset,
                } => {
                    rule!(register, REG_CFA_VAL, factored_offset as i64);
                }
                ValOffsetSf {
                    register,
                    factored_offset,
                } => {
                    rule!(register, REG_CFA_VAL, factored_offset);
                }
                Register {
                    dest_register,
                    src_register,
                } => {
                    rule!(dest_register, src_register.0 as u64, 0);
                }
                Expression {
                    register,
                    expression,
                } => {
                    let expr = expression.get(eh_frame)?;
                    let mut expr_iter = expr.operations(encoding);
                    let mut ops = vec![];

                    loop {
                        if let Some(op) = expr_iter.next()? {
                            ops.push(op);
                        } else {
                            break;
                        }
                    }

                    todo!("handle expression")
                }
                ValExpression {
                    register,
                    expression: _,
                } => {
                    rule!(register, REG_UNDEFINED, 0);
                }
                Restore { register } => {
                    if register == X86_64::RBP {
                        state.curr.fp.reg = initial_state.fp.reg;
                        state.curr.fp.off = initial_state.fp.off;
                    } else if register == X86_64::RA {
                        state.curr.ra.reg = initial_state.ra.reg;
                        state.curr.ra.off = initial_state.ra.off;
                    }
                }
                RememberState => {
                    if state.stack_idx >= (state.stack.len() as i32) {
                        panic!("stack overflow");
                    }
                    state.stack[state.stack_idx as usize] = state.curr.clone();
                    state.stack_idx += 1;
                }
                RestoreState => {
                    if state.stack_idx == 0 {
                        panic!("underflow");
                    }

                    state.stack_idx -= 1;
                    state.curr = state.stack[state.stack_idx as usize].clone();
                }
                ArgsSize { size } => {
                    // todo!()
                }
                NegateRaState => {
                    unreachable!("DW_CFA_AARCH64_negate_ra_state")
                }
                Nop => {}
                _ => {
                    unreachable!()
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ElfFile;

    #[test]
    fn test_parse_elf() {
        // llvm-dwarfdump --eh-frame /usr/lib64/ld-2.32.so
        let mut elf = ElfFile::new("/usr/lib64/libcrypto.so.1.1.1k").unwrap();
        let deltas = ElfFile::parse_eh_frame(&elf.file).unwrap();
        for delta in &deltas {
            println!("delta: {}", delta);
        }

        // let deltas = elf.parse_eh_frame().unwrap();
        // println!("{}", deltas.len());
    }

    #[test]
    fn test_parse_symbols() {
        // let mut elf = ElfFile::new("/usr/lib64/ld-2.32.so").unwrap();
        // let syms = elf.parse_symbols();
        // println!("{} {:?}", syms.len(), syms);
    }
}
