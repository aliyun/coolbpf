use paste::paste;
use regalloc2::MachineEnv;
use regalloc2::PReg;
use regalloc2::RegClass;
use regalloc2::VReg;
use std::fmt;

// Generate a method to obtain the bpf register, such as BPFReg::r0() to obtain the register r0
macro_rules! gen_reg {
    ($($num: expr), *) => {
        paste! {
            $(
                pub fn [<r $num>]() -> BPFReg {
                    BPFReg::new($num)
                }
            )*
        }
    };
}

/// BPF register, we use it to represent both virtual registers and hardware
/// registers. When in the register allocation phase, treat them as virtual
/// registers. After the register is allocated, we will assign it a real
/// hardware register number.
#[derive(Debug, Clone, Copy)]
pub struct BPFReg(u32);

impl BPFReg {
    pub fn new(no: u32) -> Self {
        BPFReg(no)
    }

    /// get hardware register umber
    pub fn hwid(&self) -> u8 {
        debug_assert!(self.0 <= 10);
        self.0 as u8
    }

    gen_reg!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
}

impl fmt::Display for BPFReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl std::convert::From<BPFReg> for VReg {
    fn from(value: BPFReg) -> Self {
        VReg::new(value.0 as usize, RegClass::Int)
    }
}

impl std::convert::From<BPFReg> for PReg {
    fn from(value: BPFReg) -> Self {
        PReg::new(value.hwid() as usize, RegClass::Int)
    }
}

/// Convert PReg to BPFReg, when register allocation is done, we need
/// to convert PReg to BPFReg
impl std::convert::From<PReg> for BPFReg {
    fn from(value: PReg) -> Self {
        Self::new(value.hw_enc() as u32)
    }
}

/// BPFSize is used to represent the data size operated by the bpf instruction:
///
/// 1. DW is 64bit
/// 2. W is 32bit
/// 3. H is 16bit
/// 4. B is 8bit
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum BPFSize {
    DW = libbpf_sys::BPF_DW as u8,
    W = libbpf_sys::BPF_W as u8,
    H = libbpf_sys::BPF_H as u8,
    B = libbpf_sys::BPF_B as u8,
}

impl BPFSize {
    /// Get the corresponding number of bits
    pub fn bits(&self) -> u8 {
        match self {
            BPFSize::DW => 64,
            BPFSize::W => 32,
            BPFSize::H => 16,
            BPFSize::B => 8,
        }
    }

    pub fn from_bits(bits: u32) -> Self {
        match bits {
            64 => BPFSize::DW,
            32 => BPFSize::W,
            16 => BPFSize::H,
            8 => BPFSize::B,
            _ => panic!("wrong number of bits"),
        }
    }
}

impl fmt::Display for BPFSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            BPFSize::DW => "64",
            BPFSize::W => "32",
            BPFSize::H => "16",
            BPFSize::B => "8",
        };
        write!(f, "{str}")
    }
}

/// BPFBop is the operator of the bpf binary instruction
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum BPFBOp {
    Add = libbpf_sys::BPF_ADD as u8, // +
    Sub = libbpf_sys::BPF_SUB as u8, // -
    Mul = libbpf_sys::BPF_MUL as u8, // *
    Div = libbpf_sys::BPF_DIV as u8, // /
    Or = libbpf_sys::BPF_OR as u8,   // |
    And = libbpf_sys::BPF_AND as u8, // &
    Lsh = libbpf_sys::BPF_LSH as u8, // <<
    Rsh = libbpf_sys::BPF_RSH as u8, // >>
    Neg = libbpf_sys::BPF_NEG as u8, // -
    Mod = libbpf_sys::BPF_MOD as u8, // %
    Xor = libbpf_sys::BPF_XOR as u8, // ^
}

impl fmt::Display for BPFBOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            BPFBOp::Add => "+",
            BPFBOp::Sub => "-",
            BPFBOp::Mul => "*",
            BPFBOp::Div => "/",
            BPFBOp::Or => "|",
            BPFBOp::And => "&",
            BPFBOp::Lsh => "<<",
            BPFBOp::Rsh => ">>",
            BPFBOp::Neg => "-",
            BPFBOp::Mod => "%",
            BPFBOp::Xor => "^",
        };
        write!(f, "{str}")
    }
}

/// BPFJOp is the operator of the bpf jump instruction, which is actually the
/// operator of relational expressions.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum BPFJOp {
    NotEqual = libbpf_sys::BPF_JNE as u8,
    Equal = libbpf_sys::BPF_JEQ as u8,
    Less = libbpf_sys::BPF_JLT as u8,
    LessEqual = libbpf_sys::BPF_JLE as u8,
    SignedLess = libbpf_sys::BPF_JSLT as u8,
    SignedLessEqual = libbpf_sys::BPF_JSLE as u8,
    Greater = libbpf_sys::BPF_JGT as u8,
    GreateEqual = libbpf_sys::BPF_JGE as u8,
    SignedGreater = libbpf_sys::BPF_JSGT as u8,
    SignedGreateEqual = libbpf_sys::BPF_JSGE as u8,
}

impl fmt::Display for BPFJOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BPFJOp::NotEqual => write!(f, "!="),
            BPFJOp::Equal => write!(f, "=="),
            BPFJOp::Less => write!(f, "<"),
            BPFJOp::LessEqual => write!(f, "<="),
            BPFJOp::SignedLess => write!(f, "<(signed)"),
            BPFJOp::SignedLessEqual => write!(f, "<=(signed)"),
            BPFJOp::Greater => write!(f, ">"),
            BPFJOp::GreateEqual => write!(f, ">="),
            BPFJOp::SignedGreater => write!(f, ">(signed)"),
            BPFJOp::SignedGreateEqual => write!(f, ">=(signed)"),
        }
    }
}

/// BPFInst is used to represent the bpf instruction. It should be mentioned
/// in particular that BPFInst::PlaceHolder has two main uses. a. One is a
/// virtual instruction for block arguments and fp(r10), b. and the other is an extension
/// of the `BPFInst::Load64` instruction to facilitate subsequent calculation
/// of jmp offset.
#[derive(Debug, Clone)]
pub enum BPFInst {
    PlaceHolder,
    LoadX(BPFSize, BPFReg, BPFReg, i16),
    Load64(BPFReg, i64),
    StoreX(BPFSize, BPFReg, BPFReg, i16),
    Store(BPFSize, BPFReg, i16, i32),
    Alu64X(BPFBOp, BPFReg, BPFReg),
    Alu32X(BPFBOp, BPFReg, BPFReg),
    Alu64(BPFBOp, BPFReg, i32),
    Alu32(BPFBOp, BPFReg, i32),
    Endian(BPFSize, BPFReg),
    MovX(BPFReg, BPFReg),
    Mov32X(BPFReg, BPFReg),
    Mov(BPFReg, i32),
    Mov32(BPFReg, i32),
    JmpX(BPFJOp, BPFReg, BPFReg, i16),
    Jmp(BPFJOp, BPFReg, i32, i16),
    Jmp32X(BPFJOp, BPFReg, BPFReg, i16),
    Jmp32(BPFJOp, BPFReg, i32, i16),
    JmpA(i16),
    Call(i32),
    Exit,
}

impl BPFInst {
    pub fn need_placeholder(&self) -> bool {
        match self {
            BPFInst::Load64(..) => true,
            _ => false,
        }
    }
}

impl fmt::Display for BPFInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BPFInst::PlaceHolder => write!(f, ""),
            BPFInst::LoadX(sz, v1, v2, off) => write!(f, "{v1} = *(u{sz})({v2} + {off})"),
            BPFInst::Load64(v, imm) => write!(f, "{v} = {imm}"),
            BPFInst::StoreX(sz, v1, v2, off) => write!(f, "*(u{sz})({v1} + {off}) = {v2}"),
            BPFInst::Store(sz, v, off, imm) => write!(f, "*(u{sz})({v} + {off}) = {imm}"),
            BPFInst::Alu64X(op, v1, v2) => write!(f, "{v1} {op}= {v2}"),
            BPFInst::Alu32X(op, v1, v2) => write!(f, "{v1} {op}= {v2}"),
            BPFInst::Alu64(op, v1, imm) => write!(f, "{v1} {op}= {imm}"),
            BPFInst::Alu32(op, v1, imm) => write!(f, "{v1} {op}= {imm}"),
            BPFInst::Endian(sz, v) => write!(f, "bswap{sz}({v})"),
            BPFInst::MovX(v1, v2) => write!(f, "{v1} = {v2}"),
            BPFInst::Mov32X(v1, v2) => write!(f, "{v1} = {v2}"),
            BPFInst::Mov(v1, imm) => write!(f, "{v1} = {imm}"),
            BPFInst::Mov32(v1, imm) => write!(f, "{v1} = {imm}"),
            BPFInst::JmpX(rel, v1, v2, off) => write!(f, "if ({v1} {rel} {v2}) goto pc + {off}"),
            BPFInst::Jmp(rel, v1, imm, off) => write!(f, "if ({v1} {rel} {imm}) goto pc + {off}"),
            BPFInst::Jmp32X(rel, v1, v2, off) => write!(f, "if ({v1} {rel} {v2}) goto pc + {off}"),
            BPFInst::Jmp32(rel, v1, imm, off) => write!(f, "if ({v1} {rel} {imm}) goto pc + {off}"),
            BPFInst::JmpA(off) => write!(f, "goto pc + {off}"),
            BPFInst::Call(id) => write!(f, "call #{id}"),
            BPFInst::Exit => write!(f, "exit"),
        }
    }
}

pub fn BPFMachineEnv() -> MachineEnv {
    MachineEnv {
        preferred_regs_by_class: [
            vec![
                BPFReg::r6().into(),
                BPFReg::r7().into(),
                BPFReg::r8().into(),
                BPFReg::r9().into(),
            ],
            vec![],
            vec![],
        ],
        non_preferred_regs_by_class: [
            vec![
                BPFReg::r0().into(),
                BPFReg::r1().into(),
                BPFReg::r2().into(),
                BPFReg::r3().into(),
                BPFReg::r4().into(),
                BPFReg::r5().into(),
            ],
            vec![],
            vec![],
        ],
        scratch_by_class: [None, None, None],
        fixed_stack_slots: vec![],
    }
}
