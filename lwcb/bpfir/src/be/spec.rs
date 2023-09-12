use paste::paste;
use regalloc2::MachineEnv;
use regalloc2::PReg;
use regalloc2::RegClass;
use regalloc2::VReg;
use std::fmt;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use crate::types::Relation;
static VREG_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn new_vreg() -> VReg {
    VReg::new(VREG_COUNTER.fetch_add(1, Ordering::SeqCst), RegClass::Int)
}

macro_rules! gen_reg {
    ($($num: expr), *) => {
        paste! {
            $(
                pub fn [<R $num>]() -> PReg {
                    PReg::new($num, RegClass::Int)
                }
            )*
        }
    };
}

pub struct BPFSpec {}

impl BPFSpec {
    gen_reg!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    pub fn reg(no: u8) -> PReg {
        match no {
            0 => BPFSpec::R0(),
            1 => BPFSpec::R1(),
            2 => BPFSpec::R2(),
            3 => BPFSpec::R3(),
            4 => BPFSpec::R4(),
            5 => BPFSpec::R5(),
            6 => BPFSpec::R6(),
            7 => BPFSpec::R7(),
            8 => BPFSpec::R8(),
            9 => BPFSpec::R9(),
            10 => BPFSpec::R10(),
            _ => todo!(),
        }
    }

    pub fn env() -> MachineEnv {
        MachineEnv {
            preferred_regs_by_class: [
                vec![BPFSpec::R6(), BPFSpec::R7(), BPFSpec::R8(), BPFSpec::R9()],
                vec![],
                vec![],
            ],
            non_preferred_regs_by_class: [
                vec![
                    BPFSpec::R0(),
                    BPFSpec::R1(),
                    BPFSpec::R2(),
                    BPFSpec::R3(),
                    BPFSpec::R4(),
                    BPFSpec::R5(),
                ],
                vec![],
                vec![],
            ],
            scratch_by_class: [None, None, None],
            fixed_stack_slots: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BinaryOP {
    Add, // +
    Sub, // -
    Mul, // *
    Div, // /
    Or,  // |
    And, // &
    Lsh, // <<
    Rsh, // >>
    Neg, // -
    Mod, // %
    Xor, // ^
}
impl fmt::Display for BinaryOP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            BinaryOP::Add => "+",
            BinaryOP::Sub => "-",
            BinaryOP::Mul => "*",
            BinaryOP::Div => "/",
            BinaryOP::Or => "|",
            BinaryOP::And => "&",
            BinaryOP::Lsh => "<<",
            BinaryOP::Rsh => ">>",
            BinaryOP::Neg => "-",
            BinaryOP::Mod => "%",
            BinaryOP::Xor => "^",
        };
        write!(f, "{str}")
    }
}

#[derive(Debug, Clone)]
pub enum BPFInst {
    // load: dst_reg = *(uint *) (src_reg + off16)
    LoadX(u8, VReg, VReg, u16), // src, off
    // dst_reg = imm64
    Load64(VReg, i64),
    // store: *(uint *) (dst_reg + off16) = src_reg
    StoreX(u8, VReg, VReg, u16), // dst, src, off
    // *(uint *) (dst_reg + off16) = imm32
    Store(u8, VReg, u16, i32), // dst, off, imm
    // bpf_add|sub|...: dst_reg += src_reg
    Alu64X(BinaryOP, VReg, VReg), // BinaryOP, dst, src
    Alu32X(BinaryOP, VReg, VReg), // BinaryOP, dst, src
    Alu64(BinaryOP, VReg, i32),   // BinaryOP, dst, src
    Alu32(BinaryOP, VReg, i32),   // BinaryOP, dst, src
    Endian(u8, VReg),
    // dst_reg = src_reg
    MovX(VReg, VReg),
    Mov32X(VReg, VReg),

    // dst_reg = imm32
    Mov(VReg, i32),
    Mov32(VReg, i32),
    // if (dst_reg 'BinaryOP' src_reg) goto pc + off16
    JmpX(Relation, VReg, VReg, u16),
    Jmp(Relation, VReg, i32, u16),
    Jmp32X(Relation, VReg, VReg, u16),
    Jmp32(Relation, VReg, i32, u16),
    JmpA(u16),
    Call(i32),
    Exit,
}

impl fmt::Display for BPFInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

pub enum Helper {}
