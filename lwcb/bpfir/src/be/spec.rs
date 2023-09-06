use libbpf_sys::bpf_insn;
use paste::paste;
use regalloc2::MachineEnv;
use regalloc2::OperandConstraint;
use regalloc2::PReg;
use regalloc2::RegClass;

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

#[derive(Debug, Clone)]
pub enum BPFInst {
    // load: dst_reg = *(uint *) (src_reg + off16)
    LoadX(PReg, PReg, u16), // src, off
    // dst_reg = imm64
    Load64(PReg, i64),
    // store: *(uint *) (dst_reg + off16) = src_reg
    StoreX(PReg, PReg, u16), // dst, src, off
    // *(uint *) (dst_reg + off16) = imm32
    Store(PReg, u16, i32), // dst, off, imm
    // bpf_add|sub|...: dst_reg += src_reg
    Alu64X(BinaryOP, PReg, PReg), // BinaryOP, l, r
    Alu32X(BinaryOP, PReg, PReg), // BinaryOP, l, r
    Alu64(BinaryOP, PReg, i32),  // BinaryOP, l, r
    Alu32(BinaryOP, PReg, i32),  // BinaryOP, l, r
    Endian(PReg),
    // dst_reg = src_reg
    MovX(PReg, PReg),
    Mov32X(PReg, PReg),

    // dst_reg = imm32
    Mov(PReg, i32),
    Mov32(PReg, i32),
    // if (dst_reg 'BinaryOP' src_reg) goto pc + off16
    JmpX(BinaryOP, PReg, PReg, u16),
    Jmp(BinaryOP, PReg, i32, u16),
    Jmp32X(BinaryOP, PReg, PReg, u16),
    Jmp32(BinaryOP, PReg, i32, u16),
    JmpA(u16),
    Call(i32),
    Exit,
}


pub enum Helper {

}

