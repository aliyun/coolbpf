use libbpf_rs::libbpf_sys::bpf_insn;
use libbpf_sys::{BPF_ALU, BPF_END, BPF_X};

use super::{object::BPFObject, spec::BPFInst};

pub fn codegen(insts: &Vec<BPFInst>) -> Vec<bpf_insn> {
    let mut res = vec![];
    for inst in insts {
        let insn = match inst {
            BPFInst::Endian(reg) => codegen_endian(reg.hw_enc() as u8, 64),
            _ => todo!(),
        };
    }
    res
}

// generate memory elf file which represents with bytes
pub fn codegen_mem_elf(sec_name: &str, func_name: &str, insts: &Vec<BPFInst>) -> Vec<u8> {
    let mut obj = BPFObject::new();
    obj.add_function(sec_name, func_name, &codegen(insts));
    obj.emit()
}

// reference: include/linux/filter.h in linux code
fn codegen_alu64_reg() -> bpf_insn {
    todo!()
}

fn codegen_alu32_reg() -> bpf_insn {
    todo!()
}

fn codegen_alu64_imm() -> bpf_insn {
    todo!()
}

fn codegen_alu32_imm() -> bpf_insn {
    todo!()
}

fn codegen_endian(dst: u8, bits: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_ALU | BPF_END | BPF_X) as u8;
    insn.set_dst_reg(dst);
    insn.imm = bits;
    insn
}

fn codegen_mov64_reg() -> bpf_insn {
    todo!()
}

fn codegen_mov32_reg() -> bpf_insn {
    todo!()
}

fn codegen_mov64_imm() -> bpf_insn {
    todo!()
}

fn codegen_mov32_imm() -> bpf_insn {
    todo!()
}

fn codegen_ldx_mem() -> bpf_insn {
    todo!()
}

fn codegen_stx_mem() -> bpf_insn {
    todo!()
}

fn codegen_st_mem() -> bpf_insn {
    todo!()
}

fn codegen_jmp_reg() -> bpf_insn {
    todo!()
}

fn codegen_jmp_imm() -> bpf_insn {
    todo!()
}

fn codegen_jmp32_reg() -> bpf_insn {
    todo!()
}

fn codegen_jmp32_imm() -> bpf_insn {
    todo!()
}

fn codegen_jmpa() -> bpf_insn {
    todo!()
}

fn codegen_call() -> bpf_insn {
    todo!()
}

fn codegen_exit() -> bpf_insn {
    todo!()
}
