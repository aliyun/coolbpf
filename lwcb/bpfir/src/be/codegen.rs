use super::spec::BPFInst;
use crate::object::BPFObject;
use libbpf_rs::libbpf_sys::bpf_insn;
use libbpf_sys::*;

/// Convert BPFInst to eBPF bytecode
pub fn codegen(insts: &Vec<BPFInst>) -> Vec<bpf_insn> {
    let mut res = vec![];

    macro_rules! emit {
        ($ident: expr) => {
            res.push($ident);
        };
    }

    macro_rules! emit2 {
        ($ident: expr) => {
            res.push($ident.0);
            res.push($ident.1);
        };
    }

    for inst in insts {
        match inst {
            BPFInst::PlaceHolder => {}
            BPFInst::LoadX(sz, dst, src, off) => {
                emit!(codegen_ldx_mem(*sz as u8, dst.hwid(), src.hwid(), *off,));
            }
            BPFInst::Load64(dst, imm) => {
                emit2!(codegen_ld_imm64(dst.hwid(), *imm as u64));
            }
            BPFInst::StoreX(sz, dst, src, off) => {
                emit!(codegen_stx_mem(*sz as u8, dst.hwid(), src.hwid(), *off));
            }
            BPFInst::Store(sz, dst, off, imm) => {
                emit!(codegen_st_mem(*sz as u8, dst.hwid(), *off, *imm as u32));
            }
            BPFInst::Alu64X(op, dst, src) => {
                emit!(codegen_alu64_reg(*op as u8, dst.hwid(), src.hwid()));
            }
            BPFInst::Alu64(op, dst, imm) => {
                emit!(codegen_alu64_imm(*op as u8, dst.hwid(), *imm));
            }
            BPFInst::Alu32X(op, dst, src) => {
                emit!(codegen_alu32_reg(*op as u8, dst.hwid(), src.hwid()));
            }
            BPFInst::Alu32(op, dst, imm) => {
                emit!(codegen_alu32_imm(*op as u8, dst.hwid(), *imm));
            }
            BPFInst::MovX(dst, src) => {
                emit!(codegen_mov64_reg(dst.hwid(), src.hwid()));
            }
            BPFInst::Mov32X(dst, src) => {
                emit!(codegen_mov32_reg(dst.hwid(), src.hwid()));
            }
            BPFInst::Mov(dst, imm) => {
                emit!(codegen_mov64_imm(dst.hwid(), *imm));
            }
            BPFInst::Mov32(dst, imm) => {
                emit!(codegen_mov32_imm(dst.hwid(), *imm));
            }
            BPFInst::JmpX(rel, dst, src, off) => {
                emit!(codegen_jmp_reg(*rel as u8, dst.hwid(), src.hwid(), *off));
            }
            BPFInst::Jmp(rel, dst, imm, off) => {
                emit!(codegen_jmp_imm(*rel as u8, dst.hwid(), *imm, *off));
            }
            BPFInst::Jmp32X(rel, dst, src, off) => {
                emit!(codegen_jmp32_reg(*rel as u8, dst.hwid(), src.hwid(), *off));
            }
            BPFInst::Jmp32(rel, dst, imm, off) => {
                emit!(codegen_jmp32_imm(*rel as u8, dst.hwid(), *imm, *off));
            }
            BPFInst::JmpA(off) => {
                emit!(codegen_jmpa(*off));
            }
            BPFInst::Endian(sz, reg) => {
                emit!(codegen_endian(reg.hwid(), sz.bits() as i32));
            }
            BPFInst::Call(id) => {
                emit!(codegen_call(*id));
            }
            BPFInst::Exit => {
                emit!(codegen_exit());
            }
        };
    }
    res
}

// generate memory elf file which represents with bytes
pub fn codegen_object(
    object: &mut BPFObject,
    sec_name: &str,
    func_name: &str,
    insts: &Vec<BPFInst>,
) {
    object.add_function(sec_name, func_name, &codegen(insts));
}

#[inline]
fn codegen_ldx_mem(sz: u8, dst: u8, src: u8, off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_LDX | BPF_MEM) as u8) | sz;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn.off = off as i16;
    insn
}

#[inline]
fn __codegen_ld_imm64_raw(dst: u8, src: u8, imm: u64) -> (bpf_insn, bpf_insn) {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_LD | BPF_DW | BPF_IMM) as u8;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn.imm = (imm as u32) as i32;

    let mut insn2 = bpf_insn::default();
    insn2.imm = (imm >> 32) as i32;
    (insn, insn2)
}

#[inline]
fn codegen_ld_imm64(dst: u8, imm: u64) -> (bpf_insn, bpf_insn) {
    __codegen_ld_imm64_raw(dst, 0, imm)
}

#[inline]
fn codegen_ld_mapfd(dst: u8, imm: u64) -> (bpf_insn, bpf_insn) {
    __codegen_ld_imm64_raw(dst, BPF_PSEUDO_MAP_FD as u8, imm)
}

#[inline]
fn codegen_stx_mem(sz: u8, dst: u8, src: u8, off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_STX | BPF_MEM) as u8) | sz;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn.off = off as i16;
    insn
}

#[inline]
fn codegen_st_mem(sz: u8, dst: u8, off: i16, imm: u32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_ST | BPF_MEM) as u8) | sz;
    insn.set_dst_reg(dst);
    insn.off = off as i16;
    insn.imm = imm as i32;
    insn
}

#[inline]
fn codegen_alu64_reg(op: u8, dst: u8, src: u8) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_ALU64 | BPF_X) as u8) | op;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn
}

#[inline]
fn codegen_alu32_reg(op: u8, dst: u8, src: u8) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_ALU | BPF_X) as u8) | op;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn
}

#[inline]
fn codegen_alu64_imm(op: u8, dst: u8, imm: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_ALU64 | BPF_K) as u8) | op;
    insn.set_dst_reg(dst);
    insn.imm = imm;
    insn
}

#[inline]
fn codegen_alu32_imm(op: u8, dst: u8, imm: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = ((BPF_ALU | BPF_K) as u8) | op;
    insn.set_dst_reg(dst);
    insn.imm = imm;
    insn
}

#[inline]
fn codegen_endian(dst: u8, bits: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_ALU | BPF_END | BPF_X) as u8;
    insn.set_dst_reg(dst);
    insn.imm = bits;
    insn
}

#[inline]
fn codegen_mov64_reg(dst: u8, src: u8) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_ALU64 | BPF_MOV | BPF_X) as u8;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn
}

#[inline]
fn codegen_mov32_reg(dst: u8, src: u8) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_ALU | BPF_MOV | BPF_X) as u8;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn
}

#[inline]
fn codegen_mov64_imm(dst: u8, imm: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_ALU64 | BPF_MOV | BPF_K) as u8;
    insn.set_dst_reg(dst);
    insn.imm = imm;
    insn
}

#[inline]
fn codegen_mov32_imm(dst: u8, imm: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_ALU | BPF_K | BPF_MOV) as u8;
    insn.set_dst_reg(dst);
    insn.imm = imm;
    insn
}

#[inline]
fn codegen_jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP | BPF_X) as u8 | op;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn.off = off;
    insn
}

#[inline]
fn codegen_jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP | BPF_K) as u8 | op;
    insn.set_dst_reg(dst);
    insn.off = off;
    insn.imm = imm;
    insn
}

#[inline]
fn codegen_jmp32_reg(op: u8, dst: u8, src: u8, off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP32 | BPF_X) as u8 | op;
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn.off = off;
    insn
}

#[inline]
fn codegen_jmp32_imm(op: u8, dst: u8, imm: i32, off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP32 | BPF_K) as u8 | op;
    insn.set_dst_reg(dst);
    insn.off = off;
    insn.imm = imm;
    insn
}

#[inline]
fn codegen_jmpa(off: i16) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP | BPF_JA) as u8;
    insn.off = off;
    insn
}

#[inline]
fn codegen_call(id: i32) -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP | BPF_CALL) as u8;
    insn.imm = id;
    insn
}

#[inline]
fn codegen_exit() -> bpf_insn {
    let mut insn = bpf_insn::default();
    insn.code = (BPF_JMP | BPF_EXIT) as u8;
    insn
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::be::spec::BPFBOp;
    use crate::be::spec::BPFJOp;
    use crate::be::spec::BPFReg;
    use crate::be::spec::BPFSize;
    use libbpf_rs::ObjectBuilder;

    fn load_insts(insts: &Vec<BPFInst>) {
        let mut object = BPFObject::new();
        codegen_object(
            &mut object,
            "kprobe/tcp_sendmsg",
            "kprobe_tcp_sendmsg",
            &insts,
        );
        let mem_obj = object.emit();
        let mut builder = ObjectBuilder::default();
        let object = builder.open_memory("lwcb_test", &mem_obj).unwrap();
        let mut bpfskel = object.load().unwrap();
        bpfskel
            .prog_mut("kprobe_tcp_sendmsg")
            .unwrap()
            .attach()
            .unwrap();
    }

    #[test]
    fn cgen_object() {
        let r0 = BPFReg::r0();
        let insts = vec![BPFInst::Mov(r0, 0), BPFInst::Exit];
        load_insts(&insts);
    }

    #[test]
    fn codegen() {
        let r0 = BPFReg::r0();
        let r2 = BPFReg::r2();
        let r3 = BPFReg::r3();
        let r6 = BPFReg::r6();
        let r10 = BPFReg::r10();
        let insts = vec![
            BPFInst::Mov(r6, 0),
            BPFInst::StoreX(BPFSize::from_bits(64), r10, r6, -8),
            BPFInst::StoreX(BPFSize::from_bits(64), r10, r6, -16),
            BPFInst::LoadX(BPFSize::from_bits(64), r2, r10, -8),
            BPFInst::Load64(BPFReg::r3(), 0),
            BPFInst::StoreX(BPFSize::from_bits(32), r10, r3, -16),
            BPFInst::Store(BPFSize::from_bits(16), r10, -16, 70),
            BPFInst::Alu64X(BPFBOp::Add, r3, r2),
            BPFInst::Alu32X(BPFBOp::Add, r3, r2),
            BPFInst::Alu64(BPFBOp::Add, r3, 20),
            BPFInst::Alu32(BPFBOp::Add, r3, 20),
            BPFInst::Endian(BPFSize::from_bits(64), r3),
            BPFInst::MovX(r2, r3),
            BPFInst::Mov32X(r2, r3),
            BPFInst::Mov(r2, 50),
            BPFInst::Mov32(r2, 50),
            BPFInst::Call(5),
            BPFInst::JmpX(BPFJOp::Equal, r0, r0, 0),
            BPFInst::Jmp(BPFJOp::Equal, r0, 0, 0),
            BPFInst::Jmp32X(BPFJOp::Equal, r0, r0, 0),
            BPFInst::Jmp32(BPFJOp::Equal, r0, 0, 0),
            BPFInst::JmpA(0),
            BPFInst::Mov(r0, 0),
            BPFInst::Exit,
        ];
        load_insts(&insts);
    }
}
