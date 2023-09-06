use crate::be::spec::BPFInst;
use core::fmt;

use regalloc2::{
    Allocation, AllocationKind, Block, Edit, Function, Inst, InstOrEdit, InstRange, MachineEnv,
    Operand, Output, PRegSet, RegClass, VReg,
};

use super::{
    isel::ISelFunction,
    spec::{BPFSpec, BinaryOP},
};
use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub enum VBPFInst {
    // load: dst_reg = *(uint *) (src_reg + off16)
    LoadX(VReg, VReg, u16), // src, off
    // dst_reg = imm64
    Load64(VReg, i64),
    // store: *(uint *) (dst_reg + off16) = src_reg
    StoreX(VReg, VReg, u16), // dst, src, off
    // *(uint *) (dst_reg + off16) = imm32
    Store(VReg, u16, i32), // dst, off, imm
    // bpf_add|sub|...: dst_reg += src_reg
    Alu64X(BinaryOP, VReg, VReg), // BinaryOP, l, r
    Alu32X(BinaryOP, VReg, VReg), // BinaryOP, l, r
    Alu64(BinaryOP, VReg, i32),   // BinaryOP, l, r
    Alu32(BinaryOP, VReg, i32),   // BinaryOP, l, r
    Endian(VReg),
    // dst_reg = src_reg
    MovX(VReg, VReg),
    Mov32X(VReg, VReg),

    // dst_reg = imm32
    Mov(VReg, i32),
    Mov32(VReg, i32),
    // if (dst_reg 'BinaryOP' src_reg) goto pc + off16
    JmpX(BinaryOP, VReg, VReg, u16),
    Jmp(BinaryOP, VReg, i32, u16),
    Jmp32X(BinaryOP, VReg, VReg, u16),
    Jmp32(BinaryOP, VReg, i32, u16),
    JmpA(u16),
    Call(i32),
    Exit,
}

pub struct RAFunction {
    entry_block: Block,
    insts: Vec<VBPFInst>,
    blocks: Vec<InstRange>,
    block_preds: Vec<Vec<Block>>,
    block_succs: Vec<Vec<Block>>,
    block_params_in: Vec<Vec<VReg>>,
    block_params_out: Vec<Vec<Vec<VReg>>>,
    num_vregs: usize,
    reftype_vregs: Vec<VReg>,
    debug_value_labels: Vec<(VReg, Inst, Inst, u32)>,
    spillslot_size: Vec<usize>,
    multi_spillslot_named_by_last_slot: bool,
    allow_multiple_vreg_defs: bool,
}

impl Function for RAFunction {
    fn num_insts(&self) -> usize {
        self.insts.len()
    }

    fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    fn entry_block(&self) -> Block {
        self.entry_block
    }

    fn block_insns(&self, block: Block) -> InstRange {
        self.blocks[block.index()]
    }

    fn block_succs(&self, block: Block) -> &[Block] {
        &self.block_succs[block.index()][..]
    }

    fn block_preds(&self, block: Block) -> &[Block] {
        &self.block_preds[block.index()][..]
    }

    fn block_params(&self, block: Block) -> &[VReg] {
        &self.block_params_in[block.index()][..]
    }

    fn is_ret(&self, insn: Inst) -> bool {
        todo!()
        // self.insts[insn.index()].kind.is_ret()
    }

    fn is_branch(&self, insn: Inst) -> bool {
        todo!()
        // self.insts[insn.index()].kind.is_branch()
    }

    fn branch_blockparams(&self, block: Block, _: Inst, succ: usize) -> &[VReg] {
        &self.block_params_out[block.index()][succ][..]
    }

    fn inst_operands(&self, insn: Inst) -> &[Operand] {
        todo!()
        // &self.insts[insn.index()].operands[..]
    }

    fn inst_clobbers(&self, insn: Inst) -> PRegSet {
        PRegSet::empty()
    }

    fn num_vregs(&self) -> usize {
        self.num_vregs
    }

    fn reftype_vregs(&self) -> &[VReg] {
        &self.reftype_vregs[..]
    }

    fn debug_value_labels(&self) -> &[(VReg, Inst, Inst, u32)] {
        &self.debug_value_labels[..]
    }

    fn spillslot_size(&self, regclass: RegClass) -> usize {
        self.spillslot_size[regclass as usize]
    }

    fn multi_spillslot_named_by_last_slot(&self) -> bool {
        self.multi_spillslot_named_by_last_slot
    }

    fn allow_multiple_vreg_defs(&self) -> bool {
        self.allow_multiple_vreg_defs
    }
}

impl RAFunction {
    pub fn from_isel_function(isel: &ISelFunction) -> Self {
        todo!()
    }

    pub fn do_regalloc(&mut self) -> Result<()> {
        let env = BPFSpec::env();
        let opts = regalloc2::RegallocOptions {
            verbose_log: false,
            validate_ssa: true,
        };
        let mut output =
            regalloc2::run(self, &env, &opts).expect("failed to run register allocation");

        Ok(())
    }
}

pub fn do_regalloc(f: &mut RAFunction) -> Output {
    let env = BPFSpec::env();
    let opts = regalloc2::RegallocOptions {
        verbose_log: false,
        validate_ssa: true,
    };
    regalloc2::run(f, &env, &opts).expect("failed to run register allocation")
}

pub fn regalloc_emit(f: &RAFunction, output: &Output) -> Vec<BPFInst> {
    let mut blocks = vec![];
    let mut total_insts = vec![];
    // todo: emit prologue, that is, the stack space is cleared to 0.
    for (idx, _) in f.blocks.iter().enumerate() {
        let insts = regalloc_emit_block(f, output, idx as u32);
        let start = total_insts.len();
        let end = start + insts.len();
        blocks.push((start, end));
        total_insts.extend_from_slice(&insts);
    }

    // fix jmp
    let _ =total_insts.iter().map( |inst| {
        match inst {
            // todo: convert block id to instruction offset
            _ => todo!()
        }
    });

    total_insts
}

fn regalloc_emit_block(f: &RAFunction, output: &Output, block: u32) -> Vec<BPFInst> {
    let mut res = vec![];
    for inst_or_edit in output.block_insts_and_edits(f, Block(block)) {
        match inst_or_edit {
            InstOrEdit::Inst(inst) => {
                res.push(regalloc_emit_inst(
                    &f.insts[inst.index()],
                    &output.inst_allocs(inst),
                ));
            }

            InstOrEdit::Edit(Edit::Move { from, to }) => {
                match (from.as_reg(), to.as_reg()) {
                    (Some(from), Some(to)) => {
                        // todo: It should be judged according to the type whether to use MovX or Mov32X
                        res.push(BPFInst::MovX(to, from));
                    }
                    (Some(from), None) => {
                        // Spill from register to spillslot.
                        let to = to.as_stack().unwrap();
                        res.push(BPFInst::StoreX(BPFSpec::R10(), from, to.index() as u16));
                    }
                    (None, Some(to)) => {
                        // Load from spillslot to register.
                        let from = from.as_stack().unwrap();
                        res.push(BPFInst::LoadX(to, BPFSpec::R10(), from.index() as u16));
                    }
                    (None, None) => {
                        panic!("regalloc2 should have eliminated stack-to-stack moves!");
                    }
                }
            }
        }
    }
    res
}

fn regalloc_emit_inst(vinst: &VBPFInst, allocs: &[Allocation]) -> BPFInst {
    match vinst {
        VBPFInst::Alu32(op, _, imm) => {
            assert!(allocs.len() == 1);
            assert!(allocs[0].is_reg());
            return BPFInst::Alu32(*op, allocs[0].as_reg().unwrap(), *imm);
        }
        // todo: implement other VBPFInst
        _ => todo!(),
    }
}
