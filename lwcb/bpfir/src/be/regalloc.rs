use crate::be::spec::BPFInst;
use core::fmt;

use regalloc2::{Block, Function, Inst, InstRange, MachineEnv, Operand, PRegSet, RegClass, VReg};

use super::{
    spec::BPFSpec, isel::ISelFunction,
};
use anyhow::{bail, Result};

pub struct BPFFunction {
    entry_block: Block,
    insts: Vec<usize>,
    blocks: Vec<InstRange>,
    block_preds: Vec<Vec<Block>>,
    block_succs: Vec<Vec<Block>>,
    // (to-vreg,to-block, from-block)
    // fn block_params(&self, block: Block) -> &[VReg]
    block_params_in: Vec<Vec<VReg>>,
    // (from-vreg, from-block, to-block, to-vreg),
    // branch_blockparams(&self, block: Block, _: Inst, succ: usize) -> &[VReg]
    block_params_out: Vec<Vec<Vec<VReg>>>,
    num_vregs: usize,
    reftype_vregs: Vec<VReg>,
    debug_value_labels: Vec<(VReg, Inst, Inst, u32)>,
    spillslot_size: Vec<usize>,
    multi_spillslot_named_by_last_slot: bool,
    allow_multiple_vreg_defs: bool,
}

impl Function for BPFFunction {
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
        // todo: operandpos没看太明白
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

impl BPFFunction {

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
            regalloc2::run(self, &env, &opts).expect("failed to run register allocator");
        Ok(())
    }
}
