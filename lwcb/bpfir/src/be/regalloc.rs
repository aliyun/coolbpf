use super::isel::ISelBlock;
use super::isel::ISelFunction;
use super::spec::BPFMachineEnv;
use super::spec::BPFReg;
use super::spec::BPFSize;
use crate::be::spec::BPFInst;
use regalloc2::Allocation;
use regalloc2::Block;
use regalloc2::Edit;
use regalloc2::Function;
use regalloc2::Inst;
use regalloc2::InstOrEdit;
use regalloc2::InstRange;
use regalloc2::Operand;
use regalloc2::Output;
use regalloc2::PRegSet;
use regalloc2::RegClass;
use regalloc2::VReg;
use std::fmt;

/// As a result of register allocation, the virtual registers of instructions
/// have been replaced with hardware registers.
#[derive(Default)]
pub struct RAFunction {
    insts: Vec<BPFInst>,
}

impl fmt::Display for RAFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for inst in &self.insts {
            writeln!(f, "{inst}")?;
        }
        Ok(())
    }
}

impl RAFunction {
    pub fn insts(&self) -> &Vec<BPFInst> {
        &self.insts
    }

    fn add_inst(&mut self, inst: BPFInst) -> usize {
        self.insts.push(inst);
        self.insts.len()
    }
}

#[derive(Default)]
pub struct RAFunctionBuilder {
    insts: Vec<BPFInst>,
    operands: Vec<Vec<Operand>>,
    blocks: Vec<InstRange>,
    block_preds: Vec<Vec<Block>>,
    block_succs: Vec<Vec<Block>>,
    block_params_in: Vec<Vec<VReg>>,
    block_params_out: Vec<Vec<Vec<VReg>>>,

    rf: RAFunction,
}

impl RAFunctionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(mut self, isel: ISelFunction) -> RAFunction {
        let mut rf = RAFunction::default();
        for ib in isel.blocks {
            self.build_block(ib)
        }
        // regalloc2 would check if entry block has block args.
        self.block_params_in[0] = vec![];
        rf.insts = do_regalloc(&self);
        rf
    }

    fn build_block(&mut self, block: ISelBlock) {
        let start = self.insts.len();
        self.insts.extend(block.insts.clone());
        let end = self.insts.len();
        log::debug!(
            "Block instruction range: {} -> {}, params_in: {}, params_out: {}, {}",
            start,
            end,
            block.params.len(),
            block.params_out.len(),
            block,
        );
        self.operands.extend(block.operands);
        self.block_preds
            .push(block.preds.iter().map(|x| Block(*x as u32)).collect());
        self.block_succs
            .push(block.succs.iter().map(|x| Block(*x as u32)).collect());

        self.block_params_in
            .push(block.params.iter().map(|&x| x.into()).collect());
        self.block_params_out.push(
            block
                .params_out
                .iter()
                .map(|xx| xx.clone().iter().map(|&x| x.into()).collect())
                .collect(),
        );
        self.blocks
            .push(InstRange::forward(Inst(start as u32), Inst(end as u32)));
    }
}

impl Function for RAFunctionBuilder {
    fn num_insts(&self) -> usize {
        self.insts.len()
    }

    fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    fn entry_block(&self) -> Block {
        Block(0)
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
        if let BPFInst::Exit = self.insts[insn.index()] {
            true
        } else {
            false
        }
    }

    fn is_branch(&self, insn: Inst) -> bool {
        match &self.insts[insn.index()] {
            BPFInst::Jmp(_, _, _, _)
            | BPFInst::Jmp32(_, _, _, _)
            | BPFInst::Jmp32X(_, _, _, _)
            | BPFInst::JmpA(_)
            | BPFInst::JmpX(..) => true,
            _ => false,
        }
    }

    fn branch_blockparams(&self, block: Block, _: Inst, succ: usize) -> &[VReg] {
        &self.block_params_out[block.index()][succ][..]
    }

    fn inst_operands(&self, insn: Inst) -> &[Operand] {
        &self.operands[insn.index()]
    }

    fn inst_clobbers(&self, insn: Inst) -> PRegSet {
        PRegSet::empty()
    }

    fn num_vregs(&self) -> usize {
        20
    }

    fn reftype_vregs(&self) -> &[VReg] {
        &[]
    }

    fn debug_value_labels(&self) -> &[(VReg, Inst, Inst, u32)] {
        &[]
    }

    fn spillslot_size(&self, regclass: RegClass) -> usize {
        8
    }

    fn multi_spillslot_named_by_last_slot(&self) -> bool {
        false
    }

    fn allow_multiple_vreg_defs(&self) -> bool {
        false
    }
}

fn do_regalloc(f: &RAFunctionBuilder) -> Vec<BPFInst> {
    let env = BPFMachineEnv();
    let opts = regalloc2::RegallocOptions {
        verbose_log: true,
        validate_ssa: true,
    };
    let output = regalloc2::run(f, &env, &opts).expect("failed to run register allocation");

    regalloc_emit(f, &output)
}

fn regalloc_emit(f: &RAFunctionBuilder, output: &Output) -> Vec<BPFInst> {
    let mut blocks = vec![];
    let mut total_insts = vec![];
    // todo: emit prologue, that is, the stack space is cleared to 0.
    for (idx, _) in f.blocks.iter().enumerate() {
        let insts = regalloc_emit_block(f, &output, idx as u32);
        let start = total_insts.len() as i16;
        let end = start + insts.len() as i16;
        blocks.push((start, end));
        total_insts.extend_from_slice(&insts);
    }

    // fix jmp
    let _ = total_insts.iter_mut().map(|inst| match inst {
        BPFInst::JmpA(x) => *x = blocks[*x as usize].0,
        _ => todo!(),
    });

    total_insts
}

fn regalloc_emit_block(f: &RAFunctionBuilder, output: &Output, block: u32) -> Vec<BPFInst> {
    let mut res = vec![];
    for inst_or_edit in output.block_insts_and_edits(f, Block(block)) {
        match inst_or_edit {
            InstOrEdit::Inst(inst) => {
                let instref = &f.insts[inst.index()];
                res.push(regalloc_emit_inst(instref, &output.inst_allocs(inst)));

                if instref.need_placeholder() {
                    res.push(BPFInst::PlaceHolder);
                }
            }

            InstOrEdit::Edit(Edit::Move { from, to }) => {
                match (from.as_reg(), to.as_reg()) {
                    (Some(from), Some(to)) => {
                        // todo: It should be judged according to the type whether to use MovX or Mov32X
                        res.push(BPFInst::MovX(BPFReg::from(to), BPFReg::from(from)));
                    }
                    (Some(from), None) => {
                        // Spill from register to spillslot.
                        let to = to.as_stack().unwrap();
                        res.push(BPFInst::StoreX(
                            BPFSize::DW,
                            BPFReg::r10(),
                            BPFReg::from(from),
                            to.index() as i16,
                        ));
                    }
                    (None, Some(to)) => {
                        // Load from spillslot to register.
                        let from = from.as_stack().unwrap();
                        res.push(BPFInst::LoadX(
                            BPFSize::DW,
                            BPFReg::from(to),
                            BPFReg::r10(),
                            from.index() as i16,
                        ));
                    }
                    (None, None) => {
                        panic!("unexpected stack-to-stack moves!");
                    }
                }
            }
        }
    }
    res
}

// Replace the virtual registers in BPFInst with hardware registers
fn regalloc_emit_inst(inst: &BPFInst, allocs: &[Allocation]) -> BPFInst {
    // get the allocated preg and then convert it to BPFReg
    let reg = |idx: usize| BPFReg::from(allocs[idx].as_reg().unwrap());

    match inst {
        BPFInst::LoadX(sz, v1, v2, off) => BPFInst::LoadX(*sz, reg(0), reg(1), *off),
        BPFInst::Load64(v, imm) => BPFInst::Load64(reg(0), *imm),
        BPFInst::StoreX(sz, v1, v2, off) => BPFInst::StoreX(*sz, reg(0), reg(1), *off),
        BPFInst::Store(sz, v, off, imm) => BPFInst::Store(*sz, reg(0), *off, *imm),
        BPFInst::Alu64X(op, v1, v2) => BPFInst::Alu64X(*op, reg(0), reg(1)),
        BPFInst::Alu32X(op, v1, v2) => BPFInst::Alu32X(*op, reg(0), reg(1)),
        BPFInst::Alu64(op, v1, imm) => BPFInst::Alu64(*op, reg(0), *imm),
        BPFInst::Alu32(op, v1, imm) => BPFInst::Alu32(*op, reg(0), *imm),
        BPFInst::Endian(sz, v) => BPFInst::Endian(*sz, reg(0)),
        BPFInst::MovX(v1, v2) => BPFInst::MovX(reg(0), *v2),
        BPFInst::Mov32X(v1, v2) => BPFInst::Mov32X(reg(0), reg(1)),
        BPFInst::Mov(v1, imm) => BPFInst::Mov(reg(0), *imm),
        BPFInst::Mov32(v1, imm) => BPFInst::Mov32(reg(0), *imm),
        BPFInst::JmpX(rel, v1, v2, off) => BPFInst::JmpX(*rel, reg(0), reg(1), *off),
        BPFInst::Jmp(rel, v1, imm, off) => BPFInst::Jmp(*rel, reg(0), *imm, *off),
        BPFInst::Jmp32X(rel, v1, v2, off) => BPFInst::Jmp32X(*rel, reg(0), reg(1), *off),
        BPFInst::Jmp32(rel, v1, imm, off) => BPFInst::Jmp32(*rel, reg(0), *imm, *off),
        BPFInst::JmpA(off) => inst.clone(),
        BPFInst::Call(id) => inst.clone(),
        BPFInst::Exit => inst.clone(),
        BPFInst::PlaceHolder => inst.clone(), // panic!("BUG: BPFInst::PlaceHolder should not be here"),
    }
}
