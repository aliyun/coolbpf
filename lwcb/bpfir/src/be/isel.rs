use super::spec::BPFInst;
use super::spec::BPFSpec;
use crate::be::spec::new_vreg;
use crate::types::Relation;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::Block;
use cranelift_codegen::ir::Inst;
use cranelift_codegen::ir::InstructionData;
use cranelift_codegen::ir::Value;
use cranelift_codegen::Context;
use regalloc2::Operand;
use regalloc2::OperandConstraint;
use regalloc2::OperandKind;
use regalloc2::OperandPos;
use regalloc2::VReg;
use std::collections::HashMap;
use std::fmt;

#[derive(Default)]
pub struct ISelBlock {
    pub insts: Vec<BPFInst>,
    pub operands: Vec<Vec<Operand>>,
    pub preds: Vec<usize>,
    pub succs: Vec<usize>,
    pub params: Vec<VReg>,
    pub params_out: Vec<Vec<VReg>>,
}

impl fmt::Display for ISelBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for inst in &self.insts {
            writeln!(f, "{inst}")?;
        }
        Ok(())
    }
}

impl ISelBlock {}

#[derive(Default)]
pub struct ISelFunction {
    pub blocks: Vec<ISelBlock>,
}

impl fmt::Display for ISelFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, block) in self.blocks.iter().enumerate() {
            write!(f, "BBlock{idx}:\n{block}")?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ISelFunctionBuilder {
    value_regs: HashMap<Value, VReg>,
    value_uses: HashMap<Value, u16>,

    block_args: HashMap<(Block, Block), Vec<VReg>>,

    block_index: HashMap<Block, usize>,
    blocks: Vec<ISelBlock>,
}

impl ISelFunctionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(mut self, ctx: &Context) -> ISelFunction {
        for bb in ctx.func.layout.blocks() {
            for param in ctx.func.dfg.block_params(bb) {
                self.value_regs.insert(*param, new_vreg());
            }
            for inst in ctx.func.layout.block_insts(bb) {
                let values = ctx.func.dfg.inst_results(inst);
                assert!(values.len() <= 1);
                for result in values {
                    self.value_regs.insert(*result, new_vreg());
                }
            }
        }

        self.compute_block_index(ctx);

        for block in ctx.domtree.cfg_postorder() {
            let ib = __do_isel_block(&mut self, ctx, *block);
            self.blocks.push(ib);
        }

        self.blocks.reverse();

        ISelFunction {
            blocks: self.blocks,
        }
    }

    fn compute_block_index(&mut self, ctx: &Context) {
        let mut blocks = ctx.domtree.cfg_postorder().to_vec();
        blocks.reverse();
        for (idx, &block) in blocks.iter().enumerate() {
            self.block_index.insert(block, idx);
        }
    }

    fn add_out_args(&mut self, from: Block, to: Block, args: Vec<VReg>) {
        self.block_args.insert((from, to), args);
    }
}

fn __do_isel_block(builder: &mut ISelFunctionBuilder, ctx: &Context, block: Block) -> ISelBlock {
    let mut ib = ISelBlock::default();
    for inst in ctx.func.layout.block_insts(block).rev() {
        log::debug!(
            "Instruction: {:?}, is branch: {}",
            ctx.func.dfg.insts[inst],
            ctx.func.dfg.insts[inst].opcode().is_branch()
        );
        let last_inst = ctx.func.layout.last_inst(block).unwrap();
        if ctx.func.dfg.insts[last_inst].opcode().is_branch() {
            __do_isel_block_branch(builder, ctx, block, last_inst, &mut ib);
        }

        __do_isel_inst(builder, ctx, inst, &mut ib);
    }

    // add block parameters
    for arg in ctx.func.dfg.block_params(block) {
        ib.params.push(builder.value_regs[arg]);
    }

    // add predecessors
    for pred in ctx.cfg.pred_iter(block) {
        let idx = builder.block_index[&pred.block];
        ib.preds.push(idx);
    }

    // add successors
    for succ in ctx.cfg.succ_iter(block) {
        let idx = builder.block_index[&succ];
        ib.succs.push(idx);
        ib.params_out.push(vec![]);
    }

    ib
}

fn __do_isel_block_branch(
    builder: &mut ISelFunctionBuilder,
    ctx: &Context,
    block: Block,
    br: Inst,
    iblock: &mut ISelBlock,
) {
    let pool = &ctx.func.dfg.value_lists;
    let data = &ctx.func.dfg.insts[br];
    match data {
        InstructionData::Jump {
            opcode,
            destination,
        } => {
            let target_block = destination.block(pool);
            let bi = BPFInst::JmpA(builder.block_index[&target_block] as u16);
            iblock.insts.push(bi);
            iblock.operands.push(vec![]);
        }
        InstructionData::Brif {
            opcode,
            arg,
            blocks,
        } => {
            todo!();
            let then_block = blocks[0].block(pool);
            let else_block = blocks[1].block(pool);

            let pre_inst = ctx.func.dfg.value_def(*arg).inst().unwrap();

            match &ctx.func.dfg.insts[pre_inst] {
                InstructionData::IntCompare { opcode, args, cond } => {
                    let rel = intcc2relation(cond);
                    todo!()
                }
                InstructionData::IntCompareImm {
                    opcode,
                    arg,
                    cond,
                    imm,
                } => {}

                _ => panic!("not integer compare instruction"),
            }
        }
        _ => panic!("unexpected branch instruction: {:?}", br),
    }

    let succs: Vec<Block> = ctx.cfg.succ_iter(block).collect();
    for (idx, &succ) in succs.iter().enumerate() {
        let branch = ctx.func.dfg.insts[br].branch_destination(&ctx.func.dfg.jump_tables);
        let branch_args = branch[idx].args_slice(&ctx.func.dfg.value_lists);
        let mut vregs = vec![];
        for &arg in branch_args {
            let arg = ctx.func.dfg.resolve_aliases(arg);
            builder.value_uses.get_mut(&arg).map(|x| *x += 1);
            vregs.push(builder.value_regs[&arg]);
        }
        builder.add_out_args(block, succ, vregs);
    }
}

fn __do_isel_inst(
    builder: &mut ISelFunctionBuilder,
    ctx: &Context,
    inst: Inst,
    iblock: &mut ISelBlock,
) {
    let vl_pool = &ctx.func.dfg.value_lists;
    let data = &ctx.func.dfg.insts[inst];

    let op = data.opcode();
    let mut operands = vec![];

    let is_important = op.is_return()
        || if ctx.func.dfg.has_results(inst) {
            let val = ctx.func.dfg.first_result(inst);
            builder.value_uses.contains_key(&val)
        } else {
            false
        };

    if !is_important {
        return;
    }

    match data {
        InstructionData::StackStore {
            opcode,
            arg,
            stack_slot,
            offset,
        } => {
            todo!()
        }
        InstructionData::Call {
            opcode,
            args,
            func_ref,
        } => {
            let bi = BPFInst::Call(func_ref.as_u32() as i32);

            for (idx, arg) in args.as_slice(vl_pool).iter().enumerate() {
                operands.push(use_operand(
                    builder.value_regs[arg],
                    cons_fixed_reg((idx + 1) as u8),
                ));
            }
            let tmp = builder.value_regs[&ctx.func.dfg.first_result(inst)];
            operands.push(def_operand(tmp, cons_fixed_reg(0)));
        }
        InstructionData::Brif {
            opcode,
            arg,
            blocks,
        } => {
            todo!()
        }
        InstructionData::MultiAry { opcode, args } => {
            assert!(opcode.is_return());
            assert!(args.len(&vl_pool) == 1);
            let first = args.first(vl_pool).unwrap();
            let vreg = builder.value_regs[&first];
            let bi = BPFInst::Mov(vreg, 0);
            operands.push(def_operand(vreg, cons_fixed_reg(0)));
            iblock.insts.push(bi);
            iblock.insts.push(BPFInst::Exit);
            iblock.operands.push(operands);
            iblock.operands.push(vec![]);
        }
        _ => todo!(),
    }
}

#[inline]
fn use_operand(vreg: VReg, cons: OperandConstraint) -> Operand {
    Operand::new(vreg, cons, OperandKind::Use, OperandPos::Early)
}

#[inline]
fn def_operand(vreg: VReg, cons: OperandConstraint) -> Operand {
    Operand::new(vreg, cons, OperandKind::Def, OperandPos::Late)
}

#[inline]
fn cons_fixed_reg(regno: u8) -> OperandConstraint {
    OperandConstraint::FixedReg(BPFSpec::reg(regno))
}

#[inline]
fn cons_any() -> OperandConstraint {
    OperandConstraint::Any
}

#[inline]
fn intcc2relation(cc: &IntCC) -> Relation {
    match cc {
        IntCC::Equal => Relation::Equal,
        IntCC::NotEqual => Relation::NotEqual,
        IntCC::UnsignedGreaterThan => Relation::Greater,
        IntCC::UnsignedGreaterThanOrEqual => Relation::GreateEqual,
        IntCC::UnsignedLessThan => Relation::Less,
        IntCC::UnsignedLessThanOrEqual => Relation::LessEqual,
        _ => todo!(),
    }
}
