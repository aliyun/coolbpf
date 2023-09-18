use super::spec::BPFBOp;
use super::spec::BPFInst;
use super::spec::BPFReg;
use super::spec::BPFSize;
use crate::types::Relation;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::types;
use cranelift_codegen::ir::Block;
use cranelift_codegen::ir::ExternalName;
use cranelift_codegen::ir::FuncRef;
use cranelift_codegen::ir::Inst;
use cranelift_codegen::ir::InstructionData;
use cranelift_codegen::ir::Opcode;
use cranelift_codegen::ir::StackSlot;
use cranelift_codegen::ir::Value;
use cranelift_codegen::Context;
use regalloc2::Operand;
use regalloc2::OperandConstraint;
use regalloc2::OperandKind;
use regalloc2::OperandPos;
use regalloc2::RegClass;
use regalloc2::VReg;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;

#[derive(Default)]
pub struct ISelBlock {
    pub insts: Vec<BPFInst>,
    pub operands: Vec<Vec<Operand>>,
    pub preds: Vec<usize>,
    pub succs: Vec<usize>,
    pub params: Vec<BPFReg>,
    pub params_out: Vec<Vec<BPFReg>>,
}

impl fmt::Display for ISelBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "intput params: ")?;
        for param in &self.params {
            write!(f, "{}", param)?;
        }
        writeln!(f, "")?;
        write!(f, "output params: ")?;
        for params in &self.params_out {
            for param in params {
                write!(f, "{}", param)?;
            }
            writeln!(f, "")?;
        }
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

pub struct ISelFunctionBuilder {
    value_regs: HashMap<Value, BPFReg>,
    value_uses: HashMap<Value, u16>,

    block_args: HashMap<(Block, Block), Vec<BPFReg>>,

    block_index: HashMap<Block, usize>,
    blocks: Vec<ISelBlock>,
    fp: BPFReg,
    vreg: u32,
    used_values: HashSet<Value>,
    stackslots: HashMap<StackSlot, i16>,
    used_stacksize: i16,
}

impl ISelFunctionBuilder {
    pub fn new() -> Self {
        ISelFunctionBuilder {
            value_regs: Default::default(),
            value_uses: Default::default(),
            block_args: Default::default(),
            block_index: Default::default(),
            blocks: Default::default(),
            used_values: Default::default(),
            vreg: 0,
            // Allocate virtual registers to the fp register in advance
            fp: BPFReg::new(0),
            stackslots: Default::default(),
            used_stacksize: 0,
        }
    }

    fn new_reg(&mut self) -> BPFReg {
        self.vreg += 1;
        BPFReg::new(self.vreg)
    }

    #[inline]
    fn alloc_reg_for_value(&mut self, val: Value) {
        let reg = self.new_reg();
        self.value_regs.insert(val, reg);
    }

    // Marking this value as being used means that we need to convert the def
    // instruction of this value into BPFInst later.
    #[inline]
    fn use_value(&mut self, val: Value) {
        self.used_values.insert(val);
    }

    #[inline]
    fn is_used_value(&self, val: Value) -> bool {
        self.used_values.contains(&val)
    }

    // main entry for instruction selection
    pub fn build(mut self, ctx: &Context) -> ISelFunction {
        self.compute_stackslots(ctx);
        // Assign register to basic block parameters and operands.
        for bb in ctx.func.layout.blocks() {
            for &param in ctx.func.dfg.block_params(bb) {
                self.alloc_reg_for_value(param);
            }
            for inst in ctx.func.layout.block_insts(bb) {
                let values = ctx.func.dfg.inst_results(inst);
                assert!(values.len() <= 1);
                for &result in values {
                    self.alloc_reg_for_value(result);
                }
            }
        }

        self.compute_block_index(ctx);

        // do isel for each block in postorder.
        for block in ctx.domtree.cfg_postorder() {
            let ib = __do_isel_block(&mut self, ctx, *block);
            self.blocks.push(ib);
        }

        // Because we are traversing in postorder, we need to reverse the order.
        self.blocks.reverse();

        ISelFunction {
            blocks: self.blocks,
        }
    }

    // Calculate block order and assign index to it
    fn compute_block_index(&mut self, ctx: &Context) {
        let mut blocks = ctx.domtree.cfg_postorder().to_vec();
        blocks.reverse();
        for (idx, &block) in blocks.iter().enumerate() {
            self.block_index.insert(block, idx);
        }
    }
    // compute stackslots offset
    fn compute_stackslots(&mut self, ctx: &Context) {
        let mut stack_offset: u32 = 0;
        for (slot, data) in ctx.func.sized_stack_slots.iter() {
            let off = stack_offset;
            stack_offset += data.size;
            stack_offset = (stack_offset + 7) & (!7);
            self.stackslots.insert(slot, off as i16);
        }
        assert!(stack_offset <= 512, "Stack size more than 512 bytes");
        self.used_stacksize = stack_offset as i16;
    }

    fn add_out_args(&mut self, from: Block, to: Block, args: Vec<BPFReg>) {
        self.block_args.insert((from, to), args);
    }

    // Convert the address value into the form of base+offset. There are two
    // situations for the base, one is stack and the other is memory.
    //
    // The first situation:
    // v1 = iconst.i32 123456
    // v2 = stack_addr.i64 ss0
    // store notrap v1, v2
    fn addr_value2offset(&mut self, ctx: &Context, val: Value) -> (bool, BPFReg, i16) {
        let inst = ctx.func.dfg.value_def(val).inst().unwrap();
        let data = &ctx.func.dfg.insts[inst];
        match data {
            // Store data on the stack
            InstructionData::StackLoad {
                opcode, stack_slot, ..
            } => {
                if let &Opcode::StackAddr = opcode {
                    return (
                        true,
                        self.fp.into(),
                        (*self.stackslots.get(stack_slot).unwrap()) * -1,
                    );
                }
                unreachable!()
            }
            _ => todo!("todo: it may also be a memory address"),
        }
    }
}

fn __do_isel_block(builder: &mut ISelFunctionBuilder, ctx: &Context, block: Block) -> ISelBlock {
    let mut ib = ISelBlock::default();

    // process the branch instruction first.
    let last_inst = ctx.func.layout.last_inst(block).unwrap();
    if ctx.func.dfg.insts[last_inst].opcode().is_branch() {
        __do_isel_block_branch(builder, ctx, block, last_inst, &mut ib);
    }

    // and then process each instruction。
    for inst in ctx.func.layout.block_insts(block).rev() {
        log::debug!(
            "Instruction: {:?}, is branch: {}",
            ctx.func.dfg.insts[inst],
            ctx.func.dfg.insts[inst].opcode().is_branch()
        );
        __do_isel_inst(builder, ctx, inst, &mut ib);
    }

    // entry block
    if builder.block_index[&block] == 0 {
        assert!(ctx.func.dfg.block_params(block).len() == 1);
        let arg = ctx.func.dfg.block_params(block)[0];
        // define block params
        ib.insts.push(BPFInst::PlaceHolder);
        let reg = builder.value_regs[&arg];
        ib.operands
            .push(vec![def_operand(reg.into(), cons_fixed_reg(1))]);

        // define fp
        ib.insts.push(BPFInst::PlaceHolder);
        ib.operands
            .push(vec![def_operand(builder.fp.into(), cons_fixed_reg(10))]);
    }

    ib.insts.reverse();
    ib.operands.reverse();

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
            let bi = BPFInst::JmpA(builder.block_index[&target_block] as i16);
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
            builder.use_value(arg);
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
    let insts = &ctx.func.dfg.insts;
    let pool = &ctx.func.dfg.value_lists;
    let data = &ctx.func.dfg.insts[inst];
    let dfg = &ctx.func.dfg;

    let op = data.opcode();
    let mut operands = vec![];

    // The following commands should be executed by isel even if the value is not used.
    // return, store, call
    let is_important = op.is_return()
        || op.can_store()
        || op.is_call()
        || if ctx.func.dfg.has_results(inst) {
            let val = ctx.func.dfg.first_result(inst);
            builder.is_used_value(val)
        } else {
            false
        };

    if !is_important {
        return;
    }

    match data {
        InstructionData::Store {
            opcode: _,
            args,
            flags: _,
            offset: _,
        } => {
            let (is_stack, base, offset) = builder.addr_value2offset(ctx, args[1]);

            let bi;
            if let Some((x, y)) = get_imm_by_value(ctx, args[0]) {
                bi = BPFInst::Store(BPFSize::from_bits(y.bits()), base, offset, x as i32);
                if is_stack {
                    operands.push(use_operand(base.into(), cons_fixed_reg(10)));
                } else {
                    operands.push(use_operand(base.into(), cons_reg()));
                }
            } else {
                todo!()
                // builder.use_value(args[0]);
                // let vreg = builder.value_regs[&args[0]];
                // bi = BPFInst::StoreX(BPFSize::DW, builder.fp, vreg, offset);
                // operands = vec![use_operand(vreg.into(), cons_any())];
            }
            iblock.insts.push(bi);
            iblock.operands.push(operands);
        }
        InstructionData::Load {
            opcode: _,
            arg,
            flags: _,
            offset: _,
        } => {
            let dst = ctx.func.dfg.first_result(inst);
            let dst_reg = builder.value_regs[&dst];

            let src_inst = ctx.func.dfg.value_def(*arg).inst().unwrap();
            let src_inst_data = insts[src_inst];

            match src_inst_data {
                // source data address is constructed by base + offset(imm)
                InstructionData::Binary { opcode: _, args } => {
                    if let Some((off, _)) = get_imm_by_value(ctx, args[1]) {
                        builder.use_value(args[0]);

                        let base_reg = builder.value_regs[&args[0]];
                        let bi = BPFInst::LoadX(
                            BPFSize::from_bits(dfg.value_type(dst).bits()),
                            dst_reg,
                            base_reg,
                            off as i16,
                        );
                        let operands = [
                            def_operand(dst_reg.into(), cons_any()),
                            use_operand(base_reg.into(), cons_any()),
                        ];
                        iblock.insts.push(bi);
                        iblock.operands.push(operands.to_vec());
                    }
                }
                // imm source data is handled by Unary instruction
                _ => unreachable!("{:?}", src_inst_data),
            }
        }
        InstructionData::StackStore { .. } => unreachable!(),
        InstructionData::Call {
            opcode: _,
            args,
            func_ref,
        } => {
            let id = get_call_helperid(ctx, *func_ref);
            let bi = BPFInst::Call(id);

            for (idx, arg) in args.as_slice(pool).iter().enumerate() {
                operands.push(use_operand(
                    builder.value_regs[arg].into(),
                    cons_fixed_reg((idx + 1) as u8),
                ));
                builder.use_value(*arg);
            }
            let tmp = builder.value_regs[&ctx.func.dfg.first_result(inst)];
            operands.push(def_operand(tmp.into(), cons_fixed_reg(0)));

            iblock.insts.push(bi);
            iblock.operands.push(operands);
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
            assert!(args.len(&pool) == 1);
            let val = args.first(&pool).unwrap();
            builder.use_value(val);
            let reg = builder.value_regs[&val];

            operands.push(use_operand(reg.into(), cons_fixed_reg(0)));
            iblock.insts.push(BPFInst::Exit);
            iblock.operands.push(operands);
        }
        InstructionData::UnaryImm { opcode: _, imm } => {
            let dst_reg = builder.value_regs[&dfg.first_result(inst)];
            let imm_val = imm.bits();
            let bi = if imm_val > i32::MAX as i64 {
                // we should use BPFInst::load64 to load this imm.
                BPFInst::Load64(dst_reg, imm_val)
            } else {
                BPFInst::Mov(dst_reg, imm_val as i32)
            };
            iblock.insts.push(bi);
            iblock
                .operands
                .push(vec![def_operand(dst_reg.into(), cons_reg())]);
        }
        InstructionData::StackLoad {
            opcode: _,
            stack_slot,
            offset: _,
        } => {
            let addr_reg = builder.value_regs[&ctx.func.dfg.first_result(inst)];
            let inter_reg = builder.new_reg();
            let bi1 = BPFInst::MovX(inter_reg, builder.fp);
            let offset = builder.stackslots.get(stack_slot).unwrap();
            let bi2 = BPFInst::Alu64(BPFBOp::Sub, addr_reg, (*offset) as i32);
            iblock.insts.push(bi2);
            iblock.operands.push(vec![
                def_operand(addr_reg.into(), cons_reuse(1)),
                use_operand(inter_reg.into(), cons_reg()),
            ]);

            iblock.insts.push(bi1);
            iblock.operands.push(vec![
                def_operand(inter_reg.into(), cons_reg()),
                use_operand(builder.fp.into(), cons_fixed_reg(10)),
            ]);
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
    OperandConstraint::FixedReg(BPFReg::new(regno as u32).into())
}

#[inline]
fn cons_reuse(input: usize) -> OperandConstraint {
    OperandConstraint::Reuse(input)
}

#[inline]
fn cons_any() -> OperandConstraint {
    OperandConstraint::Any
}

#[inline]
fn cons_reg() -> OperandConstraint {
    OperandConstraint::Reg
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

fn get_call_helperid(ctx: &Context, fr: FuncRef) -> i32 {
    let func = ctx.func.dfg.ext_funcs.get(fr).unwrap();
    if let ExternalName::User(ur) = func.name {
        let ur = ctx.func.params.user_named_funcs().get(ur).unwrap();
        if ur.namespace == 0 {
            return ur.index as i32;
        }
    }
    panic!("Not a eBPF helper function id")
}

fn get_imm_by_value(ctx: &Context, val: Value) -> Option<(i64, types::Type)> {
    let inst;
    if let Some(i) = ctx.func.dfg.value_def(val).inst() {
        inst = i;
    } else {
        // it's a block parameter
        return None;
    }

    let data = &ctx.func.dfg.insts[inst];

    match data {
        InstructionData::UnaryImm { opcode, imm } => {
            if let &Opcode::Iconst = opcode {
                return Some((imm.bits(), ctx.func.dfg.value_type(val)));
            }
            panic!("Opcode of UnaryImm is not Iconst!!!")
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cranelift_codegen::isa::riscv64::isa_builder;
    use cranelift_codegen::settings::builder;
    use cranelift_codegen::settings::Configurable;
    use cranelift_codegen::settings::Flags;
    use cranelift_reader::parse_functions;
    use target_lexicon::Architecture;
    use target_lexicon::Riscv64Architecture;
    use target_lexicon::Triple;

    fn run_test_isel(text: &str, result: &str) {
        let cf = parse_functions(text).unwrap().pop().unwrap();
        let mut ctx = Context::for_function(cf);
        let mut triple = Triple::unknown();
        triple.architecture = Architecture::Riscv64(Riscv64Architecture::Riscv64);
        let mut b = builder();
        b.set("opt_level", "speed_and_size")
            .expect("failed to set optimization level");
        let flag = Flags::new(b);
        let isa = isa_builder(triple).finish(flag).unwrap();
        ctx.optimize(isa.as_ref()).unwrap();

        let ifunc = ISelFunctionBuilder::new().build(&ctx);
        assert_eq!(result, ifunc.to_string().as_str());
    }

    #[test]
    fn empty() {
        let text = "function %test(i64) -> i32 {\nblock0(v0: i64):\n    v1 = iconst.i32 0\n    return v1\n}";
        let result = "BBlock0:\nintput params: r1\noutput params: \n\nr2 = 0\nexit\n";
        run_test_isel(text, result);
    }

    #[test]
    fn store_imm_to_stack() {
        // volatile int a;
        // a = 0;
        let text = "function %test(i64) -> i32 system_v {\n    ss0 = explicit_slot 4\nblock0(v0: i64):\n    v1 = iconst.i32 123456\n    v2 = stack_addr.i64 ss0\n    store notrap v1, v2\n    return v1\n}";
        let result = "BBlock0:\nintput params: r1\noutput params: \n\nr2 = 123456\n*(u32)(r0 + 0) = 123456\nexit\n";
        run_test_isel(text, result);
    }

    #[test]
    fn store_reg_to_stack() {
        // volatile struct sock *sk;
        // sk = (struct sock *)(ctx->di)
        // let text = "function %test(i64) -> i32 system_v {\n    ss0 = explicit_slot 4\nblock0(v0: i64):\n    v1 = iconst.i32 0\n    v2 = stack_addr.i64 ss0\n    store notrap v0, v2\n    return v1\n}";
        // let result =
        //     "BBlock0:\nintput params: r1\noutput params: \n\n*(u64)(r0 + 0) = r1\nr3 = 0\nexit\n";
        // run_test_isel(text, result);
    }

    #[test]
    fn store_imm_to_memory() {
        // todo
    }

    #[test]
    fn store_reg_to_memory() {
        // todo
    }

    #[test]
    fn load_from_imm() {
        // a = 0xffffffff
        let text = "function u0:0(i64) -> i64 system_v {\n    ss0 = explicit_slot 4\n\nblock0(v0: i64):\n    v1 = iconst.i64 4294967295\n   return v1\n}";
        let result = "BBlock0:\nintput params: r1\noutput params: \n\nr2 = 4294967295\nexit\n";
        run_test_isel(text, result);
    }

    #[test]
    fn load_from_stack() {}

    #[test]
    fn load_from_memory() {
        // sk = (struct sock *)(ctx->di)
        let text = "function u0:0(i64) -> i64 system_v {\n    ss0 = explicit_slot 4\n\nblock0(v0: i64):\n    v3 = iconst.i64 9999\n    v1 = iadd v0, v3\n    v2 = load.i64 notrap aligned v1\n    return v2\n}";
        let result =
            "BBlock0:\nintput params: r1\noutput params: \n\nr4 = *(u64)(r1 + 9999)\nexit\n";
        run_test_isel(text, result);
    }

    #[test]
    fn alu64x() {
        // return ctx->r8 + ctx->r9;
    }

    #[test]
    fn alu32x() {}

    #[test]
    fn alu64() {}

    #[test]
    fn alu32() {}

    #[test]
    fn endian() {}

    #[test]
    fn movx() {}

    #[test]
    fn mov32x() {}

    #[test]
    fn mov() {}

    #[test]
    fn mov32() {}

    #[test]
    fn jmpx() {}

    #[test]
    fn jmp() {}

    #[test]
    fn jmp32x() {}

    #[test]
    fn jmp32() {}

    #[test]
    fn jmpa() {}

    #[test]
    fn call() {
        // map[0] = 1;
        let text = "function u0:0(i64) -> i64 system_v {\n    ss0 = explicit_slot 4\n    ss1 = explicit_slot 4\n    sig0 = (i64, i64, i64, i64) -> i64 system_v\n    fn0 = u0:2 sig0\n\nblock0(v0: i64):\n    v10 = iconst.i32 0\n    v11 = stack_addr.i64 ss0\n    store notrap v10, v11  ; v10 = 0\n    v7 = iconst.i32 1\n    v12 = stack_addr.i64 ss1\n    store notrap v7, v12  ; v7 = 1\n    v9 = iconst.i64 0\n    v8 -> v9\n    v14 = call fn0(v9, v11, v12, v9)  ; v9 = 0, v9 = 0\n    return v9  ; v9 = 0\n}";
        let result = "BBlock0:\nintput params: r1\noutput params: \n\nr9 = r0\nr3 -= 0\n*(u32)(r0 + 0) = 0\nr8 = r0\nr5 -= 8\n*(u32)(r0 + -8) = 1\nr6 = 0\ncall #2\nexit\n";
        run_test_isel(text, result);
    }

    #[test]
    fn exit() {
        // return
        let text = "function u0:0(i64) -> i64 system_v {\n  block0(v0: i64):\n    v1 = iconst.i64 0\n  return v1\n}";
        let result = "BBlock0:\nintput params: r1\noutput params: \n\nr2 = 0\nexit\n";
        run_test_isel(text, result);
    }
}
