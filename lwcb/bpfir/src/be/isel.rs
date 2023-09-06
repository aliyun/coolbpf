use std::collections::{HashMap, HashSet, VecDeque};

use generational_arena::Arena;
use regalloc2::{Block, InstRange, OperandConstraint, PReg, RegClass, VReg};

use crate::{bblock::BBlockData, func::FuncData, BBlock, Func, Module, Value, ValueKind};

use super::spec::BPFInst;
use crate::types::BinaryOp;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ISelValue(pub generational_arena::Index);

pub enum ISelValueKind {
    LoadX(ISelValue, u16), // OrderingMemory, addr, off
    Load64(i64),           // non-memory
    // store: *(uint *) (dst_reg + off16) = src_reg
    StoreX(ISelValue, ISelValue, ISelValue, u16), // OrderingMemory, DST, SRC, off
    // *(uint *) (dst_reg + off16) = imm32
    Store(ISelValue, u16, i32), // dst, off, imm
    // bpf_add|sub|...: dst_reg += src_reg
    Alu64X(BinaryOp, ISelValue, ISelValue), // BinaryOp, l, r
    Alu32X(BinaryOp, ISelValue, ISelValue), // BinaryOp, l, r
    Alu64(BinaryOp, ISelValue, i64),        // BinaryOp, l, r
    Alu32(BinaryOp, ISelValue, i32),        // BinaryOp, l, r
    Endian(ISelValue),
    // dst_reg = src_reg
    MovX(ISelValue),
    Mov32X(ISelValue),

    // dst_reg = imm32
    Mov(i32),
    Mov32(i32),
    // if (dst_reg 'BinaryOp' src_reg) goto pc + off16
    JmpX(BinaryOp, ISelValue, ISelValue, u16),
    Jmp(BinaryOp, ISelValue, i32, u16),
    Jmp32X(BinaryOp, ISelValue, ISelValue, u16),
    Jmp32(BinaryOp, ISelValue, i32, u16),
    JmpA(Block),
    Call(i32, Vec<ISelValue>),
    Exit,
}

pub struct ISelValueData {
    kind: ISelValueKind,
    vreg: VReg,
}

pub struct ISelFunction {
    pub insts: Arena<ISelValueData>,
    pub blocks: Vec<InstRange>,
    pub block_preds: Vec<Vec<Block>>,
    pub block_succs: Vec<Vec<Block>>,
    pub block_params_in: Vec<Vec<VReg>>,
    pub block_params_out: Vec<Vec<Vec<VReg>>>,
}

impl ISelFunction {
    pub fn new() -> Self {
        ISelFunction {
            insts: Default::default(),
            blocks: Default::default(),
            block_preds: Default::default(),
            block_succs: Default::default(),
            block_params_in: Default::default(),
            block_params_out: Default::default(),
        }
    }

    pub fn from_funcdata(fd: &FuncData) -> Self {
        let mut isel = ISelFunction::new();
        let mut ctx = ISelContext::default();
        do_isel(&mut ctx, &mut isel, fd);
        isel
    }

    pub fn new_value_data(&mut self, vd: ISelValueData) -> ISelValue {
        ISelValue(self.insts.insert(vd))
    }
}

#[derive(Default)]
struct ISelContext {
    // record in degree of value
    in_degree: HashMap<Value, usize>,
    value_queue: VecDeque<Value>,
    handled_value: HashMap<Value, ISelValue>,
}

fn do_isel(ctx: &mut ISelContext, isel: &mut ISelFunction, fd: &FuncData) {
    let _ = fd.cfg.values.iter().map(|(idx, vd)| {
        let tmp = vd.used_by.len();
        if tmp == 0 {
            ctx.value_queue.push_back(Value(idx));
        } else {
            ctx.in_degree.insert(Value(idx), tmp);
        }
    });

    while let Some(val) = ctx.value_queue.pop_front() {
        do_isel_inst(ctx, isel, fd, val);
    }
}

fn do_isel_inst(
    ctx: &mut ISelContext,
    isel: &mut ISelFunction,
    fd: &FuncData,
    val: Value,
) -> ISelValue {
    if let Some(ival) = ctx.handled_value.get(&val) {
        return *ival;
    }

    let get_constant = |v: Value| {
        if let ValueKind::Constant(c) = &fd.cfg.values[v.0].kind {
            return Some(c);
        }
        None
    };

    macro_rules! mark_visited_value {
        ($val: expr, $ival: expr) => {
            ctx.handled_value.insert($val, $ival);
            for u in fd.cfg.values[$val.0].kind.uses() {
                ctx.in_degree.entry(u).and_modify(|x| {
                    *x -= 1;
                    if *x == 0 {
                        ctx.value_queue.push_back(u);
                    }
                });
            }
        };
    }

    let vd = &fd.cfg.values[val.0];
    match &vd.kind {
        ValueKind::Binary(op, l, r) => {
            let lval = do_isel_inst(ctx, isel, fd, *l);
            let kind = if let Some(x) = get_constant(*r) {
                ISelValueKind::Alu64(op.clone(), lval, *x)
            } else {
                let rval = do_isel_inst(ctx, isel, fd, *r);
                ISelValueKind::Alu64X(op.clone(), lval, rval)
            };

            let ivd = ISelValueData {
                kind,
                vreg: VReg::new(1, RegClass::Int),
            };
            let ival = isel.new_value_data(ivd);
            mark_visited_value!(val, ival);
            return ival;
        }
        ValueKind::Branch(c, t, e) => {
            todo!()
        }
        ValueKind::Load(src) => {
            let src_vd = &fd.cfg.values[src.0];
            let mut off = 0;
            let mut addr = *src;
            if let ValueKind::Binary(op, l, r) = &src_vd.kind {
                get_constant(*r).map(|x| {
                    addr = *l;
                    off = *x as u16;
                });
            }

            let isel_val = do_isel_inst(ctx, isel, fd, addr);
            let ivd = ISelValueData {
                kind: ISelValueKind::LoadX(isel_val, off as u16),
                vreg: VReg::new(0, RegClass::Int),
            };
            let ival = isel.new_value_data(ivd);
            mark_visited_value!(val, ival);
            return ival;
        }

        ValueKind::Store(dst, src) => {
            // VBPFInst::Store((), (), ())
            todo!()
        }

        ValueKind::Exit => todo!(),

        ValueKind::Jump(b) => todo!(),

        _ => todo!(),
    }
}
