use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::PathBuf;

use crate::context::Context;
use crate::ast::*;
use crate::types::{Constant, TypeKind};
use crate::utils::align::{align8, roundup};
use anyhow::{bail, Result};
use btfparse::BtfKind;
use libfirm_rs::{
    get_node_type, get_rvalue, immblock_add_pred, set_current_graph, set_rvalue, Entity, Graph,
    Ident, Initializer, Mode, Node, Relation, Tarval, Type as IrType, TypeKind as IrTypeKind,
    UsAction,
};

use super::builtin::{gen_builtin, gen_deref, gen_member_by_type};
use super::entity::method_entity;
use super::frame::unique_ident;
use super::global::*;
use super::target::Target;
use super::types::pt_regs_type;

use crate::bpf::program::{KprobeProgram, Program, ProgramType, TracepointProgram};

use crate::types::Type;

pub struct FirmProgramState {}

pub struct FirmProgram {
    // eBPF program types and name
    graph: Graph,

    types: HashMap<u32, Type>,

    value_number: i32,
    values: HashMap<String, i32>,

    // Temporarily store CString to extend its life cycle
    names: Vec<CString>,

    sec_typeid: Vec<u32>,

    ctx_type: Option<Type>,
    ctx_node: Option<Node>,
    perf_mapfd: Option<Node>,
    perf_fmtstr: Vec<Node>,

    kprobe: Option<KprobeProgram>,
    kretprobe: Option<KprobeProgram>,
    tracepoint: Option<TracepointProgram>,
    insns: Vec<u64>,
    
    // typeid of tracing function proto
    func_typeid: Option<u32>,
    func_names: Vec<String>,
}

fn type_to_mode() -> Mode {
    todo!()
}

impl FirmProgram {
    pub fn new() -> Self {
        FirmProgram {
            graph: Graph::null(),
            types: HashMap::default(),
            value_number: 0,
            values: HashMap::default(),
            names: vec![],
            sec_typeid: vec![],
            ctx_type: None,
            ctx_node: None,
            perf_mapfd: None,
            perf_fmtstr: vec![],
            kprobe: None::<KprobeProgram>,
            kretprobe: None,
            tracepoint: None,
            insns: vec![],
            func_typeid: None,
            func_names: vec![],
        }
    }

    pub fn set_func_typeid(&mut self, typeid: u32) {
        self.func_typeid = Some(typeid);
    }

    fn func_typeid(&self) -> u32 {
        self.func_typeid.unwrap()
    }

    fn try_func_typeid(&self) -> Option<u32> {
        self.func_typeid
    }

    pub fn set_func_name(&mut self, name: String) {
        self.func_names.push(name);
    }

    pub fn set_kprobe(&mut self) {
        self.kprobe = Some(KprobeProgram::new());
    }

    pub fn set_kretprobe(&mut self) {
        let mut kretprobe = KprobeProgram::new();
        kretprobe.set_kretprobe(true);
        self.kretprobe = Some(kretprobe);
    }

    fn func_name(&self) -> &String {
        &self.func_names[0]
    }

    // Determine whether the name is the same
    pub fn is_name(&self, name: &str) -> bool {
        todo!()
    }

    // Try load eBPF program with kprobe type.
    pub fn load_kprobe(&mut self, is_kret: bool) -> Result<()> {
        if self.is_load_kprobe() {
            return Ok(());
        }

        let mut kprobe = KprobeProgram::new();
        kprobe.set_kretprobe(is_kret);
        kprobe.set_insns(self.insns.clone());
        kprobe.load()?;

        self.kprobe = Some(kprobe);
        return Ok(());
    }

    // Determine whether eBPF program loaded
    pub fn is_load_kprobe(&self) -> bool {
        self.kprobe.is_some()
    }

    // Attach firmprogram with kprobe
    pub fn attach_kprobe(&mut self, name: &str) -> Result<()> {
        self.load_kprobe(false)?;
        if let Some(kprobe) = &mut self.kprobe {
            return kprobe.attach(name, 0);
        }
        bail!("Failed to attach kprobe: {}", name)
    }

    pub fn attach_kretprobe(&mut self, name: &str) -> Result<()> {
        self.load_kprobe(true)?;
        if let Some(kprobe) = &mut self.kprobe {
            return kprobe.attach(name, 0);
        }
        bail!("Failed to attach kprobe: {}", name)
    }

    pub fn attach(&mut self) -> Result<()> {
        let name = self.func_name().clone();
        if let Some(k) = &mut self.kprobe {
            k.set_insns(self.insns.clone());
            k.load()?;
            k.attach(&name, 0)?;
        }

        return Ok(());
    }

    // convert
    fn conv(&mut self, value: Node, mode: &Mode) -> Node {
        if value.mode() == *mode {
            return value;
        }

        return Node::new_conv(&value, mode);
    }

    fn gen_cast(&mut self, ctx: &mut Context, from: &Expr, to: &NodeId) -> Result<Node> {
        // todo: genereate address or generate value
        let from_node = self.gen_expr_val(ctx, &from)?;

        let node = self.conv(from_node, &ctx.tb.type_(to).mode());

        return Ok(node);
    }

    fn gen_expr_addr(&mut self, ctx: &mut Context, expr: &Expr) -> Result<Node> {
        match &expr.kind {
            ExprKind::Unary(op, e) => match op {
                UnaryOp::Deref => {
                    return self.gen_expr_val(ctx, e);
                }
                _ => todo!(),
            },

            ExprKind::Member(p, s) => {
                let addr = self.gen_expr_addr(ctx, p)?;
                let typ = ctx.tb.type_(&expr.id);

                return Ok(Node::new_add(
                    addr,
                    Node::new_const(&Tarval::new_long(typ.size() as i64, &Mode::ModeLu())),
                ));
            }

            ExprKind::Ident(i) => {
                if let Some(vn) = self.values.get(i) {
                    let node = get_rvalue(*vn, &Mode::ModeP());
                    return Ok(node);
                }
                bail!("failed to find identifier: {}", i)
            }

            _ => todo!(),
        }

        todo!()
    }

    fn get_rvalue(&mut self, name: &str) -> Option<Node> {
        self.values
            .get(name)
            .map(|vn| get_rvalue(*vn, &Mode::ModeP()))
    }

    fn gen_expr_val(&mut self, ctx: &mut Context, expr: &Expr) -> Result<Node> {
        match &expr.kind {
            ExprKind::Unary(op, e) => match op {
                UnaryOp::Deref => {
                    let mut addr = self.gen_expr_val(ctx, e)?;
                    return Ok(gen_deref(addr, ctx.tb.type_(&expr.id)));
                }
                _ => todo!(),
            },

            ExprKind::Ident(i) => {
                // if let Some(vn) = self.values
                let ctx_node = self.get_rvalue("ctx").unwrap();
                let typ = ctx.tb.type_(&expr.id);
                return self.get_rvalue(i).map_or_else(
                    || {
                        if typ.param() {
                            log::debug!("load function parameter from context pointer: {i}");
                            return Ok(gen_member_by_type(&ctx_node, &typ));
                        } else {
                            bail!("Unknow identifier: {}", i)
                        }
                    },
                    |x| Ok(x),
                );
            }

            ExprKind::Const(c) => {
                let mut val = None;
                match c {
                    Constant::I32(x) => {
                        val = Some(Tarval::new_long(((*x) as i64), &Mode::ModeIs()));
                    }
                    _ => todo!(),
                }
                if let Some(v) = &val {
                    let node = Node::new_const(v);
                    return Ok(node);
                }
                bail!("failed to generate constant")
            }
            ExprKind::LitStr(string) => {
                // delete "
                let mut s = string[1..(string.len() - 1)].to_owned();
                // https://stackoverflow.com/questions/72583983/interpreting-escape-characters-in-a-string-read-from-user-input
                // replace literal escape to actual speical character
                s = s.replace("\\n", "\n");
                let mut strinit = Initializer::new_compound(s.len() as u64);
                for (i, c) in s.chars().enumerate() {
                    let val = Tarval::new_long(c as i64, &Mode::ModeBu());
                    let init = Initializer::from_tarval(&val);
                    strinit.compound_set_value(i as u64, &init);
                }

                let ty = IrType::new_array(&IrType::new_primitive(&Mode::ModeBu()), s.len() as u32);
                let gty = IrType::global_type();
                let id = unique_ident("str");
                let mut entity = Entity::new_global(&gty, &id, &ty);

                entity.set_initializer(&strinit);
                return Ok(Node::new_address(&entity));
            }
            ExprKind::Binary(op, l, r) => {
                match op {
                    BinaryOp::Assign => {
                        let val = self.gen_expr_val(ctx, &r)?;
                        if let ExprKind::Ident(i) = &l.kind {
                            if let Some(vn) = self.values.get(i) {
                                set_rvalue(*vn, &val);
                            } else {
                                self.add_rvalue(i, &val);
                            }
                        }
                        return Ok(val);
                    }

                    BinaryOp::Index => {
                        let lhs = self.gen_expr_val(ctx, l)?;
                        let mut rhs = self.gen_expr_val(ctx, r)?;

                        if ctx.tb.type_(&l.id).is_ptr() {
                            // todo: check mode
                            // rhs.0 = Node::new_conv(&rhs.0, &Mode::offset_mode());
                        }

                        todo!()
                    }

                    _ => todo!(),
                }
            }

            ExprKind::Cast(from, to) => return self.gen_cast(ctx, from, &to.id),
            ExprKind::BuiltinCall(c, args) => {
                let mut argvals = vec![];
                for arg in args {
                    argvals.push((self.gen_expr_val(ctx, arg)?, arg.id));
                    
                }

                return gen_builtin(ctx, c, &self.get_rvalue("ctx").unwrap(), argvals);
            }

            ExprKind::Member(p, s) => {
                let mut addr = self.gen_expr_addr(ctx, expr)?;
                return Ok(gen_deref(addr, &ctx.tb.type_(&expr.id)));
            }
            _ => todo!(),
        }
    }

    fn gen_expr(&mut self, ctx: &mut Context, expr: &Expr) {
        self.gen_expr_val(ctx, expr)
            .expect("failed to generate expression");
    }
    // generate relation control flow
    fn gen_rel_cf(
        &mut self,
        ctx: &mut Context,
        left: &Node,
        right: &Node,
        relation: &Relation,
        true_target: &mut Target,
        false_target: &mut Target,
    ) {
        let cmp = Node::new_cmp(left, right, relation);
        let cond = Node::new_cond(&cmp);
        let true_prog = Node::new_prog(&cond, &Mode::ModeX(), libfirm_sys::pn_Cond_pn_Cond_true);
        let false_prog = Node::new_prog(&cond, &Mode::ModeX(), libfirm_sys::pn_Cond_pn_Cond_false);

        true_target.add_pred(&true_prog);
        false_target.add_pred(&false_prog);

        // unreachable now
        self.graph.set_unreachable();
    }
    // generate expression control flow
    fn gen_expr_cf(
        &mut self,
        ctx: &mut Context,
        expr: &Expr,
        true_target: &mut Target,
        false_target: &mut Target,
    ) -> Result<Option<Node>> {
        match &expr.kind {
            ExprKind::Unary(op, e) => match op {
                UnaryOp::Neg => {
                    return self.gen_expr_cf(ctx, e, false_target, true_target);
                }
                _ => {
                    panic!("Only UnaryOp::Negate is logical expression which is control flow")
                }
            },

            ExprKind::Binary(op, l, r) => match op {
                BinaryOp::And => {
                    let mut extra_target = Target::new(None);
                    self.gen_expr_cf(ctx, l, &mut extra_target, false_target)?;
                    if extra_target.enter().is_some() {
                        return self.gen_expr_cf(ctx, r, true_target, false_target);
                    }
                    return Ok(None);
                }

                _ => {
                    let relation = match op {
                        BinaryOp::Equal => Relation::Equal,
                        _ => todo!(),
                    };
                    let mut left = self.gen_expr_val(ctx, l)?;
                    let mut right = self.gen_expr_val(ctx, r)?;

                    if left.mode().size() < right.mode().size() {
                        std::mem::swap(&mut left, &mut right);
                    }
                    // right = self.generate_conv(right, &left.mode());

                    self.gen_rel_cf(ctx, &left, &right, &relation, true_target, false_target);
                    return Ok(None);
                }
            },
            _ => {
                let mut left = self.gen_expr_val(ctx, expr)?;
                let mut right = Node::new_const(&Tarval::new_long(0, &left.mode()));

                let relation = Relation::UnorderedLessGreater;

                self.gen_rel_cf(ctx, &left, &right, &relation, true_target, false_target);
                todo!()
            }
        }
    }

    fn gen_if_stmt(
        &mut self,
        ctx: &mut Context,
        c: &Expr,
        t: &Expr,
        e: &Option<Box<Expr>>,
    ) -> Result<()> {
        let mut true_target = Target::new(None);
        let mut false_target = Target::new(None);

        if self.graph.is_reachable() {
            self.gen_expr_cf(ctx, c, &mut true_target, &mut false_target)?;
        }

        let mut exit_target = Target::new(None);

        true_target.enter();
        self.gen_stmt(ctx, t)?;
        true_target.jump(&mut exit_target);

        false_target.enter();
        if let Some(x) = e {
            self.gen_stmt(ctx, x)?;
        }
        false_target.jump(&mut exit_target);

        exit_target.enter();

        Ok(())
    }

    fn gen_stmt(&mut self, ctx: &mut Context, expr: &Expr) -> Result<()> {
        match &expr.kind {
            ExprKind::ExprStmt(e) => {
                self.gen_expr(ctx, e);
            }

            ExprKind::Return => {
                todo!()
            }

            ExprKind::Compound(es) => {
                for e in es {
                    self.gen_stmt(ctx, e)?;
                }
            }

            ExprKind::If(c, t, e) => {
                self.gen_if_stmt(ctx, c, t, e);
            }
            _ => todo!(),
        }

        Ok(())
    }

    fn add_rvalue(&mut self, name: &str, value: &Node) {
        set_rvalue(self.value_number, value);
        self.values.insert(name.to_owned(), self.value_number);
        self.value_number += 1;
    }

    /// generate firm graph.
    fn gen_graph(&mut self, prog_type: &Type, local: usize) {
        // decide function name
        let method_entity = method_entity(prog_type);
        self.graph = Graph::new(&method_entity, local);
        set_current_graph(&self.graph);
    }

    /// generate tracing function default parameters: `struct pt_regs *`
    fn gen_params(&mut self) {
        let args = self.graph.args();
        let ctx_node = Node::new_prog(&args, &Mode::ModeP(), 0);
        self.add_rvalue("ctx", &ctx_node);
    }

    pub fn gen(
        &mut self,
        ctx: &mut Context,
        id: NodeId,
        expr: &Expr,
        local: usize,
    ) -> Result<()> {
        // create firm graph
        self.gen_graph(ctx.tb.type_(&id), local);
        // create parameters
        self.gen_params();
        // generate expression ir
        self.gen_stmt(ctx, expr).unwrap();

        let mut end_block = self.graph.end_block();
        let mut ret = Node::new_return(&self.graph.store());
        immblock_add_pred(&end_block, &ret);

        self.graph.finalize_cons();

        self.graph.walk_type(|ty, _| {
            if ty.is_struct() {
                ty.set_layout_fixed();
            }
        });
        Ok(())
    }

    pub fn optimize(&mut self) {
        self.graph.opt_lower_highlevel();
        self.graph.opt_conv();
    }

    pub fn generate_bytecode(&mut self) {
        self.insns = self.graph.bytecodes();
    }

    pub fn dump(&self, out: &PathBuf) {
        self.graph.dump(out);
    }

    pub fn emit(&mut self, out: &str) {}
}
