use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::PathBuf;

use crate::ast::Visit;
use crate::bpf::map::{Layout, LayoutKind, PerfEvent};
use crate::btf::{
    btf_find_func, btf_find_struct, btf_find_struct_member, btf_get_func_args, btf_get_func_name,
    btf_get_func_returnty, btf_get_point_to, btf_get_struct_name, btf_get_struct_size,
    btf_skip_const, btf_skip_typedef, btf_skip_volatile, btf_struct_has_bitfield, btf_struct_size,
    btf_type_kind, btf_type_mode, btf_type_name, btf_type_size, dump_by_typeid, try_btf_find_func,
    try_btf_find_struct,
};
use crate::builtin_function::BuiltinFunction;
use crate::gperf::{perf_add_event, perf_get_event_id, perf_mapfd};
use crate::gstack::get_stackmap_fd;
use crate::types::Constant;
use crate::utils::align::{align8, roundup};
use crate::{ast::*, is_python};
use anyhow::{bail, Result};
use btfparse::BtfKind;
use libfirm_rs::{
    get_node_type, get_rvalue, immblock_add_pred, set_current_graph, set_rvalue, Entity, Graph,
    Ident, Initializer, Mode, Node, Relation, Tarval, Type, TypeKind, UsAction,
};

use super::global::*;
use super::target::Target;

use crate::bpf::program::{KprobeProgram, Program, ProgramType, TracepointProgram};

pub struct FirmProgramState {}

pub struct FirmProgram {
    // eBPF program types and name
    ptypes: Vec<BpfProgramType>,
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
    tracepoint: Option<TracepointProgram>,
    insns: Vec<u64>,

    // typeid of tracing function proto
    func_typeid: Option<u32>,
    func_names: Vec<String>,
    program_type: ProgramType,
}

impl FirmProgram {
    pub fn new(func_names: Vec<String>, program_type: ProgramType) -> Self {
        FirmProgram {
            ptypes: vec![],
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
            tracepoint: None,
            insns: vec![],
            func_typeid: None,
            func_names,
            program_type,
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

    fn func_name(&self) -> &String {
        &self.func_names[0]
    }

    fn program_type(&self) -> ProgramType {
        self.program_type
    }

    // Determine whether the name is the same
    pub fn is_name(&self, name: &str) -> bool {
        for pt in &self.ptypes {
            match pt {
                BpfProgramType::Kprobe(pname) => {
                    if pname.as_str().cmp(name) == Ordering::Equal {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
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
        match self.program_type {
            ProgramType::Kprobe => {
                let func_names = self.func_names.clone();
                for func in func_names.iter() {
                    self.attach_kprobe(func.as_str())?;
                }
            }
            _ => todo!(),
        }

        return Ok(());
    }

    fn generate_conv(&mut self, value: Node, mode: &Mode) -> Node {
        if value.mode() == *mode {
            return value;
        }

        return Node::new_conv(&value, mode);
    }

    pub fn set_perf_mapfd(&mut self, fd: i32) {
        let mut node = Node::new_const(&Tarval::new_long(fd as i64, &Mode::ModeP()));

        node.set_const_mapfd();
        self.perf_mapfd = Some(node);
    }

    // set typeid
    fn get_type(&mut self, typeid: u32) -> Type {
        loop {
            match btf_type_kind(typeid) {
                BtfKind::Ptr => {
                    let tmp = btf_get_point_to(typeid);
                    let point_to = self.get_type(tmp);
                    let pointer = Type::new_pointer(&point_to);
                    return pointer;
                }
                BtfKind::Struct => {
                    let name = CString::new(btf_get_struct_name(typeid)).unwrap();
                    let ident = Ident::new(&name);
                    let mut ty = Type::new_struct(&ident);
                    self.names.push(name);
                    ty.set_typeid(typeid);
                    // set alignment
                    // set size
                    ty.set_align(8);
                    ty.set_size(btf_get_struct_size(typeid));
                    return ty;
                }
                BtfKind::Int => {
                    let mode = btf_type_mode(typeid);
                    let mut ty = Type::new_primitive(&mode);
                    ty.set_size(mode.size());
                    return ty;
                }

                BtfKind::Typedef => {
                    return self.get_type(btf_skip_typedef(typeid));
                }

                BtfKind::Volatile => {
                    return self.get_type(btf_skip_volatile(typeid));
                }

                BtfKind::Const => {
                    return self.get_type(btf_skip_const(typeid));
                }

                BtfKind::Enum => {
                    // todo: fix this
                    return TYPE_I32.clone();
                }
                _ => {
                    panic!("{:?} not yet implemented", dump_by_typeid(typeid));
                }
            }
        }
    }

    fn get_context_type(&mut self) -> Type {
        if let Some(typeid) = try_btf_find_struct("pt_regs") {
            let mut ty = self.get_type(typeid);
            ty.set_typeid(typeid);
            return ty;
        }
        panic!("failed to find struct pt_regs in BTF");
    }

    fn get_ident(&mut self, name: &str) -> Ident {
        let cname = CString::new(name).unwrap();
        let ident = Ident::new(&cname);
        self.names.push(cname);
        return ident;
    }

    fn get_unique_ident(&mut self, name: &str) -> Ident {
        let cname = CString::new(name).unwrap();
        let ident = Ident::unique(&cname);
        self.names.push(cname);
        return ident;
    }

    // get member entity of struct, then add member entity into
    // owner type
    fn get_entity(&mut self, owner: &Type, name: &str) -> Entity {
        let mut tmp_owner = owner.clone();
        loop {
            if tmp_owner.kind() == TypeKind::Pointer {
                tmp_owner = tmp_owner.point_to();
                continue;
            }
            break;
        }
        if let Some(typeid) = tmp_owner.typeid() {
            if let Some(mem) = btf_find_struct_member(typeid, name) {
                let member_ident = self.get_ident(name);
                let member_type = self.get_type(mem.type_id);
                let mut member_entity = Entity::new_entity(&tmp_owner, &member_ident, &member_type);

                if btf_struct_has_bitfield(typeid) {
                    let (bitfield_offset, bitfield_size) = mem.offset_bitfield();
                    member_entity.set_offset((bitfield_offset / 8) as i32);
                    member_entity.set_bitfield_offset(bitfield_offset % 8);
                    member_entity.set_bitfield_size(bitfield_size);
                } else {
                    member_entity.set_offset((mem.offset() / 8) as i32);
                }

                return member_entity;
            }
        }
        panic!("Failed to get member: {} from type: {}", name, tmp_owner);
    }

    fn get_tmp_frame(&mut self, ty: &Type) -> Node {
        let frame_type = self.graph.frame_type();
        let id = self.get_unique_ident("tmp");

        let entity = Entity::new_entity(&frame_type, &id, ty);
        let frame = self.graph.frame();
        return Node::new_member(&frame, &entity);
    }

    fn get_frame(&mut self, ty: &Type, name: &str) -> Node {
        let frame_type = self.graph.frame_type();
        let id = self.get_ident(name);

        let entity = Entity::new_entity(&frame_type, &id, ty);
        let frame = self.graph.frame();
        return Node::new_member(&frame, &entity);
    }

    fn get_unique_frame(&mut self, ty: &Type) -> Node {
        // self.get_frame(ty, "name")
        todo!()
    }

    fn create_method(&mut self) {}

    /// name: function name
    /// method: function method type
    fn create_function_entity(&mut self, name: &CString, method: &Type) -> Entity {
        let id = Ident::new(name);
        let owner = Type::global_type();
        let mut func_entity = Entity::new_global(&owner, &id, method);
        func_entity
    }

    fn create_context_pointer(&mut self) {
        let args = self.graph.args();
        let ctx_node = Node::new_prog(&args, &Mode::ModeP(), 0);
        set_rvalue(self.value_number, &ctx_node);
        self.values.insert("ctx".to_owned(), self.value_number);
        self.value_number += 1;
    }

    fn load_context_register(&mut self, reg: &String) -> Result<(Node, Type)> {
        let ctx_type = self.graph.entity().type_().param(0).point_to();
        let ctx_node = self.ctx_node.unwrap();
        let member_entity = self.get_entity(&ctx_type, &reg.as_str());
        let member_node = Node::new_member(&ctx_node, &member_entity);
        self.deref_address(&member_node, &member_entity.type_())
    }

    fn generate_helper_call(
        &mut self,
        callee: &Node,
        args: &Vec<&Node>,
        method: &Type,
    ) -> Option<(Node, Type)> {
        let call = Node::new_call(&self.graph.store(), callee, args, method);
        let memory = Node::new_prog(&call, &Mode::ModeM(), libfirm_sys::pn_Call_pn_Call_M);
        self.graph.set_store(&memory);

        if method.method_n_res() >= 1 {
            let res = Node::new_prog(&call, &Mode::ModeT(), libfirm_sys::pn_Call_pn_Call_T_result);
            return Some((
                Node::new_prog(&res, &method.method_res().mode(), 0),
                method.method_res(),
            ));
        }

        return None;
    }

    ///
    /// `static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;`
    fn generate_helper_probe_read(&mut self, dst: &Node, size: &Node, src: &Node) {
        let callee = Node::new_address(&ENTITY_PROBE_READ);
        self.generate_helper_call(&callee, &vec![dst, size, src], &TYPE_PROBE_READ);
    }

    fn generate_helper_ktime_get_ns(&mut self) -> (Node, Type) {
        let callee = Node::new_address(&ENTITY_KTIME_GET_NS);
        let res = self
            .generate_helper_call(&callee, &vec![], &TYPE_KTIME_GET_NS)
            .unwrap();
        res
    }

    /// allocate frame
    fn generate_helper_probe_read_with_frame(&mut self, src: &Node, ty: &Type) -> Node {
        let mut dst = self.get_tmp_frame(&ty);
        let size = Node::new_const(&Tarval::new_long(ty.size() as i64, &Mode::ModeIu()));
        self.generate_helper_probe_read(&dst, &size, &src);
        dst.set_is_kernel_memory(0);
        dst
    }

    // static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
    fn generate_helper_perf_event_output(&mut self, data: &Node, size: u32) {
        if let Some(ctx) = self.ctx_node {
            if let Some(map) = self.perf_mapfd {
                let flags = Node::new_const(&Tarval::new_long(0xffffffff, &Mode::ModeLu()));
                let size = Node::new_const(&Tarval::new_long(size as i64, &Mode::ModeLu()));

                let callee = Node::new_address(&ENTITY_PERF_OUT);
                self.generate_helper_call(
                    &callee,
                    &vec![&ctx, &map, &flags, data, &size],
                    &TYPE_PERF_OUT,
                );
                return;
            }
            panic!("Can not find perf map, you should create it firstly")
        }
        panic!("Failed to find context pointer")
    }

    fn generate_helper_probe_read_with_load() {}

    fn generate_builtin_tcphdr(&mut self, skb: &Node, skb_ty: &Type) -> Result<(Node, Type)> {
        assert!(skb_ty.is_pointer());
        let head_entity = self.get_entity(&skb_ty.point_to(), "head");
        let head_node = Node::new_member(&skb, &head_entity);
        let (head, head_type) = self.deref_address(&head_node, &head_entity.type_())?;

        let transport_entity = self.get_entity(&skb_ty.point_to(), "transport_header");
        let transport_node = Node::new_member(&skb, &transport_entity);
        let (mut transport, transport_type) =
            self.deref_address(&transport_node, &transport_entity.type_())?;

        let typeid = btf_find_struct("tcphdr");
        let dst_type = self.get_type(typeid);
        let dst = self.get_frame(&dst_type, "tcphdr");
        let size = Node::new_const(&Tarval::new_long(
            btf_struct_size(typeid) as i64,
            &Mode::ModeIu(),
        ));

        if head.mode() != transport.mode() {
            transport = Node::new_conv(&transport, &Mode::offset_mode());
        }
        let src = Node::new_add(&head, &transport);
        self.generate_helper_probe_read(&dst, &size, &src);
        self.deref_address(&dst, &dst_type)
    }

    ///
    /// return iphdr address in frame
    ///
    /// The corresponding C language code.
    ///
    /// ```c
    /// struct iphdr ih = {0};
    /// int network_header;
    /// char *head;
    ///
    /// bpf_probe_read(&head, sizeof(head), &skb->head);
    /// bpf_probe_read(&network_header, sizeof(network_header), &skb->network_header);
    /// if (network_header != 0) {
    ///     bpf_probe_read(&ih, sizeof(ih), head + network_header);
    /// }
    /// ```
    fn generate_builtin_iphdr(&mut self, skb: &Node, skb_ty: &Type) -> (Node, Type) {
        // self.graph
        assert!(skb_ty.is_pointer());

        let dst_type = Type::new_pointer(&Type::new_pointer(&TYPE_U8));
        let dst = self.get_frame(&dst_type, "head");
        let size = Node::new_const(&Tarval::new_long(8, &Mode::ModeIu()));
        let head = self.get_entity(&skb_ty.point_to(), "head");
        let src = Node::new_member(&skb, &head);
        self.generate_helper_probe_read(&dst, &size, &src);
        let (res1, _) = self.deref_address(&dst, &dst_type.point_to()).unwrap();

        let dst_type = Type::new_pointer(&Type::new_primitive(&Mode::ModeHu()));
        let dst = self.get_frame(&dst_type, "network_header");
        let size = Node::new_const(&Tarval::new_long(2, &Mode::ModeIu()));
        let network_header = self.get_entity(&skb_ty.point_to(), "network_header");
        let src = Node::new_member(&skb, &network_header);
        self.generate_helper_probe_read(&dst, &size, &src);
        let (mut res2, _) = self.deref_address(&dst, &dst_type.point_to()).unwrap();

        let typeid = btf_find_struct("iphdr");
        let dst_type = self.get_type(typeid);
        let dst = self.get_frame(&dst_type, "iphdr");
        let size = Node::new_const(&Tarval::new_long(
            btf_struct_size(typeid) as i64,
            &Mode::ModeIu(),
        ));

        // fix:  expected mode Ls for input 'right' but found Is (Proj Is[98:32])
        if res1.mode() != res2.mode() {
            res2 = Node::new_conv(&res2, &Mode::offset_mode());
        }
        let src = Node::new_add(&res1, &res2);
        self.generate_helper_probe_read(&dst, &size, &src);
        let res = self.deref_address(&dst, &dst_type).unwrap();
        return res;
    }

    fn generate_builtin_print(&mut self, args: &Vec<(Node, Type)>) -> (Node, Type) {
        let mut first = false;
        let mut perf_type = Type::new_struct(&self.get_unique_ident("perfout_data_struct"));
        let tmpframe = self.get_frame(&perf_type, "perf_data");

        let mut layout = Layout::new(LayoutKind::Tuple(vec![]));
        let mut fmt = None;

        let event_id = perf_get_event_id();
        let mut offset = 0;

        let ident = self.get_unique_ident("member");
        let mut entity = Entity::new_entity(&perf_type, &ident, &TYPE_U64);
        entity.set_offset(offset);
        offset += 8;
        let addr = Node::new_member(&tmpframe, &entity);
        let id = Node::new_const(&Tarval::new_long(event_id as i64, &Mode::ModeLu()));
        let store = Node::new_store(&self.graph.store(), &addr, &id, &TYPE_U64);
        let store_mem = Node::new_prog(&store, &Mode::ModeM(), libfirm_sys::pn_Store_pn_Store_M);
        self.graph.set_store(&store_mem);
        // perf type id
        for arg in args.iter() {
            if !first {
                first = true;
                if is_python() {
                    fmt = Some("forpython".to_owned());
                } else {
                    // save print format string
                    fmt = Some(arg.0.address_entity().initializer().construct_string());
                    self.perf_fmtstr.push(arg.0.clone());
                    continue;
                }
            }

            let ident = self.get_unique_ident("member");
            let mut entity = Entity::new_entity(&perf_type, &ident, &arg.1);

            offset = roundup(offset as usize, arg.1.size() as usize) as i32;
            entity.set_offset(offset);
            let mut lo = Layout::from(&arg.0);
            lo.set_offset(offset as u16);
            layout.add_member(lo);
            offset += arg.1.size() as i32;

            let addr = Node::new_member(&tmpframe, &entity);
            let store = Node::new_store(&self.graph.store(), &addr, &arg.0, &arg.1);
            let store_mem =
                Node::new_prog(&store, &Mode::ModeM(), libfirm_sys::pn_Store_pn_Store_M);
            self.graph.set_store(&store_mem);
        }

        perf_add_event(PerfEvent::new(fmt, layout));

        perf_type.set_size(offset as u32);
        perf_type.set_align(8);
        self.generate_helper_perf_event_output(&tmpframe, perf_type.size());

        return (tmpframe, perf_type);
    }

    fn generate_builtin_kstack(&mut self, ctx: &Node, map: &Node) -> (Node, Type) {
        let flags = Node::new_const(&Tarval::new_long(0, &Mode::ModeLu()));
        self.generate_helper_call(
            &NODE_GET_STACKID,
            &vec![ctx, map, &flags],
            &TYPE_GET_STACKID,
        )
        .unwrap()
    }

    fn generate_builtin_ntop(&mut self, input: &Node) -> Node {
        let mut node = input.clone();
        node.set_us_action(UsAction::Ntop);
        node
    }

    /// addr: the address to dereference
    /// ty: the type of the dereferenced result (the points_to type)
    fn deref_address(&mut self, addr: &Node, ty: &Type) -> Result<(Node, Type)> {
        match ty.kind() {
            TypeKind::Struct | TypeKind::Method | TypeKind::Array => {
                return Ok((addr.clone(), ty.clone()))
            }
            _ => {}
        }

        if addr.is_kernel_memory() {
            let dst = self.generate_helper_probe_read_with_frame(&addr, ty);
            return self.deref_address(&dst, ty);
        }

        let mode = ty.mode();
        let load = Node::new_load(&self.graph.store(), addr, &mode, ty);
        let load_mem = Node::new_prog(&load, &Mode::ModeM(), libfirm_sys::pn_Load_pn_Load_M);
        let load_res = Node::new_prog(&load, &mode, libfirm_sys::pn_Load_pn_Load_res);
        self.graph.set_store(&load_mem);
        return Ok((load_res, ty.clone()));
    }

    fn typename_to_type(&mut self, tn: &TypeName) -> Type {
        let mut ty;
        match tn.type_specifier {
            TypeSpecifier::U8 => {
                ty = Type::new_primitive(&Mode::ModeBu());
            }
            _ => todo!(),
        }

        for _ in 0..tn.pointers {
            ty = Type::new_pointer(&ty);
        }
        ty
    }

    fn generate_cast_expression(
        &mut self,
        cast_expression: &CastExpression,
    ) -> Result<(Node, Type)> {
        let to_type = self.typename_to_type(&cast_expression.type_name);

        // todo: genereate address or generate value
        let from = self.generate_expression_value(&cast_expression.expression)?;

        let node = self.generate_conv(from.0, &to_type.mode());

        return Ok((node, to_type));
    }

    fn generate_expression_address(&mut self, expression: &Expression) -> Result<(Node, Type)> {
        match expression {
            Expression::Unary(u) => match u.operator {
                UnaryOperator::Indirection => {
                    return self.generate_expression_value(&u.operand);
                }
                _ => todo!(),
            },
            Expression::Member(m) => {
                let (addr, ty) = self.generate_expression_address(&m.expression)?;
                let entity = self.get_entity(&ty, &m.identifier.name);
                return Ok((Node::new_member(&addr, &entity), entity.type_()));
            }

            Expression::Identifier(i) => {
                if let Some(vn) = self.values.get(&i.name) {
                    let node = get_rvalue(*vn, &Mode::ModeP());
                    return Ok((node, get_node_type(&node)));
                }
                bail!("failed to find identifier: {}", i.name)
            }

            _ => todo!(),
        }

        todo!()
    }

    fn generate_expression_value(&mut self, expression: &Expression) -> Result<(Node, Type)> {
        match expression {
            Expression::Unary(u) => match u.operator {
                UnaryOperator::Indirection => {
                    let (addr, ty) = self.generate_expression_value(&u.operand)?;
                    if ty.is_pointer() {
                        return self.deref_address(&addr, &ty.point_to());
                    } else {
                        return self.deref_address(&addr, &ty);
                    }
                }
                _ => todo!(),
            },

            Expression::Identifier(i) => {
                if let Some(vn) = self.values.get(&i.name) {
                    let val = get_rvalue(*vn, &Mode::ModeP());
                    return Ok((val, get_node_type(&val)));
                }
                bail!("failed to find identifier: {}", i.name)
                // let addr = self.generate_expression_address(expression)?;
                // return self.deref_address(&addr, &get_node_type(&addr));
            }
            Expression::Constant(c) => {
                let mut val = None;
                match c {
                    Constant::I32(x) => {
                        val = Some(Tarval::new_long(*x as i64, &Mode::ModeIs()));
                    }
                    _ => todo!(),
                }
                if let Some(v) = &val {
                    let node = Node::new_const(v);
                    return Ok((node, v.mode().type_()));
                }
                bail!("failed to generate constant")
            }
            Expression::StringLiteral(string) => {
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

                let ty = Type::new_array(&Type::new_primitive(&Mode::ModeBu()), s.len() as u32);
                let gty = Type::global_type();
                let id = self.get_unique_ident("str");
                let mut entity = Entity::new_global(&gty, &id, &ty);

                entity.set_initializer(&strinit);
                return Ok((Node::new_address(&entity), ty));
            }
            Expression::Binary(b) => {
                match b.op {
                    BinaryOp::Assign => {
                        let (value, ty) = self.generate_expression_value(&b.right)?;

                        if let Expression::Identifier(i) = &*b.left {
                            if let Some(vn) = self.values.get(&i.name) {
                                set_rvalue(*vn, &value);
                            } else {
                                set_rvalue(self.value_number, &value);
                                self.values.insert(i.name.clone(), self.value_number);
                                self.value_number += 1;
                            }
                            return Ok((value, ty));
                        }
                        // let addr = self.generate_expression_address(&b.left);
                        panic!("We now can't handle this left expression: {:?}", b.left);
                    }
                    BinaryOp::Index => {
                        let lhs = self.generate_expression_value(&b.left)?;
                        let mut rhs = self.generate_expression_value(&b.right)?;
                        assert!(lhs.1.is_pointer());

                        if lhs.1.mode() != rhs.1.mode() {
                            rhs.0 = Node::new_conv(&rhs.0, &Mode::offset_mode());
                        }

                        let addr = Node::new_add(&lhs.0, &rhs.0);
                        self.deref_address(&addr, &lhs.1.point_to())
                    }
                    _ => {
                        todo!("{:?}", b)
                    }
                }
            }
            Expression::Cast(c) => self.generate_cast_expression(c),
            Expression::Call(c) => {
                let mut argvals = vec![];
                for arg in &c.arguments {
                    let mut nt = self.generate_expression_value(arg)?;
                    nt.0.set_type(&nt.1);
                    argvals.push(nt);
                }

                match c.callee {
                    BuiltinFunction::Tcphdr => {
                        assert!(argvals.len() == 1);
                        let skb = argvals[0];
                        self.generate_builtin_tcphdr(&skb.0, &skb.1)
                    }
                    BuiltinFunction::Iphdr => {
                        assert!(argvals.len() == 1);
                        let skb = argvals[0];
                        return Ok(self.generate_builtin_iphdr(&skb.0, &skb.1));
                    }
                    BuiltinFunction::Print => {
                        return Ok(self.generate_builtin_print(&argvals));
                    }
                    BuiltinFunction::Kstack => {
                        assert!(argvals.len() <= 1);
                        let mut depth = 20;
                        if argvals.len() == 1 {
                            depth = argvals[0].0.ulong();
                        }
                        let fd = get_stackmap_fd(depth as u8);

                        let mut map = Node::new_const(&Tarval::new_long(fd, &Mode::ModeLu()));
                        map.set_const_mapfd();

                        if let Some(ctx) = self.ctx_node {
                            let mut res = self.generate_builtin_kstack(&ctx, &map);
                            res.0.set_us_action(UsAction::from(
                                UsAction::StackMap as u32 + depth as u32,
                            ));
                            return Ok(res);
                        }
                        bail!("No context pointer")
                    }
                    BuiltinFunction::Ntop => {
                        assert!(argvals.len() == 1);
                        argvals[0].0.set_us_action(UsAction::Ntop);
                        return Ok(argvals[0]);
                    }
                    BuiltinFunction::Bswap => {
                        assert!(argvals.len() == 1);
                        let bswap = Node::new_builtin_bswap(&self.graph.store(), &argvals[0].0);
                        let return_type = bswap.builtin_type().method_res();
                        // let memory = Node::new_prog(&bswap, &Mode::ModeM(), libfirm_sys::pn_Builtin_pn_Builtin_M);
                        // self.graph.set_store(&memory);

                        let mut res = Node::new_prog(
                            &bswap,
                            &return_type.mode(),
                            libfirm_sys::pn_Builtin_pn_Builtin_max + 1,
                        );
                        res.set_type(&return_type);
                        return Ok((res, return_type));
                    }
                    BuiltinFunction::TcpState => {
                        assert!(argvals.len() == 1);
                        argvals[0].0.set_us_action(UsAction::TcpState);
                        return Ok(argvals[0]);
                    }
                    BuiltinFunction::TcpFlags => {
                        assert!(argvals.len() == 1);
                        // todo: check if is u8 type
                        argvals[0].0.set_us_action(UsAction::TcpFlags);
                        return Ok(argvals[0]);
                    }
                    BuiltinFunction::Ns => {
                        assert!(argvals.len() == 0);
                        return Ok(self.generate_helper_ktime_get_ns());
                    }
                    BuiltinFunction::TimeStr => {
                        assert!(argvals.len() == 1);
                        argvals[0].0.set_us_action(UsAction::TimeStr);
                        return Ok(argvals[0]);
                    }
                    BuiltinFunction::Ksym => {
                        assert!(argvals.len() == 1);
                        argvals[0].0.set_us_action(UsAction::Ksym);
                        return Ok(argvals[0]);
                    }
                    BuiltinFunction::Reg => {
                        assert!(argvals.len() == 1);
                        let reg = argvals[0]
                            .0
                            .address_entity()
                            .initializer()
                            .construct_string();
                        self.load_context_register(&reg)
                    }
                    _ => todo!("call expression not yet implemented: {:?}", c),
                }
            }
            Expression::Member(m) => {
                let (addr, ty) = self.generate_expression_address(expression)?;
                if ty.is_pointer() {
                    return self.deref_address(&addr, &ty.point_to());
                } else {
                    return self.deref_address(&addr, &ty);
                }
            }

            _ => todo!(),
        }
    }

    fn generate_expression(&mut self, expression: &Expression) {
        self.generate_expression_value(expression)
            .expect("failed to generate expression");
    }

    fn generate_relation_control_flow(
        &mut self,
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

    fn generate_expression_control_flow(
        &mut self,
        expression: &Expression,
        true_target: &mut Target,
        false_target: &mut Target,
    ) -> Result<Option<Node>> {
        match expression {
            Expression::Unary(u) => match u.operator {
                UnaryOperator::Negate => {
                    return self.generate_expression_control_flow(
                        &u.operand,
                        false_target,
                        true_target,
                    );
                }
                _ => {
                    panic!("Only UnaryOperator::Negate is logical expression which is control flow")
                }
            },
            Expression::Binary(b) => match b.op {
                BinaryOp::And => {
                    let mut extra_target = Target::new(None);
                    self.generate_expression_control_flow(
                        &b.left,
                        &mut extra_target,
                        false_target,
                    )?;
                    if extra_target.enter().is_some() {
                        return self.generate_expression_control_flow(
                            &b.right,
                            true_target,
                            false_target,
                        );
                    }
                    return Ok(None);
                }
                BinaryOp::Or => {
                    let mut extra_target = Target::new(None);
                    self.generate_expression_control_flow(&b.left, true_target, &mut extra_target)?;
                    if extra_target.enter().is_some() {
                        return self.generate_expression_control_flow(
                            &b.right,
                            true_target,
                            false_target,
                        );
                    }
                    return Ok(None);
                }
                _ => {
                    let relation = match b.op {
                        BinaryOp::Equal => Relation::Equal,
                        _ => todo!(),
                    };
                    let (mut left, _) = self.generate_expression_value(&b.left)?;
                    let (mut right, _) = self.generate_expression_value(&b.right)?;

                    if left.mode().size() < right.mode().size() {
                        std::mem::swap(&mut left, &mut right);
                    }
                    right = self.generate_conv(right, &left.mode());

                    self.generate_relation_control_flow(
                        &left,
                        &right,
                        &relation,
                        true_target,
                        false_target,
                    );
                    return Ok(None);
                }
            },
            _ => {
                let (mut left, _) = self.generate_expression_value(expression)?;
                let mut right = Node::new_const(&Tarval::new_long(0, &left.mode()));

                let relation = Relation::UnorderedLessGreater;

                self.generate_relation_control_flow(
                    &left,
                    &right,
                    &relation,
                    true_target,
                    false_target,
                );
                todo!()
            } // ir_node    *const right = new_Const(get_mode_null(get_irn_mode(val)));
              // ir_relation const relation = ir_relation_unordered_less_greater;
              // compare_to_control_flow(expr, left, right, relation, true_target, false_target);
              //     }
        }
    }

    fn generate_if_statement(&mut self, if_statement: &IfStatement) -> Result<()> {
        let mut true_target = Target::new(None);
        let mut false_target = Target::new(None);

        if self.graph.is_reachable() {
            self.generate_expression_control_flow(
                &if_statement.condition,
                &mut true_target,
                &mut false_target,
            )?;
        }

        let mut exit_target = Target::new(None);

        true_target.enter();
        self.generate_statement(&if_statement.then_statement)?;
        true_target.jump(&mut exit_target);

        false_target.enter();
        if let Some(s) = &if_statement.else_statement {
            self.generate_statement(s)?;
        }
        false_target.jump(&mut exit_target);

        exit_target.enter();

        Ok(())
    }

    fn generate_statement(&mut self, statement: &Statement) -> Result<()> {
        match statement {
            Statement::Expression(expression) => {
                if let Some(e) = expression {
                    self.generate_expression(e);
                }
                return Ok(());
            }
            Statement::Return => {
                // 1. if >= 0, goto perf_output
                // 2. if < 0, goto exit

                todo!()
                // let ret = ReturnNode::new(self.graph.current_block(), self.graph.store()).to_rr();
                // if let Some(end_block) = self
                //     .graph
                //     .end_block()
                //     .borrow_mut()
                //     .as_any()
                //     .downcast_mut::<Block>()
                // {
                //     end_block.add_node(ret);
                // }
                // self.graph.set_current_block(None);
                // return Ok(())
            }

            Statement::Compound(c) => {
                for statement in &c.statements {
                    self.generate_statement(statement)?;
                }
                return Ok(());
            }
            Statement::If(i) => {
                return self.generate_if_statement(i);
            }
            _ => todo!(),
        }
    }

    fn generate_function_parameters(&mut self, ctx_type_ptr: &Type, ctx_node: &Node) -> Result<()> {
        let ctx_type = ctx_type_ptr.point_to();
        if let Some(typeid) = try_btf_find_func(&self.func_name()) {
            self.set_func_typeid(typeid);
        }

        match self.program_type() {
            ProgramType::Kprobe => {
                let sec_args = if let Some(typeid) = self.try_func_typeid() {
                    btf_get_func_args(typeid)
                } else {
                    vec![]
                };
                let tmp_name = vec!["di", "si", "dx", "cx", "r8", "sp"];
                // (struct sk_buff *)ctx->di
                for i in 0..5 {
                    let member_entity = self.get_entity(&ctx_type, tmp_name[i]);
                    let member_node = Node::new_member(&ctx_node, &member_entity);

                    let (mut loaded_member_node, loaded_ty) =
                        self.deref_address(&member_node, &member_entity.type_())?;

                    if let Some(x) = sec_args.get(i) {
                        let ty = self.get_type(x.1);
                        if loaded_ty.mode() != ty.mode() {
                            loaded_member_node = Node::new_conv(&loaded_member_node, &ty.mode());
                        }
                        loaded_member_node.set_type(&ty);

                        self.values.insert(x.0.clone(), self.value_number);
                    }

                    loaded_member_node.set_is_kernel_memory(1);
                    set_rvalue(self.value_number, &loaded_member_node);
                    self.values.insert(format!("arg{}", i), self.value_number);

                    self.value_number += 1;
                }
            }
            ProgramType::Kretprobe => {
                let member_entity = self.get_entity(&ctx_type, "ax");
                let member_node = Node::new_member(&ctx_node, &member_entity);
                let (mut loaded_member_node, loaded_ty) =
                    self.deref_address(&member_node, &member_entity.type_())?;

                let return_type = if let Some(typeid) = self.try_func_typeid() {
                    self.get_type(btf_get_func_returnty(typeid))
                } else {
                    TYPE_U64.clone()
                };
                if loaded_ty.mode() != return_type.mode() {
                    loaded_member_node = Node::new_conv(&loaded_member_node, &return_type.mode());
                }
                loaded_member_node.set_type(&return_type);
                loaded_member_node.set_is_kernel_memory(1);

                self.add_rvalue("retval", &loaded_member_node);
            }
            _ => {
                todo!()
            }
        };

        Ok(())
    }

    fn generate_function_method(&mut self) -> Result<()> {
        let func_ident = self.get_unique_ident(&self.func_name().clone().as_str());
        let type_ctx = self.get_context_type();
        let type_ctx_ptr = Type::new_pointer(&type_ctx);
        let method = Type::new_method(&vec![type_ctx_ptr], None);

        let global_type = Type::global_type();
        let entity = Entity::new_global(&global_type, &func_ident, &method);

        self.graph = Graph::new(&entity, 100);
        set_current_graph(&self.graph);

        Ok(())
    }

    fn add_rvalue(&mut self, name: &str, value: &Node) {
        set_rvalue(self.value_number, value);
        self.values.insert(name.to_owned(), self.value_number);
        self.value_number += 1;
    }

    fn generate_function(&mut self) -> Result<()> {
        self.generate_function_method()?;

        // create context node
        let args = self.graph.args();
        let ctx_node = Node::new_prog(&args, &Mode::ModeP(), 0);
        self.add_rvalue("ctx", &ctx_node);

        self.ctx_node = Some(ctx_node.clone());

        self.generate_function_parameters(&self.graph.entity().type_().param(0), &ctx_node)?;
        Ok(())
    }

    pub fn generate(&mut self, program: &BpfProgram) -> Result<()> {
        self.generate_function()?;

        self.set_perf_mapfd(perf_mapfd() as i32);

        self.generate_statement(&program.statement).unwrap();

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
