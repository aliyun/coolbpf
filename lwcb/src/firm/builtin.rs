use libfirm_rs::{current_graph, Mode, Node, Tarval, Type as IrType, UsAction};

use super::{
    frame::{alloc_frame, unique_ident},
    helper::{gen_helper_get_stackid, gen_helper_ktime_get_ns, gen_helper_probe_read_with_frame, gen_helper_perf_event_output},
    map::map_node,
    types::gen_struct_type,
};
use crate::{
    ast::nodeid::NodeId, context::Context, event::Event, perf_event::PerfEvent, types::Type,
};
use crate::{
    builtin::{Builtin, KBuiltin},
    gstack::get_stackmap_fd,
    is_python,
    types::TypeKind,
};
use anyhow::Result;

pub fn gen_builtin(
    ctx: &mut Context,
    builtin: &Builtin,
    ctx_node: &Node,
    args: Vec<(Node, NodeId)>,
) -> Result<Node> {
    let node = match builtin {
        Builtin::User(u) => args[0].0,
        Builtin::Kernel(k) => match k {
            KBuiltin::Bswap => gen_builtin_bswap(&args[0].0, ctx.tb.type_(&args[0].1)),
            KBuiltin::Iphdr => gen_builtin_iphdr(&args[0].0, ctx.tb.type_(&args[0].1)),
            KBuiltin::Kstack => {
                let mut depth = 20;
                if args.len() == 1 {
                    depth = args[0].0.ulong();
                }
                gen_builtin_kstack(ctx_node, depth as u8)
            }
            KBuiltin::Ns => gen_builtin_ns(),
            KBuiltin::Pid => todo!(),
            KBuiltin::Print => gen_builtin_print(ctx, ctx_node, &args),
            KBuiltin::Reg => gen_builtin_reg(ctx_node, "ip"),
            KBuiltin::Tcphdr => gen_builtin_tcphdr(&args[0].0, ctx.tb.type_(&args[0].1)),
        },
    };

    Ok(node)
}

pub fn cast_mode(src: Node, mode: Mode) -> Node {
    if src.mode() == mode {
        return src;
    }
    log::debug!("cast mode: {} -> {}", src.mode(), mode);
    return Node::new_conv(&src, &mode);
}

/// do derefence
pub fn gen_deref(mut addr: Node, typ: &Type) -> Node {
    log::debug!("deref address with type: {}", typ);
    if typ.kmem() {
        let dst = gen_helper_probe_read_with_frame(&addr, typ);
        let mut new_typ = typ.clone();
        new_typ.clear_kmem();
        return gen_deref(dst, &new_typ);
    }

    if typ.is_struct() || typ.is_union() {
        return addr;
    }

    let mut graph = current_graph();
    let mode = typ.mode();

    addr = cast_mode(addr, Mode::ModeP());
    let load = Node::new_load(&graph.store(), &addr, &mode, &typ.irtype());
    let load_mem = Node::new_prog(&load, &Mode::ModeM(), libfirm_sys::pn_Load_pn_Load_M);
    let load_res = Node::new_prog(&load, &mode, libfirm_sys::pn_Load_pn_Load_res);
    graph.set_store(&load_mem);
    return load_res;
}

pub fn gen_store(addr: &Node, offset: usize, value: &Node, value_type: &Type) {
    let mut graph = current_graph();
    let offset_node = Node::new_const(&Tarval::new_long(offset as i64, &Mode::ModeLs()));
    let ptr = Node::new_add(*addr, offset_node);
    let store = Node::new_store(&graph.store(), &ptr, value, &value_type.irtype());
    let store_mem = Node::new_prog(&store, &Mode::ModeM(), libfirm_sys::pn_Store_pn_Store_M);
    graph.set_store(&store_mem);
}

/// load structure's member by structure's node and member type
pub fn gen_member_by_type(st: &Node, member_type: &Type) -> Node {
    // todo: check bitfield
    let member_offset = Node::new_const(&Tarval::new_long(
        member_type.offset() as i64,
        &Mode::ModeLu(),
    ));
    let member_node = Node::new_add(*st, member_offset);

    gen_deref(member_node, &member_type)
}

/// load structure's member by structure's node, structure's type and member name
/// find member type by member name
fn gen_member_by_name(st: &Node, typ: &Type, name: &str) -> Node {
    log::debug!("Getting member {} from type {}", name, typ);
    let member_type = typ.member_type(name);
    gen_member_by_type(st, &member_type)
}

// gen builtin tcphdr
pub fn gen_builtin_tcphdr(skb: &Node, typ: &Type) -> Node {
    let skb_type = typ.ptr_to();

    let head_node = gen_member_by_name(skb, &skb_type, "head");
    let transport_header_node = gen_member_by_name(skb, &skb_type, "transport_header");

    let addr = Node::new_add(head_node, transport_header_node);
    let mut tcphdr_type = Type::from_struct_name("tcphdr");
    tcphdr_type.set_kmem();

    gen_deref(addr, &tcphdr_type)
}

// kstack(depth) -> stackid
fn gen_builtin_kstack(ctx: &Node, depth: u8) -> Node {
    let fd = get_stackmap_fd(depth);
    let map = map_node(fd);
    let mut stackid = gen_helper_get_stackid(ctx, &map);

    stackid.set_us_action(UsAction::from(UsAction::StackMap as u32 + depth as u32));
    stackid
}

// ntop(addr) -> string
fn gen_builtin_ntop(input: &Node) -> Node {
    let mut node = input.clone();
    node.set_us_action(UsAction::Ntop);
    node
}

// regname
fn gen_builtin_reg(ctx: &Node, name: &str) -> Node {
    let ctx_type = Type::from_struct_name("pt_regs");
    let member_type = ctx_type.find_member(name);
    gen_member_by_type(ctx, &member_type)
}

fn gen_builtin_ns() -> Node {
    gen_helper_ktime_get_ns()
}

fn gen_builtin_bswap(node: &Node, typ: &Type) -> Node {
    let bswap = Node::new_builtin_bswap(&current_graph().store(), node, &typ.irtype());
    let return_type = bswap.builtin_type().method_res();
    Node::new_prog(
        &bswap,
        &return_type.mode(),
        libfirm_sys::pn_Builtin_pn_Builtin_max + 1,
    )
}

fn gen_perf_event_struct_type(event_id: usize, types: &Vec<&Type>) -> Type {
    let mut new_types = vec![Type::u64()];
    for typ in types {
        new_types.push((*typ).clone());
    }

    let mut new_type = gen_struct_type(&new_types);
    new_type.set_name(format!("perf_event_struct_{}", event_id));
    new_type
}

fn gen_builtin_print(ctx: &mut Context, ctx_node: &Node, args: &Vec<(Node, NodeId)>) -> Node {
    let mut first = false;
    let mut fmt = None;

    let event_id = ctx.event_id();

    let mut perf_type = gen_perf_event_struct_type(
        event_id,
        &args[if ctx.python { 0 } else { 1 }..]
            .iter()
            .map(|x| ctx.tb.type_(&x.1))
            .collect::<Vec<_>>(),
    );
    let mut perf_frame = alloc_frame(&perf_type, "perf_data");
    let mut idx = 1;

    gen_store(
        &perf_frame,
        perf_type.member_by_idx(idx).offset(),
        &Node::new_const(&Tarval::new_long(event_id as i64, &Mode::ModeLu())),
        perf_type.member_by_idx(0),
    );
    for (node, _) in args {
        if !first {
            first = true;
            if is_python() {
                fmt = Some("ForPython".to_owned());
            } else {
                fmt = Some(node.address_entity().initializer().construct_string());
                continue;
            }
        }

        gen_store(
            &perf_frame,
            perf_type.member_by_idx(idx).offset(),
            node,
            perf_type.member_by_idx(idx),
        );

        idx += 1;
    }

    let mut map = Node::new_const(&Tarval::new_long(ctx.perf_mapfd(), &Mode::ModeP()));
    map.set_const_mapfd();

    gen_helper_perf_event_output(ctx_node, &map, &perf_frame, perf_type.size() as u32);

    ctx.add_event(Event::new(fmt, perf_type));
    perf_frame
}

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
fn gen_builtin_iphdr(skb: &Node, typ: &Type) -> Node {
    let skb_type = typ.ptr_to();
    let head_node = gen_member_by_name(skb, &skb_type, "head");
    let transport_header_node = gen_member_by_name(skb, &skb_type, "network_header");

    let addr = Node::new_add(head_node, transport_header_node);

    let mut iphdr_type = Type::from_struct_name("iphdr");
    iphdr_type.set_kmem();

    gen_deref(addr, &iphdr_type)
}
