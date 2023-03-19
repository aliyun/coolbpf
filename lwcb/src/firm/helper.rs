use super::{
    frame::alloc_anon_frame,
    global::{
        ENTITY_KTIME_GET_NS, ENTITY_PERF_OUT, ENTITY_PROBE_READ, NODE_GET_STACKID,
        TYPE_GET_STACKID, TYPE_KTIME_GET_NS, TYPE_PERF_OUT, TYPE_PROBE_READ,
    },
};
use crate::types::Type;
use libfirm_rs::{current_graph, node_adress_mode_cast, Mode, Node, Tarval, Type as IrType};

fn gen_helper(callee: &Node, mut args: Vec<Node>, method: &IrType) -> Option<Node> {
    args = node_adress_mode_cast(callee, args);

    let mut graph = current_graph();
    let call = Node::new_call(&graph.store(), callee, &args, method);
    let memory = Node::new_prog(&call, &Mode::ModeM(), libfirm_sys::pn_Call_pn_Call_M);
    graph.set_store(&memory);

    if method.method_n_res() >= 1 {
        let res = Node::new_prog(&call, &Mode::ModeT(), libfirm_sys::pn_Call_pn_Call_T_result);
        return Some(Node::new_prog(&res, &method.method_res().mode(), 0));
    }

    return None;
}

/// generate ir of helper function bpf_probe_read.
pub fn gen_helper_probe_read(dst: &Node, size: &Node, src: &Node) {
    let callee = Node::new_address(&ENTITY_PROBE_READ);
    gen_helper(&callee, vec![*dst, *size, *src], &TYPE_PROBE_READ);
}

/// generate ir of helper function bpf_probe_read and allocate frame to save result.
pub fn gen_helper_probe_read_with_frame(src: &Node, typ: &Type) -> Node {
    log::debug!("call bpf_probe_read, target type: {}", typ);
    let ty = typ.irtype();
    let mut dst = alloc_anon_frame(&ty);
    let size = Node::new_const(&Tarval::new_long(ty.size() as i64, &Mode::ModeIu()));
    gen_helper_probe_read(&dst, &size, &src);
    dst
}

/// generate ir of helper function bpf_ktime_get_ns.
pub fn gen_helper_ktime_get_ns() -> Node {
    let callee = Node::new_address(&ENTITY_KTIME_GET_NS);
    gen_helper(&callee, vec![], &TYPE_KTIME_GET_NS).unwrap()
}

/// generate ir of helper function bpf_perf_event_output.
pub fn gen_helper_perf_event_output(ctx: &Node, map: &Node, data: &Node, size: u32) {
    let flags = Node::new_const(&Tarval::new_long(0xffffffff, &Mode::ModeLu()));
    let size = Node::new_const(&Tarval::new_long(size as i64, &Mode::ModeLu()));

    let callee = Node::new_address(&ENTITY_PERF_OUT);
    gen_helper(
        &callee,
        vec![*ctx, *map, flags, *data, size],
        &TYPE_PERF_OUT,
    );
}

/// generate ir of helper function bpf_get_stackid.
pub fn gen_helper_get_stackid(ctx: &Node, map: &Node) -> Node {
    let flags = Node::new_const(&Tarval::new_long(0, &Mode::ModeLu()));
    gen_helper(
        &NODE_GET_STACKID,
        vec![*ctx, *map, flags],
        &TYPE_GET_STACKID,
    )
    .unwrap()
}
