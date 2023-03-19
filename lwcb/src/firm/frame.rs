use libfirm_rs::{current_graph, Entity, Ident, Node, Type as IrType};
use std::ffi::CString;

use crate::types::Type;

pub fn unique_ident(name: &str) -> Ident {
    let cname = CString::new(name).unwrap();
    let ident = Ident::unique(&cname);
    return ident;
}

pub fn ident(name: &str) -> Ident {
    let cname = CString::new(name).unwrap();
    // todo: do we need keeping cname alive?
    Ident::new(&cname)
}

fn __alloc_frame(ty: &IrType, ident: &Ident) -> Node {
    let mut graph = current_graph();
    let frame_type = graph.frame_type();
    let entity = Entity::new_entity(&frame_type, ident, ty);
    Node::new_member(&graph.frame(), &entity)
}

// allocate anonymous frame
pub fn alloc_anon_frame(ty: &IrType) -> Node {
    let id = unique_ident("tmp");
    __alloc_frame(ty, &id)
}

// allocate named frame
pub fn alloc_frame_with_irtype(ty: &IrType, name: &str) -> Node {
    let id = ident(name);
    __alloc_frame(ty, &id)
}

pub fn alloc_frame(typ: &Type, name: &str) -> Node {
    let mut ir_type = typ.irtype();
    ir_type.set_size(typ.size() as u32);
    ir_type.set_align(8);
    alloc_frame_with_irtype(&ir_type, name)
}