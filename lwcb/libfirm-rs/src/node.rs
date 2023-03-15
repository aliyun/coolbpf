use libfirm_sys::*;

use crate::{Entity, Mode, Relation, Tarval, Type};
use std::{ffi::CStr, fmt};

#[derive(Debug)]
#[repr(C)]
pub enum UsAction {
    None,
    StackMap,
    StackMapDepth1,
    StackMapDepth2,
    StackMapDepth3,
    StackMapDepth4,
    StackMapDepth5,
    StackMapDepth6,
    StackMapDepth7,
    StackMapDepth8,
    StackMapDepth9,
    StackMapDepth10,
    StackMapDepth11,
    StackMapDepth12,
    StackMapDepth13,
    StackMapDepth14,
    StackMapDepth15,
    StackMapDepth16,
    StackMapDepth17,
    StackMapDepth18,
    StackMapDepth19,
    StackMapDepth20,
    Ntop,
    TcpState,
    TcpFlags,
    TimeStr,
    Ksym,
}

impl From<u32> for UsAction {
    fn from(val: u32) -> Self {
        match val {
            ir_node_us_action_us_action_none => Self::None,
            ir_node_us_action_us_action_stack_map => Self::StackMap,
            ir_node_us_action_us_action_stack_map_depth1 => Self::StackMapDepth1,
            ir_node_us_action_us_action_stack_map_depth2 => Self::StackMapDepth2,
            ir_node_us_action_us_action_stack_map_depth3 => Self::StackMapDepth3,
            ir_node_us_action_us_action_stack_map_depth4 => Self::StackMapDepth4,
            ir_node_us_action_us_action_stack_map_depth5 => Self::StackMapDepth5,
            ir_node_us_action_us_action_stack_map_depth6 => Self::StackMapDepth6,
            ir_node_us_action_us_action_stack_map_depth7 => Self::StackMapDepth7,
            ir_node_us_action_us_action_stack_map_depth8 => Self::StackMapDepth8,
            ir_node_us_action_us_action_stack_map_depth9 => Self::StackMapDepth9,
            ir_node_us_action_us_action_stack_map_depth10 => Self::StackMapDepth10,
            ir_node_us_action_us_action_stack_map_depth11 => Self::StackMapDepth11,
            ir_node_us_action_us_action_stack_map_depth12 => Self::StackMapDepth12,
            ir_node_us_action_us_action_stack_map_depth13 => Self::StackMapDepth13,
            ir_node_us_action_us_action_stack_map_depth14 => Self::StackMapDepth14,
            ir_node_us_action_us_action_stack_map_depth15 => Self::StackMapDepth15,
            ir_node_us_action_us_action_stack_map_depth16 => Self::StackMapDepth16,
            ir_node_us_action_us_action_stack_map_depth17 => Self::StackMapDepth17,
            ir_node_us_action_us_action_stack_map_depth18 => Self::StackMapDepth18,
            ir_node_us_action_us_action_stack_map_depth19 => Self::StackMapDepth19,
            ir_node_us_action_us_action_stack_map_depth20 => Self::StackMapDepth20,
            ir_node_us_action_us_action_ntop => Self::Ntop,
            ir_node_us_action_us_action_tcpstate => Self::TcpState,
            ir_node_us_action_us_action_tcpflags => Self::TcpFlags,
            ir_node_us_action_us_action_timestr => Self::TimeStr,
            ir_node_us_action_us_action_ksym => Self::Ksym,
            _ => todo!(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Node(*mut ir_node);

impl From<*mut ir_node> for Node {
    fn from(ptr: *mut ir_node) -> Self {
        Node(ptr)
    }
}

unsafe impl Sync for Node {}

impl Node {
    pub fn raw(&self) -> *mut ir_node {
        self.0
    }

    pub fn new_prog(pred: &Node, mode: &Mode, num: u32) -> Node {
        unsafe { new_Proj(pred.raw(), mode.raw(), num).into() }
    }

    pub fn new_member(prev: &Node, entity: &Entity) -> Node {
        let mut node: Node = unsafe { new_Member(prev.raw(), entity.raw()).into() };
        node.set_is_kernel_memory(prev.is_kernel_memory() as i32);
        node
    }

    pub fn new_const(val: &Tarval) -> Node {
        unsafe { new_Const(val.raw()).into() }
    }

    pub fn set_const_mapfd(&mut self) {
        unsafe { set_Const_mapfd(self.raw()) }
    }

    pub fn new_address(entity: &Entity) -> Node {
        unsafe { new_Address(entity.raw()).into() }
    }

    pub fn address_entity(&self) -> Entity {
        unsafe { get_Address_entity(self.raw()).into() }
    }

    pub fn member_entity(&self) -> Entity {
        unsafe { get_Member_entity(self.raw()).into() }
    }

    pub fn call_type(&self) -> Type {
        unsafe { get_Call_type(self.raw()).into() }
    }

    pub fn proj_pred(&self) -> Self {
        unsafe { get_Proj_pred(self.raw()).into() }
    }

    pub fn new_load(memory: &Node, addr: &Node, mode: &Mode, ty: &Type) -> Self {
        unsafe { new_Load(memory.raw(), addr.raw(), mode.raw(), ty.raw(), 0).into() }
    }

    pub fn new_store(memory: &Node, ptr: &Node, value: &Node, ty: &Type) -> Self {
        unsafe { new_Store(memory.raw(), ptr.raw(), value.raw(), ty.raw(), 0).into() }
    }

    pub fn is_proj(&self) -> bool {
        unsafe { is_Proj(self.raw()) != 0 }
    }

    pub fn is_load(&self) -> bool {
        unsafe { is_Load(self.raw()) != 0 }
    }

    pub fn is_member(&self) -> bool {
        unsafe { is_Member(self.raw()) != 0 }
    }

    pub fn is_address(&self) -> bool {
        unsafe { is_Address(self.raw()) != 0 }
    }

    pub fn is_call(&self) -> bool {
        unsafe { is_Call(self.raw()) != 0 }
    }

    pub fn load_type(&self) -> Type {
        unsafe { get_Load_type(self.raw()).into() }
    }

    pub fn new_call(memory: &Node, ptr: &Node, args: &Vec<&Node>, ty: &Type) -> Self {
        let mut raw_args = vec![];
        for arg in args {
            raw_args.push(arg.raw());
        }
        unsafe {
            new_Call(
                memory.raw(),
                ptr.raw(),
                raw_args.len() as i32,
                raw_args.as_ptr(),
                ty.raw(),
            )
            .into()
        }
    }

    pub fn new_return(memory: &Node) -> Self {
        unsafe { new_Return(memory.raw(), 0, std::ptr::null()).into() }
    }

    pub fn mode(&self) -> Mode {
        unsafe { get_irn_mode(self.raw()).into() }
    }
    // FIRM_API  ir_node *new_Cmp(ir_node * irn_left, ir_node * irn_right, ir_relation relation);
    pub fn new_cmp(left: &Node, right: &Node, relation: &Relation) -> Self {
        unsafe { new_Cmp(left.raw(), right.raw(), *relation as u32).into() }
    }

    pub fn new_cond(cmp: &Node) -> Self {
        unsafe { new_Cond(cmp.raw()).into() }
    }

    pub fn new_immblock() -> Self {
        unsafe { new_immBlock().into() }
    }

    pub fn new_add(left: &Node, right: &Node) -> Self {
        unsafe { new_Add(left.raw(), right.raw()).into() }
    }

    pub fn new_conv(value: &Node, dest_mode: &Mode) -> Self {
        unsafe { new_Conv(value.raw(), dest_mode.raw()).into() }
    }

    // Use dbg_info pointer to store the type pointer. Although this method is unreasonable,
    // it is the only feasible method at present.
    pub fn set_type(&mut self, ty: &Type) {
        unsafe { set_irn_dbg_info(self.raw(), ty.raw() as *mut dbg_info) }
    }

    pub fn try_type(&self) -> Option<Type> {
        unsafe {
            let ty = get_irn_dbg_info(self.raw());
            if ty.is_null() {
                return None;
            } else {
                Some((ty as *mut ir_type).into())
            }
        }
    }

    pub fn new_r_jmp(block: &Node) -> Node {
        unsafe { new_r_Jmp(block.raw()).into() }
    }

    pub fn is_bad(&self) -> bool {
        unsafe { is_Bad(self.raw()) != 0 }
    }

    pub fn typeid(&self) -> i32 {
        unsafe { get_irn_typeid(self.raw()) }
    }

    pub fn set_typeid(&self, typeid: i32) {
        unsafe { set_irn_typeid(self.raw(), typeid) }
    }

    pub fn is_kernel_memory(&self) -> bool {
        unsafe { get_irn_kernel_memory(self.raw()) != 0 }
    }

    pub fn set_is_kernel_memory(&mut self, kernel_memory: i32) {
        unsafe { set_irn_kernel_memory(self.raw(), kernel_memory) }
    }

    pub fn type_(&self) -> Type {
        unsafe { (get_irn_dbg_info(self.raw()) as *mut ir_type).into() }
    }

    pub fn tarval(&self) -> Tarval {
        unsafe { get_Const_tarval(self.raw()).into() }
    }

    pub fn ulong(&self) -> u64 {
        unsafe { get_tarval_long(self.tarval().raw()) as u64 }
    }

    pub fn set_us_action(&self, action: UsAction) {
        unsafe { set_irn_us_action(self.raw(), action as i32) }
    }

    pub fn us_action(&self) -> UsAction {
        let ua = unsafe { get_irn_us_action(self.raw()) };
        UsAction::from(ua as u32)
    }

    pub fn new_builtin_bswap(memory: &Node, arg: &Node) -> Self {
        let mut raw_args = vec![];
        raw_args.push(arg.raw());

        let method_ty = Type::new_method(&vec![arg.type_()], Some(&arg.type_()));
        let mut node: Node = unsafe {
            new_Builtin(
                memory.raw(),
                raw_args.len() as i32,
                raw_args.as_ptr(),
                ir_builtin_kind_ir_bk_bswap,
                method_ty.raw(),
            )
            .into()
        };

        node
    }

    pub fn builtin_type(&self) -> Type {
        unsafe { get_Builtin_type(self.raw()).into() }
    }

    pub fn new_sel(node: &Node, index: &Node, ty: &Type) -> Self {
        unsafe { new_Sel(node.raw(), index.raw(), ty.raw()).into() }
    }
}

pub fn get_node_type(node: &Node) -> Type {
    if let Some(ty) = node.try_type() {
        return ty;
    }

    if node.is_proj() {
        return get_node_type(&node.proj_pred());
    }

    if node.is_load() {
        return node.load_type();
    }

    if node.is_member() {
        let entity = node.member_entity();
        return entity.type_();
    }

    if node.is_address() {
        let entity = node.address_entity();
        return entity.type_();
    }

    if node.is_call() {
        return node.call_type().method_res();
    }

    todo!("{}", node)
}

pub fn immblock_add_pred(block: &Node, jmp: &Node) {
    unsafe { add_immBlock_pred(block.raw(), jmp.raw()) }
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opname = unsafe { get_irn_opname(self.raw()) };
        let cstr = unsafe { CStr::from_ptr(opname) };
        write!(f, "{}", cstr.to_str().unwrap())
    }
}
