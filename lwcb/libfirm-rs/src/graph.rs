use std::{ffi::CString, fs::File, io::Read, path::PathBuf};

use libfirm_sys::{set_store, *};

use crate::{Entity, Mode, Node, Type};

pub struct Graph(*mut ir_graph);

impl From<*mut ir_graph> for Graph {
    fn from(ptr: *mut ir_graph) -> Self {
        Graph(ptr)
    }
}

impl Graph {
    pub fn null() -> Self {
        let ptr = std::ptr::null_mut() as *mut ir_graph;
        ptr.into()
    }

    pub fn new(entity: &Entity, n_loc: usize) -> Self {
        unsafe { new_ir_graph(entity.raw(), n_loc as i32).into() }
    }

    pub fn set_current_block(&mut self, block: &Node) {
        unsafe { set_cur_block(block.raw()) }
    }

    pub fn get_current_block(&self) -> Option<Node> {
        let ptr = unsafe { get_cur_block() };
        if ptr.is_null() {
            return None;
        }
        return Some(ptr.into());
    }

    pub fn reset_block(&mut self) {
        unsafe {
            set_cur_block(std::ptr::null_mut());
        }
    }

    pub fn is_reachable(&self) -> bool {
        if let Some(block) = self.get_current_block() {
            return !block.is_bad();
        }
        false
    }

    pub fn set_unreachable(&mut self) {
        unsafe {
            set_cur_block(std::ptr::null_mut());
        }
    }

    pub fn raw(&self) -> *mut ir_graph {
        self.0
    }

    pub fn end_block(&self) -> Node {
        unsafe { get_irg_end_block(self.0).into() }
    }

    /// Returns the node that represents the argument pointer of the given IR graph.
    pub fn args(&self) -> Node {
        unsafe { get_irg_args(self.raw()).into() }
    }

    pub fn frame(&self) -> Node {
        unsafe { get_irg_frame(self.raw()).into() }
    }

    pub fn frame_type(&self) -> Type {
        unsafe { get_irg_frame_type(self.raw()).into() }
    }

    /// dump ir graph
    pub fn dump(&self, path: &PathBuf) {
        let c_path = CString::new(path.display().to_string()).unwrap();
        let c_mode = CString::new("w".to_owned()).unwrap();
        unsafe {
            let file = libc::fopen(c_path.as_ptr(), c_mode.as_ptr());
            if file.is_null() {
                panic!("Faied to open file: {:?}", c_path);
            }
            dump_ir_graph_file(file as *mut _IO_FILE, self.raw());
            libc::fclose(file);
        }
    }

    pub fn store(&self) -> Node {
        unsafe { get_store().into() }
    }

    pub fn set_store(&self, store: &Node) {
        unsafe { set_store(store.raw()) }
    }

    pub fn finalize_cons(&mut self) {
        unsafe {
            irg_finalize_cons(self.raw());
        }
    }

    // replace highlevel node with lower node. For example, delete
    // Member node to choose add node.
    pub fn opt_lower_highlevel(&mut self) {
        unsafe { lower_highlevel_graph(self.raw()) }
    }

    pub fn opt_conv(&mut self) {
        unsafe { conv_opt(self.raw()) }
    }

    pub fn walk_type<F>(&self, mut walker: F)
    where
        F: FnMut(&Type, &Entity),
    {
        // https://stackoverflow.com/questions/32270030/how-do-i-convert-a-rust-closure-to-a-c-style-callback
        let mut cb: &mut dyn FnMut(&Type, &Entity) = &mut walker;
        let cb = &mut cb;
        unsafe {
            type_walk_irg(
                self.raw(),
                Some(closure_handler_type),
                None,
                cb as *mut &mut _ as *mut std::ffi::c_void,
            )
        }
    }

    pub fn get_bytecode(&self) -> *const u64 {
        unsafe { be_get_bytecode(self.raw()) as *const u64 }
    }

    pub fn bytecode_size(&self) -> i32 {
        unsafe { be_bytecode_size(self.raw()) }
    }

    pub fn bytecodes(&self) -> Vec<u64> {
        let ptr = self.get_bytecode();
        let size = self.bytecode_size();
        let mut insns = vec![];
        for i in 0..size {
            unsafe { insns.push(*ptr.add(i as usize)) };
        }
        insns
    }

    pub fn entity(&self) -> Entity {
        unsafe { unsafe { get_irg_entity(self.raw()).into() } }
    }
}

pub fn set_current_graph(g: &Graph) {
    unsafe { set_current_ir_graph(g.raw()) }
}

pub fn current_graph() -> Graph {
    unsafe { get_current_ir_graph().into() }
}

pub fn set_rvalue(pos: i32, value: &Node) {
    unsafe { set_value(pos, value.raw()) }
}

pub fn get_rvalue(pos: i32, mode: &Mode) -> Node {
    unsafe { get_value(pos, mode.raw()).into() }
}

pub fn get_current_block() -> Option<Node> {
    let ptr = unsafe { get_cur_block() };
    if ptr.is_null() {
        return None;
    }
    return Some(ptr.into());
}

unsafe extern "C" fn closure_handler_type(
    ty: *mut ir_type,
    entity: *mut ir_entity,
    closure: *mut std::ffi::c_void,
) {
    if ty.is_null() {
        return;
    }
    let closure: &mut &mut dyn FnMut(&Type, &Entity) = std::mem::transmute(closure);
    closure(&Type::new(ty), &Entity::new(entity));
}
