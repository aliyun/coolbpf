use std::collections::{HashMap, HashSet};

use crate::{cfg::CFG, BBlock, Type, Value, ValueData, ValueKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Func(pub generational_arena::Index);

pub struct FuncData {
    name: String,

    pub(crate) entry: BBlock,
    pub(crate) exit: BBlock,
    phi_counter: HashMap<String, usize>,

    pub cfg: CFG,
    pub curr_block: BBlock,

    exit_inst: Value,
}

impl FuncData {
    pub fn new(name: &str) -> Self {
        let mut cfg = CFG::new();
        let entry = cfg.new_bblock("entry");
        let exit = cfg.new_bblock("exit");
        let vd = ValueData::new("_exit", ValueKind::Exit, Type::undef(), exit);
        let exit_inst = cfg.new_value(exit, vd);
        FuncData {
            name: name.to_owned(),
            entry,
            exit,
            phi_counter: Default::default(),
            cfg: cfg,
            curr_block: entry,
            exit_inst,
        }
    }

    pub fn set_curr_block(&mut self, block: BBlock) {
        self.curr_block = block;
    }
}
