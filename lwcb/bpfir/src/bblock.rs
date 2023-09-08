use crate::value::Value;
use std::collections::{HashSet, HashMap};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BBlock(pub generational_arena::Index);

// basic block
pub struct BBlockData {
    insts: Vec<Value>,
    pub preds: Vec<BBlock>,
    pub succs: Vec<BBlock>,

    name: String,

    sealed_blocks: HashSet<BBlock>,
    // block parameters
    params: HashSet<Value>,

    pub defs: HashMap<String, Value>,
    used_by: HashSet<Value>,

    pub args: HashSet<Value>,
}

impl BBlockData {
    pub fn new(name: &str) -> Self {
        BBlockData {
            insts: vec![],
            preds: vec![],
            succs: vec![],
            name: name.to_string(),
            sealed_blocks: HashSet::default(),
            params: Default::default(),
            defs: Default::default(),
            used_by: Default::default(),
            args: Default::default(),
        }
    }

    pub fn push_inst(&mut self, inst: Value) {
        self.insts.push(inst);
    }

}
