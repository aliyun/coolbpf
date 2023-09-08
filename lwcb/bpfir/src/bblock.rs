use crate::value::Value;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BBlock(pub generational_arena::Index);

// basic block
pub struct BBlockData {
    insts: Vec<Value>,
    pub preds: Vec<BBlock>,
    pub succs: Vec<BBlock>,

    name: String,

    // block parameters
    params: HashSet<Value>,

    pub defs: HashMap<String, Value>,
    used_by: HashSet<Value>,

    pub args: HashSet<Value>,
    pub first: Option<Value>,
    pub last: Option<Value>,

    insts_order: HashMap<Value, InstNode>,
}

impl BBlockData {
    pub fn new(name: &str) -> Self {
        BBlockData {
            insts: vec![],
            preds: vec![],
            succs: vec![],
            name: name.to_string(),
            params: Default::default(),
            defs: Default::default(),
            used_by: Default::default(),
            args: Default::default(),
            first: None,
            last: None,
            insts_order: Default::default(),
        }
    }

    pub fn push_inst(&mut self, inst: Value) {
        if self.first.is_none() {
            self.first = Some(inst);
            self.last = Some(inst);
            self.insts_order.insert(inst, Default::default());
        } else {
            let prev_last = self.last.unwrap();
            self.last = Some(inst);
            self.insts_order.entry(prev_last).and_modify(|x| {
                x.next = Some(inst);
            });
            self.insts_order
                .entry(inst)
                .or_insert(InstNode::default())
                .prev = Some(prev_last);
            self.insts.push(inst);
        }
    }

    pub fn next_inst(&self, inst: Value) -> Option<Value> {
        self.insts_order[&inst].next
    }

    pub fn prev_inst(&self, inst: Value) -> Option<Value> {
        self.insts_order[&inst].prev
    }
}

#[derive(Clone, Debug, Default)]
struct InstNode {
    /// The Block containing this instruction, or `None` if the instruction is not yet inserted.
    prev: Option<Value>,
    next: Option<Value>,
}

#[cfg(test)]
mod tests {
    use generational_arena::Index;

    use super::*;
    #[test]
    fn push_inst() {
        let mut bd = BBlockData::new("test");
        let inst1 = Value(Index::from_raw_parts(0, 0));
        let inst2 = Value(Index::from_raw_parts(1, 1));
        let inst3 = Value(Index::from_raw_parts(2, 2));
        bd.push_inst(inst1);
        bd.push_inst(inst2);
        bd.push_inst(inst3);

        assert!(bd.first.unwrap() == inst1);
        assert!(bd.last.unwrap() == inst3);

        // test next
        assert!(bd.next_inst(inst1).unwrap() == inst2);
        assert!(bd.next_inst(inst2).unwrap() == inst3);
        assert!(bd.next_inst(inst3).is_none());

        // test prev
        assert!(bd.prev_inst(inst1).is_none());
        assert!(bd.prev_inst(inst2).unwrap() == inst1);
        assert!(bd.prev_inst(inst3).unwrap() == inst2);
    }
}
