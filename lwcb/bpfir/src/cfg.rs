use std::collections::{HashMap, HashSet};

use crate::bblock::BBlockData;
use crate::func::FuncData;
use crate::value::{ValueData, ValueKind};
use crate::{BBlock, Func, Type, TypeKind, Value};
use generational_arena::Arena;

pub struct CFG {
    pub blocks: Arena<BBlockData>,
    pub values: Arena<ValueData>,

    defs: HashMap<String, HashMap<BBlock, Value>>,
}

impl CFG {
    pub fn new() -> Self {
        CFG {
            blocks: Default::default(),
            values: Default::default(),
            defs: Default::default(),
        }
    }

    pub fn new_bblock(&mut self, name: &str) -> BBlock {
        BBlock(self.blocks.insert(BBlockData::new(name)))
    }

    pub fn new_value(&mut self, block: BBlock, vd: ValueData) -> Value {
        let uses = vd.kind.uses();
        let val = Value(self.values.insert(vd));
        let _ = uses.iter().map(|u| self.mut_value_data(*u).add_user(val));
        let bd = self.mut_bblock_data(block);
        bd.push_inst(val);
        val
    }

    pub fn new_block_param(&mut self, block: BBlock, name: &str) -> Value {
        let vd = ValueData::new(name, ValueKind::Param, Type::undef(), block);
        self.new_value(block, vd)
    }

    pub fn new_block_arg(&mut self, block: BBlock, name: &str) -> Value {
        let vd = ValueData::new(name, ValueKind::Argument, Type::undef(), block);
        self.new_value(block, vd)
    }

    pub fn read_variable(&mut self, block: BBlock, name: &str) -> Value {
        if let Some(val) = self.mut_bblock_data(block).defs.get(name) {
            return *val;
        }
        let val = self.new_block_param(block, name);
        self.write_variable(block, name, val);
        val
    }

    pub fn write_variable(&mut self, block: BBlock, name: &str, val: Value) {
        self.mut_bblock_data(block)
            .defs
            .insert(name.to_owned(), val);
    }

    pub fn value_data(&self, val: Value) -> &ValueData {
        &self.values[val.0]
    }

    pub fn mut_value_data(&mut self, val: Value) -> &mut ValueData {
        &mut self.values[val.0]
    }

    #[inline]
    fn remove_value_data(&mut self, val: Value) -> Option<ValueData> {
        self.values.remove(val.0)
    }

    #[inline]
    pub fn bblock_data(&self, block: BBlock) -> &BBlockData {
        &self.blocks[block.0]
    }

    #[inline]
    pub fn mut_bblock_data(&mut self, block: BBlock) -> &mut BBlockData {
        &mut self.blocks[block.0]
    }

    pub fn replace_block_argument(&mut self, block: BBlock, old: Value, new: Value) {
        // replace all users's operand
        let vd = self.remove_value_data(old).expect("BUG: value not found");
        for user in &vd.used_by {
            self.value_data(*user).kind.replace_use(old, new);
        }
        // remove old from block args list
        let bd = self.mut_bblock_data(block);
        bd.args.remove(&old);
        bd.args.insert(new);
    }

    /// seal this cfg
    pub fn finalize(&mut self, entry: BBlock) {
        eliminate_bblock_arguments(self, entry);
    }
}

fn eliminate_bblock_arguments(cfg: &mut CFG, block: BBlock) {
    let args = cfg.bblock_data(block).args.clone();
    for arg in args {
        let name = cfg.value_data(arg).name.clone();
        if let Some(val) = eliminate_read_variable(cfg, block, &name) {
            // replace block argument
            cfg.replace_block_argument(block, arg, val);
        }
    }

    let succs = cfg.bblock_data(block).succs.clone();
    for succ in succs {
        eliminate_bblock_arguments(cfg, succ);
    }
    // todo: handle forloop
}

fn eliminate_read_variable(cfg: &mut CFG, block: BBlock, name: &str) -> Option<Value> {
    let mut val = None;
    let preds = cfg.blocks[block.0].preds.clone();
    for pred in preds {
        let tmp = eliminate_read_variable_recursive(cfg, pred, name);
        if let Some(v) = val {
            if v != tmp {
                return None;
            }
        } else {
            val = Some(tmp);
        }
    }
    return val;
}

fn eliminate_read_variable_recursive(cfg: &mut CFG, block: BBlock, name: &str) -> Value {
    cfg.defs.get(name).map(|x| {
        x.get(&block).map(|v| {
            return *v;
        });
    });

    let mut val = None;
    let preds = cfg.blocks[block.0].preds.clone();
    for pred in preds {
        let tmp = eliminate_read_variable_recursive(cfg, pred, name);
        if let Some(v) = val {
            if v != tmp {
                val = Some(cfg.new_block_param(block, name));
                break;
            }
        } else {
            val = Some(tmp);
        }
    }

    assert!(val.is_some(), "BUG: undef variable: {}", name);
    cfg.defs.get_mut(name).unwrap().insert(block, val.unwrap());
    val.unwrap()
}
