use std::collections::{HashMap, HashSet};

use crate::bblock::BBlockData;
use crate::func::FuncData;
use crate::value::{ValueData, ValueKind};
use crate::{BBlock, Func, Type, TypeKind, Value};
use generational_arena::Arena;

pub struct CFG {
    pub blocks: Arena<BBlockData>,
    pub values: Arena<ValueData>,
}

impl CFG {
    pub fn new() -> Self {
        CFG {
            blocks: Default::default(),
            values: Default::default(),
        }
    }

    pub fn new_bblock(&mut self, name: &str) -> BBlock {
        BBlock(self.blocks.insert(BBlockData::new(name)))
    }

    pub fn new_value(&mut self, block: BBlock, vd: ValueData) -> Value {
        let uses = vd.kind.uses();
        let val = Value(self.values.insert(vd));
        let _  = uses.iter().map(|u|  self.mut_value_data(*u).add_user(val));
        let bd = self.mut_bblock_data(block);
        bd.push_inst(val);
        val
    }

    pub fn new_block_param(&mut self, block: BBlock, name: &str) -> Value {
        let vd = ValueData::new(name, ValueKind::Param, Type::undef(), block);
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

    pub fn bblock_data(&self, block: BBlock) -> &BBlockData {
        &self.blocks[block.0]
    }

    pub fn mut_bblock_data(&mut self, block: BBlock) -> &mut BBlockData {
        &mut self.blocks[block.0]
    }

    /// handle block arguments 
    pub fn finalize(&mut self, entry: BBlock) {
        let mut finalized_blocks: HashSet<BBlock> = HashSet::default();



    }
}
