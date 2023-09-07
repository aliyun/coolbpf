use crate::bblock::BBlockData;
use crate::func::FuncData;
use crate::value::{ValueData, ValueKind};
use crate::{Func, Type, Value};
use generational_arena::Arena;

pub struct Module {
    name: String,
    pub(crate) funcs: Arena<FuncData>,
}

impl Module {
    pub fn new(name: &str) -> Self {
        Module {
            name: name.to_owned(),
            funcs: Default::default(),
        }
    }

    pub fn new_func_data(&mut self, fd: FuncData) -> Func {
        Func(self.funcs.insert(fd))
    }

    pub fn mut_func_data(&mut self, func: Func) -> &mut FuncData {
        &mut self.funcs[func.0]
    }

    pub fn codegen(&mut self) {}
}
