use crate::be::clif::do_clif;
use crate::be::compile_function;
use crate::types::BinaryOp;
use crate::types::Relation;
use crate::BPFObject;
use crate::Type;
use cranelift_codegen::Context;
use generational_arena::Arena;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Variable(pub generational_arena::Index);

impl Display for Variable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "var{}", self.0.into_raw_parts().0)
    }
}

pub struct VariableData {
    pub(crate) ty: Type,
    name: Option<String>,
}

impl VariableData {
    pub fn new(ty: Type, name: Option<String>) -> Self {
        assert!(ty != Type::undef());
        VariableData { ty, name }
    }

    pub fn is_named(&self) -> bool {
        self.name.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Block(pub generational_arena::Index);

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BBlock{}", self.0.into_raw_parts().0)
    }
}

pub struct BlockData {
    pub(crate) insts: Vec<Instruction>,
    pub(crate) preds: Vec<Block>,
    pub(crate) succs: Vec<Block>,
}

impl BlockData {
    pub fn new() -> Self {
        BlockData {
            insts: Default::default(),
            preds: Default::default(),
            succs: Default::default(),
        }
    }

    pub fn add_instruction(&mut self, inst: Instruction) {
        self.insts.push(inst);
    }

    pub fn instructions(&self) {}
}

#[derive(Debug, Clone)]
pub enum Instruction {
    Assign(Variable, Variable), // lhs, rhs
    AssignImm(Variable, i64),
    Cmp(Relation, Variable, Variable, Variable),
    Branch(Variable, Block, Block),
    Member(Variable, Variable, String),
    Load(Variable, Variable),

    Binary(BinaryOp, Variable, Variable, Variable),
    BinaryImm(BinaryOp, Variable, Variable, i64),
}

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Instruction::Assign(v1, v2) => write!(f, "{v1} = {v2}"),
            Instruction::AssignImm(v, imm) => write!(f, "{v} = {imm}"),
            Instruction::Cmp(r, v1, v2, v3) => write!(f, "{v1} =  {v2} {r} {v3}"),
            Instruction::Branch(v, b1, b2) => write!(f, "if {v} goto {b1} else goto {b2}"),
            Instruction::Member(v1, v2, name) => write!(f, "{v1} = {v2}.{name}"),
            Instruction::Load(v1, v2) => write!(f, "{v1} = *{v2}"),
            Instruction::Binary(op, v1, v2, v3) => write!(f, "{v1} = {v2} {op} {v3}"),
            Instruction::BinaryImm(op, v1, v2, imm) => write!(f, "{v1} = {v2} {op} {imm}"),
        }
    }
}

impl Instruction {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Function(pub generational_arena::Index);

pub struct FunctionData {
    pub(crate) blocks: Arena<BlockData>,
    variables: Arena<VariableData>,

    named_variables: HashMap<String, Variable>,
    pub(crate) ty: Type,

    pub(crate) params: Vec<Variable>,
    pub(crate) entry: Block,
    pub(crate) exit: Block,
    current_block: Block,
}

impl FunctionData {
    pub fn new(ty: Type) -> Self {
        let mut blocks = Arena::default();

        let entry = Block(blocks.insert(BlockData::new()));
        let exit = Block(blocks.insert(BlockData::new()));

        FunctionData {
            blocks,
            variables: Default::default(),
            named_variables: Default::default(),
            ty,
            params: vec![],
            entry,
            exit,
            current_block: entry,
        }
    }

    pub fn set_current_block(&mut self, block: Block) {
        self.current_block = block;
    }

    pub fn current_block(&mut self) -> Block {
        self.current_block
    }

    pub fn mut_block_data(&mut self, block: Block) -> &mut BlockData {
        &mut self.blocks[block.0]
    }

    pub fn block_data(&self, block: Block) -> &BlockData {
        &self.blocks[block.0]
    }

    pub fn add_param(&mut self, param: Variable) {
        self.params.push(param);
    }

    pub fn new_variable(&mut self, vd: VariableData) -> Variable {
        let name = vd.name.clone();
        let var = Variable(self.variables.insert(vd));
        if let Some(x) = name {
            self.named_variables.insert(x, var);
        }
        var
    }

    pub fn variable_data(&self, var: Variable) -> &VariableData {
        &self.variables[var.0]
    }

    pub fn new_block(&mut self, bd: BlockData) -> Block {
        Block(self.blocks.insert(bd))
    }

    pub fn read_variable(&mut self, name: &str) -> Variable {
        *self
            .named_variables
            .get(name)
            .expect(&format!("failed to find named variable: {}", name))
    }

    pub(crate) fn lower_member_instruction(&mut self) {
        for (_, bd) in self.blocks.iter_mut() {
            for inst in &mut bd.insts {
                if let Instruction::Member(v1, v2, name) = (*inst).clone() {
                    // let ty = self.variables[v2.0].ty.clone();
                    *inst = Instruction::BinaryImm(BinaryOp::Add, v1, v2, 0x11);
                }
            }
        }
    }
}

pub struct Module {
    funcs: Arena<FunctionData>,
}

impl Module {
    pub fn new() -> Self {
        Module {
            funcs: Default::default(),
        }
    }

    pub fn new_function(&mut self, fd: FunctionData) -> Function {
        Function(self.funcs.insert(fd))
    }

    pub fn mut_function_data(&mut self, func: Function) -> &mut FunctionData {
        &mut self.funcs[func.0]
    }

    pub fn compile(&mut self) -> BPFObject {
        for (_, fd) in &mut self.funcs {
            fd.lower_member_instruction();
        }

        let mut object = BPFObject::new();
        for (_, fd) in self.funcs.iter() {
            compile_function(&mut object, fd);
        }
        object
    }
}
