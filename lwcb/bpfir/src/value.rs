use std::collections::HashSet;

use crate::types::Type;
use crate::{bblock::BBlock, types::BinaryOp};
use anyhow::{bail, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Value(pub generational_arena::Index);

pub enum ValueKind {
    Undef,
    Constant(i64),
    Branch(Value, BBlock, BBlock), // condition, then, else
    Load(Value),
    Store(Value, Value),            // dst, src
    // if lhs or rhs is constant, we alawys set constant to be rhs
    Binary(BinaryOp, Value, Value), // op, lhs, rhs
    Member(Value, String),          // structure of member, member
    Param,
    Assign(Value),
    Exit,
    Jump(BBlock),
}

impl ValueKind {
    pub fn uses(&self) -> Vec<Value> {
        match self {
            Self::Branch(v, _, _) | Self::Load(v) | Self::Member(v, _) | Self::Store(_, v) => vec![*v],
            _ => vec![],
        }
    }
}

pub struct ValueData {
    pub name: String,
    pub kind: ValueKind,
    pub ty: Type,
    // state
    pub used_by: HashSet<Value>,
    pub(crate) block: BBlock,
    next: Option<Value>,
    prev: Option<Value>,
}
impl ValueData {
    pub fn new(name: &str, kind: ValueKind, ty: Type, block: BBlock) -> Self {
        ValueData {
            name: name.to_owned(),
            kind,
            ty,
            used_by: Default::default(),
            block,
            next: None,
            prev: None,
        }
    }

    pub fn add_user(&mut self, val: Value) {
        self.used_by.insert(val);
    }

    pub fn set_next(&mut self, next: Value) {
        self.next = Some(next)
    }
    pub fn set_prev(&mut self, prev: Value) {
        self.prev = Some(prev)
    }
}
