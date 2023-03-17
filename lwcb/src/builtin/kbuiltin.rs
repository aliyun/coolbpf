use crate::types::Type;
use anyhow::{bail, Result};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KBuiltin {
    Print,
    Kstack,
    Iphdr,
    Tcphdr,
    Bswap,
    Ns,
    Pid,
    Reg,
}

impl KBuiltin {
    pub fn return_type(&self, args: &Vec<&Type>) -> Type {
        match self {
            Self::Print => Type::void(),
            Self::Kstack => Type::i64(),
            Self::Iphdr => Type::from_struct_name("iphdr").to_ptr(),
            Self::Tcphdr => Type::from_struct_name("tcphdr").to_ptr(),
            Self::Bswap => args[0].clone(),
            Self::Ns => Type::u64(),
            Self::Pid => Type::i32(),
            Self::Reg => Type::u64(),
        }
    }
}

impl TryFrom<&str> for KBuiltin {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "print" => Ok(KBuiltin::Print),
            "iphdr" => Ok(KBuiltin::Iphdr),
            "tcphdr" => Ok(KBuiltin::Tcphdr),
            "bswap" => Ok(KBuiltin::Bswap),
            "kstack" => Ok(KBuiltin::Kstack),
            "ns" => Ok(KBuiltin::Ns),
            "pid" => Ok(KBuiltin::Pid),
            "reg" => Ok(KBuiltin::Reg),
            _ => bail!("{}: Unknown kernel space builtin function", value),
        }
    }
}
