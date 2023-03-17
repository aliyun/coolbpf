use crate::types::Type;
use anyhow::{bail, Result};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UBuiltin {
    Ntop,
    TcpState,
    TcpFlags,
    Time,
    Ksym,
}

impl UBuiltin {
    pub fn return_type(&self, args: &Vec<&Type>) -> Type {
        let mut typ = args[0].clone();
        typ.set_ubuiltin(self.clone());
        typ
    }
}

impl TryFrom<&str> for UBuiltin {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self> {
        match value {
            "ntop" => Ok(UBuiltin::Ntop),
            "tcpstate" => Ok(UBuiltin::TcpState),
            "tcpflags" => Ok(UBuiltin::TcpFlags),
            "time" => Ok(UBuiltin::Time),
            "Ksym" => Ok(UBuiltin::Ksym),
            _ => bail!("{}: Unknown user space builtin function", value),
        }
    }
}
