use crate::types::Type;
use super::{KBuiltin, UBuiltin};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Builtin {
    Kernel(KBuiltin),
    User(UBuiltin),
}

impl Builtin {
    pub fn is_kernel(&self) -> bool {
        if let Builtin::Kernel(_) = self {
            return true;
        }
        false
    }

    pub fn is_user(&self) -> bool {
        !self.is_kernel()
    }

    pub fn return_type(&self, args: &Vec<&Type>) -> Type {
        match self {
            Self::Kernel(k) => k.return_type(args),
            Self::User(u) => u.return_type(args),
        }
    }
}

impl TryFrom<&str> for Builtin {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match KBuiltin::try_from(value) {
            Ok(o) => Ok(Builtin::Kernel(o)),
            Err(_) => Ok(Builtin::User(UBuiltin::try_from(value)?)),
        }
    }
}
