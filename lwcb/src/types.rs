use std::fmt;
use std::ops;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum Types {
    Void,
    Char,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    String,
    Pointer,
    Struct,
    Union,
}

impl fmt::Display for Types {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Types::Void => write!(f, "void"),
            _ => unimplemented!(),
        }
    }
}

impl From<&Constant> for Types {
    fn from(c: &Constant) -> Self {
        match c {
            Constant::Char(_) => Self::Char,
            Constant::I32(_) => Self::I32,
            _ => unimplemented!(),
        }
    }
}

/// A generic identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct Identifier {
    pub name: String,
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.name)
    }
}

impl From<&str> for Identifier {
    fn from(val: &str) -> Self {
        Identifier {
            name: val.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Constant {
    Bool(bool),
    Char(char),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
}

impl Into<i32> for Constant {
    fn into(self) -> i32 {
        match self {
            Constant::I32(x) => x,
            Constant::U32(x) => x as i32,
            Constant::I16(x) => x as i32,

            _ => unimplemented!(),
        }
    }
}

impl From<i32> for Constant {
    fn from(x: i32) -> Self {
        Constant::I32(x)
    }
}

impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constant::I32(x) => write!(f, "{}:i32", x),
            _ => unimplemented!(),
        }
    }
}

impl Constant {
    pub fn number(radix: usize, value_str: &str) -> Self {
        /*
         * todo: default type is i32, but we need to infer type in some cases.
         * For example, 0xffffffff should be u32
         */
        Constant::I32(value_str.parse().expect("Not a number"))
    }

    pub fn type_(&self) -> Types {
        match self {
            Constant::I16(_) => Types::I16,
            Constant::I32(_) => Types::I32,
            _ => unimplemented!(),
        }
    }

    pub fn type_size(&self) -> usize {
        match self {
            Constant::Char(_) | Constant::Bool(_) | Constant::I8(_) | Constant::U8(_) => 1,
            Constant::I16(_) | Constant::U16(_) => 2,
            Constant::I32(_) | Constant::U32(_) => 4,
            Constant::I64(_) | Constant::U64(_) => 8,
        }
    }

    pub fn type_signed(&self) -> bool {
        match self {
            Constant::I8(_) | Constant::I16(_) | Constant::I32(_) | Constant::I64(_) => true,
            Constant::U8(_) | Constant::U16(_) | Constant::U32(_) | Constant::U64(_) => false,
            _ => panic!("Char or Bool could not be determined if signed"),
        }
    }

    pub fn is_bool(&self) -> bool {
        if let Constant::Bool(_) = self {
            return true;
        }
        false
    }

    pub fn is_char(&self) -> bool {
        if let Constant::Char(_) = self {
            return true;
        }
        false
    }
}

fn add<T: ops::Add + ops::Add<Output = T>>(x: T, y: T) -> T {
    x + y
}

fn mul<T: ops::Mul + ops::Mul<Output = T>>(x: T, y: T) -> T {
    x * y
}

// lhs has higher priority
fn constant_op(op: char, lhs: Constant, rhs: Constant) -> Constant {
    match lhs {
        Constant::I32(x) => {
            let y: i32 = rhs.into();
            match op {
                '+' => add(x, y).into(),
                '*' => mul(x, y).into(),
                _ => unimplemented!(),
            }
        }
        _ => unimplemented!(),
    }
}

impl ops::Sub<&Constant> for &Constant {
    type Output = Constant;
    fn sub(self, rhs: &Constant) -> Self::Output {
        todo!()
    }
}

impl ops::Add<Constant> for Constant {
    type Output = Constant;
    fn add(self, rhs: Constant) -> Self::Output {
        if self.type_() > rhs.type_() {
            constant_op('+', self, rhs)
        } else {
            constant_op('+', rhs, self)
        }
    }
}

impl ops::Div<&Constant> for &Constant {
    type Output = Constant;
    fn div(self, rhs: &Constant) -> Self::Output {
        todo!()
    }
}

impl ops::Mul<Constant> for Constant {
    type Output = Constant;
    fn mul(self, rhs: Constant) -> Self::Output {
        if self.type_() > rhs.type_() {
            constant_op('*', self, rhs)
        } else {
            constant_op('*', rhs, self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Constant;

    #[test]
    fn test_constant_add() {
        let c1 = Constant::I32(1);
        let c2 = Constant::I32(2);
        assert_eq!(c1 + c2, Constant::I32(3));
        let c3 = Constant::I16(4);
        assert_eq!(c1 + c3, Constant::I32(5));
    }
}
