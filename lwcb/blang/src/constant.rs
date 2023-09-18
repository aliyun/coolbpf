use bpfir::types::Type;

#[derive(Clone, Debug, PartialEq)]
pub struct Constant {
    value: i64,
    ty: Type,
    radix: u32,
}

impl Constant {
    pub fn from_str_radix(value_str: &str, radix: u32) -> Self {
        let value = i64::from_str_radix(value_str, radix as u32).expect("not a number");

        let ty = match radix {
            2 => Type::u32(),
            8 => Type::u32(),
            10 => {
                if value > (i32::MAX as i64) {
                    Type::i64()
                } else {
                    Type::i32()
                }
            }
            16 => Type::u64(),
            _ => todo!(),
        };

        Constant { value, ty, radix }
    }

    pub fn ty(&self) -> &Type {
        &self.ty
    }

    pub fn value(&self) -> i64 {
        self.value
    }
}
