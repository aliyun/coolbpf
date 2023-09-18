use bpfir::Type;
use bpfir::TypeKind;
use byteorder::ByteOrder;

fn roundup(num: usize, r: usize) -> usize {
    ((num + (r - 1)) / r) * r
}

fn align8(offset: usize, elem_size: usize, elem_num: usize) -> usize {
    debug_assert!(
        elem_size == 1 || elem_size == 2 || elem_size == 4 || elem_size == 8,
        "elem_size: {elem_size}"
    );
    roundup(offset, elem_size) + elem_size * elem_num
}

#[derive(Debug)]
pub struct PrintType {
    ty: Type,
    off: u16, // offset in raw data
}

impl PrintType {
    pub fn bytes2string(&self, data: &[u8]) -> String {
        let off = self.off as usize;

        let data_off = &data[off..];
        match &self.ty.kind {
            TypeKind::Bool => {
                if data[off] == 0 {
                    "false".to_owned()
                } else {
                    "true".to_owned()
                }
            }
            TypeKind::Char => char::from_u32(data[off] as u32).unwrap().to_string(),
            TypeKind::I8 => (data[off] as i8).to_string(),
            TypeKind::U8 => data[off].to_string(),
            TypeKind::I16 => byteorder::NativeEndian::read_i16(data_off).to_string(),
            TypeKind::U16 => byteorder::NativeEndian::read_u16(data_off).to_string(),
            TypeKind::I32 => byteorder::NativeEndian::read_i32(data_off).to_string(),
            TypeKind::U32 => byteorder::NativeEndian::read_u32(data_off).to_string(),
            TypeKind::I64 => byteorder::NativeEndian::read_i64(data_off).to_string(),
            TypeKind::U64 => byteorder::NativeEndian::read_u64(data_off).to_string(),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Print {
    types: Vec<PrintType>,
    pub(crate) sz: usize,
}

impl Print {
    pub fn new() -> Self {
        Print::default()
    }

    pub fn add_type(&mut self, ty: &Type) -> i32 {
        let offset = align8(self.sz, ty.size() as usize, 1);
        let start_offset = offset as i32 - ty.size();
        let pty = PrintType {
            ty: ty.clone(),
            off: start_offset as u16,
        };
        self.types.push(pty);
        self.sz = offset;
        start_offset
    }

    pub fn bytes2string(&self, data: &[u8]) -> String {
        self.bytes2string_with_offset(data, 0)
    }

    // offset indicates which type to start conversion from.
    pub fn bytes2string_with_offset(&self, data: &[u8], off: usize) -> String {
        let mut res = String::new();
        for ty in &self.types[off..] {
            res.push_str(&ty.bytes2string(data));
            res += " ";
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align8() {
        assert!(align8(1, 8, 1) == 16);
    }

    #[test]
    fn print_bytes2string() {
        let mut print = Print::new();
        let mut bytes: Vec<u8> = vec![];
        print.add_type(&Type::bool());
        print.add_type(&Type::bool());
        bytes.push(0);
        bytes.push(1);
        print.add_type(&Type::char());
        bytes.push('d' as u8);
        print.add_type(&Type::i8());
        bytes.push((-2) as i8 as u8);
        print.add_type(&Type::u8());
        bytes.push(3);
        bytes.push(0);
        print.add_type(&Type::i16());
        bytes.extend((-4 as i16).to_ne_bytes());
        print.add_type(&Type::u16());
        bytes.extend((5 as i16).to_ne_bytes());
        bytes.push(0);
        bytes.push(0);
        print.add_type(&Type::i32());
        bytes.extend((-6 as i32).to_ne_bytes());
        print.add_type(&Type::u32());
        bytes.extend((7 as i32).to_ne_bytes());
        bytes.push(0);
        bytes.push(0);
        bytes.push(0);
        bytes.push(0);
        print.add_type(&Type::i64());
        bytes.extend((-8 as i64).to_ne_bytes());
        print.add_type(&Type::u64());
        bytes.extend((9 as i64).to_ne_bytes());

        let res = print.bytes2string(&bytes);

        assert_eq!(res, "false true d -2 3 -4 5 -6 7 -8 9 ");
    }
}
