use crate::types::{Type, TypeKind};
use regex::Regex;
use std::{collections::VecDeque, path::PathBuf};

pub fn tracepoint_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/sys/kernel/debug/tracing/events/{}/{}",
        category, name
    ))
}

#[derive(Debug, Clone)]
pub struct TracepointField {
    ty: Option<Type>,
    name: String,
    offset: u16,
    size: u16,
    signed: bool,

    data_loc: bool,
}

impl TracepointField {
    pub fn new() -> Self {
        TracepointField {
            ty: None,
            name: String::default(),
            offset: 0,
            size: 0,
            signed: true,
            data_loc: false,
        }
    }
    fn parse_field(&mut self, field: &str) {
        let field = field.trim();
        // log::debug!("field: {}", field);
        let mut parts = field
            .split_whitespace()
            .map(|part| part.trim().to_string())
            .collect::<VecDeque<_>>();

        while !parts.is_empty() {
            let part = parts.pop_front();
            if let Some(part) = part {
                let part = part.as_str();
                match part {
                    "const" => {
                        continue;
                    }
                    "*const" => {
                        parts.push_front("*".into());
                    }
                    "unsigned" => {
                        self.signed = false;
                    }
                    "__data_loc" => {
                        self.data_loc = true;
                    }
                    "char" => {
                        self.ty = Some(if self.signed { Type::i8() } else { Type::u8() });
                    }
                    "short" => {
                        self.ty = Some(if self.signed {
                            Type::new(TypeKind::I16)
                        } else {
                            Type::new(TypeKind::U16)
                        });
                    }
                    "int" => {
                        self.ty = Some(if self.signed {
                            Type::new(TypeKind::I32)
                        } else {
                            Type::new(TypeKind::U32)
                        });
                    }
                    "long" => {
                        self.ty = Some(if self.signed {
                            Type::new(TypeKind::I64)
                        } else {
                            Type::new(TypeKind::U64)
                        });
                    }
                    "void" => {
                        self.ty = Some(Type::new(TypeKind::Void));
                    }
                    "void*" => {
                        parts.push_front("*".into());
                        parts.push_front("void".into());
                    }
                    "bool" => {
                        self.ty = Some(Type::new(TypeKind::Bool));
                    }
                    "u8" => {
                        self.ty = Some(Type::new(TypeKind::U8));
                        self.signed = false;
                    }
                    "u16" => {
                        self.ty = Some(Type::new(TypeKind::U16));
                        self.signed = false;
                    }
                    "u32" => {
                        self.ty = Some(Type::new(TypeKind::U32));
                        self.signed = false;
                    }
                    "__u64" => {
                        self.ty = Some(Type::new(TypeKind::U64));
                        self.signed = false;
                    }
                    "__u32" => {
                        self.ty = Some(Type::new(TypeKind::U32));
                        self.signed = false;
                    }
                    "__u16" => {
                        self.ty = Some(Type::new(TypeKind::U16));
                        self.signed = false;
                    }
                    "__u8" => {
                        self.ty = Some(Type::new(TypeKind::U8));
                        self.signed = false;
                    }
                    "s64" => {
                        self.ty = Some(Type::new(TypeKind::I64));
                    }
                    "u64" => {
                        self.ty = Some(Type::new(TypeKind::U64));
                        self.signed = false;
                    }
                    "s16" => {
                        self.ty = Some(Type::new(TypeKind::I16));
                    }
                    "s32" => {
                        self.ty = Some(Type::new(TypeKind::I32));
                    }
                    "s8" => {
                        self.ty = Some(Type::new(TypeKind::I8));
                    }
                    "__le64" => {
                        self.ty = Some(Type::new(TypeKind::I64));
                    }
                    "__le16" => {
                        self.ty = Some(Type::new(TypeKind::I16));
                    }
                    "*" => {
                        if let Some(t) = self.ty.take() {
                            self.ty = Some(Type::new(TypeKind::Ptr(Box::new(t.clone()))));
                        }
                    }
                    "[]" => {
                        if let Some(t) = self.ty.take() {
                            self.ty = Some(Type::new(TypeKind::Tuple(vec![t])));
                        }
                    }
                    "struct" => {
                        if let Some(struct_name) = parts.pop_front() {
                            let mut new_struct = Type::new(TypeKind::Struct(vec![]));
                            new_struct.name = Some(struct_name.to_owned());
                            self.ty = Some(new_struct);
                        }
                    }
                    mut s => {
                        if s.ends_with("[]") {
                            s = &s[..s.len() - 2];
                            parts.push_front("[]".into());
                            parts.push_front(s.into());
                            continue;
                        }

                        let re = Regex::new(r"(.*?)\[.*?\]").unwrap();
                        if let Some(name) = re.captures(s) {
                            if let Some(name) = name.get(1) {
                                self.name = name.as_str().to_owned();
                                parts.push_front("[]".into());
                                continue;
                            }
                        }

                        let re = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
                        if re.is_match(s) {
                            self.name = s.to_owned();
                            continue;
                        }

                        if (s.contains("[") && !s.contains("]"))
                            || (s.contains("(") && !s.contains(")"))
                        {
                            parts.front_mut().unwrap().insert_str(0, s);
                            continue;
                        }
                    }
                }
            }
        }
    }

    fn parse_offset(&mut self, offset: &str) {
        self.offset = offset.trim().parse().expect("wrong format");
    }

    fn parse_size(&mut self, size: &str) {
        self.size = size.trim().parse().expect("wrong format");
    }

    fn parse_signed(&mut self, signed: &str) {
        let is_signed: usize = signed.trim().parse().expect("wrong format");
        if is_signed == 1 {
            self.signed = true
        } else {
            self.signed = false
        }
    }
}

impl From<&str> for TracepointField {
    fn from(val: &str) -> Self {
        let mut tf = TracepointField::new();

        let field = extract_value(&Regex::new(r"field:(.*?);").unwrap(), val);
        let offset = extract_value(&Regex::new(r"offset:(.*?);").unwrap(), val);
        let size = extract_value(&Regex::new(r"size:(.*?);").unwrap(), val);
        let signed = extract_value(&Regex::new(r"signed:(.*?);").unwrap(), val);

        match (field, offset, size, signed) {
            (Some(field), Some(offset), Some(size), Some(signed)) => {
                tf.parse_offset(offset);
                tf.parse_size(size);
                tf.parse_signed(signed);
                tf.parse_field(field);
            }
            _ => panic!("wrong format"),
        };

        tf
    }
}

fn extract_value<'a>(regex: &Regex, input: &'a str) -> Option<&'a str> {
    if let Some(capture) = regex.captures(input) {
        if let Some(value) = capture.get(1) {
            return Some(value.as_str());
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct TracepointEvent {
    path: PathBuf,
    fields: Vec<TracepointField>,
}

impl TracepointEvent {
    pub fn new(category: &str, name: &str) -> Self {
        let path = tracepoint_path(category, name);
        assert!(path.exists());
        let mut tf = TracepointEvent {
            path,
            fields: vec![],
        };

        tf.format();
        tf
    }

    fn format(&mut self) {
        self.path.push("format");
        let content = std::fs::read_to_string(&self.path).unwrap();
        for line in content.lines() {
            if let Some(_) = line.find("field:") {
                self.fields.push(TracepointField::from(line));
            }
        }
        self.path.pop();
    }
}

#[cfg(test)]
mod tests {
    use libfirm_rs::init_libfirm;

    use super::*;

    #[test]
    fn test_tracepoint_format() {
        init_libfirm();

        println!("{:#?}", TracepointEvent::new("skb", "kfree_skb"));
    }
}
