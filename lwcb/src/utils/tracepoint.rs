use std::path::PathBuf;

use libc::strlen;
use libfirm_rs::{Mode, Type};

use anyhow::Result;

fn tracepoint_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/sys/kernel/debug/tracing/events/{}/{}",
        category, name
    ))
}

#[derive(Debug)]
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
    fn parse_field_str(&mut self, field: &str) -> usize {
        let mut off = 0;
        self.signed = true;
        if field[off..].starts_with("unsigned") {
            self.signed = false;
            off += "unsigned".len() + 1;
        }

        // if field[off..].starts_with("__data_loc") {
        //     data_loc = true;
        //     off += "__data_loc".len() + 1;
        // }

        if field[off..].starts_with("short") {
            self.ty = Some(if self.signed {
                Type::new_primitive(&Mode::ModeHs())
            } else {
                Type::new_primitive(&Mode::ModeHu())
            });
            off += "short".len();
        } else if field[off..].starts_with("char") {
            self.ty = Some(if self.signed {
                Type::new_primitive(&Mode::ModeBs())
            } else {
                Type::new_primitive(&Mode::ModeBu())
            });
            off += "char".len();
        } else if field[off..].starts_with("int") {
            self.ty = Some(if self.signed {
                Type::new_primitive(&Mode::ModeIs())
            } else {
                Type::new_primitive(&Mode::ModeIu())
            });
            off += "int".len();
        } else if field[off..].starts_with("void") {
            self.ty = Some(if self.signed {
                Type::new_primitive(&Mode::ModeANY())
            } else {
                Type::new_primitive(&Mode::ModeANY())
            });
            off += "void".len();
        } else {
            todo!()
        }
        assert!(self.ty.is_some());

        let mut start = None;
        let mut end = None;
        for (i, c) in field[off..].chars().enumerate() {
            if c >= 'a' && c <= 'z' {
                if start.is_none() {
                    start = Some(off + i);
                }
            }

            if c == '*' {
                self.ty = Some(Type::new_pointer(&self.ty.unwrap()));
            }

            if c == ';' {
                end = Some(off + i);
                break;
            }
        }

        self.name = field[start.unwrap()..end.unwrap()].to_owned();
        end.unwrap()
    }

    fn parse_offset_str(&mut self, offset: &str) -> usize {
        let mut end = None;
        for (i, c) in offset.chars().enumerate() {
            if c == ';' {
                if end.is_none() {
                    end = Some(i);
                }
                break;
            }
        }
        self.offset = offset[..end.unwrap()].parse().unwrap();
        end.unwrap()
    }

    fn parse_size_str(&mut self, size: &str) -> usize {
        let mut end = None;
        for (i, c) in size.chars().enumerate() {
            if c == ';' {
                if end.is_none() {
                    end = Some(i);
                }
                break;
            }
        }
        self.size = size[..end.unwrap()].parse().unwrap();
        end.unwrap()
    }

    fn parse_signed_str(&mut self, signed: &str) -> usize {
        let mut end = None;
        for (i, c) in signed.chars().enumerate() {
            if c == ';' {
                if end.is_none() {
                    end = Some(i);
                }
                break;
            }
        }
        end.unwrap()
    }
}

impl From<&str> for TracepointField {
    fn from(val: &str) -> Self {
        let mut tf = TracepointField::new();
        let mut off = 0;
        if let Some(x) = val[off..].find("field:") {
            off += x + "field:".len();
            off += tf.parse_field_str(&val[off..]);
            if let Some(x) = val[off..].find("offset:") {
                off += x + "offset:".len();
                off += tf.parse_offset_str(&val[off..]);
                if let Some(x) = val[off..].find("size:") {
                    off += x + "size:".len();
                    off += tf.parse_size_str(&val[off..]);
                    if let Some(x) = val[off..].find("signed:") {
                        off += x + "signed:".len();
                        off += tf.parse_signed_str(&val[off..]);
                        return tf;
                    }
                }
            }
        }
        panic!("wrong format")
    }
}

// tracepoint format

#[derive(Debug)]
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

    pub fn format(&mut self) {
        self.path.push("format");
        let content = std::fs::read_to_string(&self.path).unwrap();
        let mut off = 0;
        loop {
            if let Some(x) = content[off..].find("field:") {
                self.fields.push(TracepointField::from(&content[off..]));
                off += x + "field:".len();
            } else {
                break;
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
