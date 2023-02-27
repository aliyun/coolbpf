use std::{
    ffi::CString,
    fs::{read_to_string, File},
    net::Ipv4Addr,
    ops::Range,
    sync::Mutex,
};

use crate::utils::timestr::TimeStr;
use crate::utils::tstamp::delta_of_mono_real_time;
use crate::{
    btf::btf_type_kind,
    builtin_function::BuiltinFunction,
    gstack::{get_stack_string, get_stackmap},
    kallsyms::GLOBAL_KALLSYMS,
    utils::{tcpflags::TcpFlags, tcpstate::TcpState},
};
use anyhow::{bail, Result};
use btfparse::BtfKind;
use byteorder::{ByteOrder, NativeEndian};
use libfirm_rs::{Mode, Node, Type, TypeKind, UsAction};
use std::fmt;

use super::perf::PrintHandler;

pub enum LayoutKind {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,

    Pointer,
    Struct(Vec<Layout>),
    Union(Vec<Layout>),
    Tuple(Vec<Layout>),

    Ntop,
    // depth
    StackMap(u8),
    BuiltinAction(BuiltinFunction),
}

impl fmt::Display for LayoutKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutKind::U8 => write!(f, "u8"),
            LayoutKind::I8 => write!(f, "i8"),
            LayoutKind::U16 => write!(f, "u16"),
            LayoutKind::I16 => write!(f, "i16"),
            LayoutKind::U32 => write!(f, "u32"),
            LayoutKind::I32 => write!(f, "i32"),
            LayoutKind::U64 => write!(f, "u64"),
            LayoutKind::I64 => write!(f, "i64"),
            LayoutKind::Tuple(_) => write!(f, "tuple"),
            _ => todo!(),
        }
    }
}

impl LayoutKind {
    fn add_member(&mut self, member: Layout) {
        match self {
            LayoutKind::Struct(v) | LayoutKind::Tuple(v) | LayoutKind::Union(v) => {
                v.push(member);
            }
            _ => {
                panic!("LayoutKind is not compound type")
            }
        }
    }
}

pub struct Layout {
    name: Option<String>,
    offset: u16,
    size: u16,
    kind: LayoutKind,
}

impl std::ops::Deref for Layout {
    type Target = LayoutKind;
    fn deref(&self) -> &Self::Target {
        &self.kind
    }
}

impl Layout {
    pub fn new(kind: LayoutKind) -> Self {
        let mut size = 0;
        match kind {
            LayoutKind::I8 | LayoutKind::U8 => size = 1,
            LayoutKind::I16 | LayoutKind::U16 => size = 2,
            LayoutKind::I32 | LayoutKind::U32 | LayoutKind::Ntop => size = 4,
            LayoutKind::I64 | LayoutKind::U64 | LayoutKind::Pointer => size = 8,
            _ => size = 0,
        }
        Layout {
            name: None,
            offset: 0,
            size,
            kind,
        }
    }

    pub fn set_offset(&mut self, offset: u16) {
        self.offset = offset
    }

    pub fn set_size(&mut self, size: u16) {
        self.size = size
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_owned())
    }

    pub fn add_member(&mut self, lo: Layout) {
        self.kind.add_member(lo)
    }

    pub fn print(&self, p: &mut PrintHandler, data: &[u8]) {
        let start = self.offset as usize;
        match &self.kind {
            LayoutKind::I8 => {
                p.print_number(data[self.offset as usize] as i8);
            }
            LayoutKind::U8 => {
                p.print_number(data[self.offset as usize] as u8);
            }
            LayoutKind::I16 => {
                p.print_number(NativeEndian::read_i16(&data[start..start + 2]));
            }
            LayoutKind::U16 => {
                p.print_number(NativeEndian::read_u16(&data[start..start + 2]));
            }
            LayoutKind::I32 => {
                p.print_number(NativeEndian::read_i32(&data[start..start + 4]));
            }
            LayoutKind::U32 => {
                p.print_number(NativeEndian::read_u32(&data[start..start + 4]));
            }
            LayoutKind::I64 => {
                p.print_number(NativeEndian::read_i64(&data[start..start + 8]));
            }
            LayoutKind::U64 | LayoutKind::Pointer => {
                p.print_number(NativeEndian::read_u64(&data[start..start + 8]));
            }
            LayoutKind::Tuple(t) => {
                for l in t {
                    l.print(p, data);
                }
            }
            LayoutKind::Ntop => {
                let ip = Ipv4Addr::from(NativeEndian::read_u32(&data[start..start + 4]));
                p.print_string(ip.to_string());
            }
            LayoutKind::StackMap(depth) => {
                let key = NativeEndian::read_i64(&data[start..start + 8]);
                let stack_string = if let Some(stack) = get_stackmap(*depth).lookup(key).unwrap() {
                    get_stack_string(&stack)
                } else {
                    "Kernel Stack Missing\n".to_owned()
                };
                p.print_string(stack_string);
            }

            LayoutKind::BuiltinAction(builtin) => match builtin {
                BuiltinFunction::TcpState => {
                    let state = TcpState::from(data[start]);
                    p.print_string(state.to_string());
                }
                BuiltinFunction::TcpFlags => {
                    let flags = TcpFlags::from(data[start]);
                    p.print_string(flags.to_string());
                }
                BuiltinFunction::TimeStr => {
                    let ns =
                        NativeEndian::read_u64(&data[start..start + 8]) + delta_of_mono_real_time();
                    let ts = TimeStr::from(ns);
                    p.print_string(ts.to_string());
                }
                BuiltinFunction::Ksym => {
                    let addr = NativeEndian::read_u64(&data[start..start + 8]);
                    p.print_string(GLOBAL_KALLSYMS.symbol(addr));
                }
                _ => todo!(),
            },

            _ => {
                panic!("not support")
            }
        }
    }
}

impl From<&Type> for Layout {
    fn from(ty: &Type) -> Self {
        match ty.kind() {
            TypeKind::Primitive => {
                let mode = ty.mode();
                if mode == Mode::ModeBu() {
                    return Layout::new(LayoutKind::U8);
                } else if mode == Mode::ModeBs() {
                    return Layout::new(LayoutKind::I8);
                } else if mode == Mode::ModeHu() {
                    return Layout::new(LayoutKind::U16);
                } else if mode == Mode::ModeHs() {
                    return Layout::new(LayoutKind::I16);
                } else if mode == Mode::ModeIu() {
                    return Layout::new(LayoutKind::U32);
                } else if mode == Mode::ModeIs() {
                    return Layout::new(LayoutKind::I32);
                } else if mode == Mode::ModeLu() {
                    return Layout::new(LayoutKind::U64);
                } else if mode == Mode::ModeLs() {
                    return Layout::new(LayoutKind::I64);
                }

                panic!("Primitive type mode is wrong")
            }
            TypeKind::Pointer => {
                return Layout::new(LayoutKind::Pointer);
            }
            _ => {}
        }

        if let Some(typeid) = ty.typeid() {
            return Layout::from(typeid);
        }

        todo!()
    }
}

impl From<&Node> for Layout {
    fn from(node: &Node) -> Self {
        match node.us_action() {
            UsAction::None => Layout::from(&node.type_()),
            UsAction::Ntop => Layout::new(LayoutKind::Ntop),
            UsAction::TcpState => Layout::new(LayoutKind::BuiltinAction(BuiltinFunction::TcpState)),
            UsAction::TcpFlags => Layout::new(LayoutKind::BuiltinAction(BuiltinFunction::TcpFlags)),
            UsAction::TimeStr => Layout::new(LayoutKind::BuiltinAction(BuiltinFunction::TimeStr)),
            UsAction::Ksym => Layout::new(LayoutKind::BuiltinAction(BuiltinFunction::Ksym)),
            _ => {
                let id = node.us_action() as u32 - UsAction::StackMap as u32;
                if id <= 20 {
                    return Layout::new(LayoutKind::StackMap(id as u8));
                }
                todo!()
            }
        }
    }
}
// type id
impl From<u32> for Layout {
    fn from(typeid: u32) -> Self {
        match btf_type_kind(typeid) {
            BtfKind::Ptr => return Layout::new(LayoutKind::Pointer),
            BtfKind::Struct => {
                panic!("not support")
            }
            _ => {
                todo!()
            }
        }
    }
}
