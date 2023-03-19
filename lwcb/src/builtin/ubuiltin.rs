use std::{ffi::CString, net::Ipv4Addr};

use crate::{
    event::print_string,
    gstack::{get_stack_string, get_stackmap},
    kallsyms::GLOBAL_KALLSYMS,
    types::Type,
    utils::{tcpflags::TcpFlags, tcpstate::TcpState},
};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, NativeEndian};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UBuiltin {
    Ntop,
    TcpState,
    TcpFlags,
    Time,
    Ksym,
    // stackid to stack string
    Kstack(usize),
}

impl UBuiltin {
    pub fn return_type(&self, args: &Vec<&Type>) -> Type {
        let mut typ = args[0].clone();
        typ.set_ubuiltin(self.clone());
        typ
    }

    pub fn print(&self, fmt: &CString, data: &[u8]) {
        let string = self.stringify(data);
        print_string(fmt, string)
    }

    pub fn stringify(&self, data: &[u8]) -> String {
        match self {
            UBuiltin::Ntop => Ipv4Addr::from(NativeEndian::read_u32(&data[..4])).to_string(),
            UBuiltin::TcpState => TcpState::from(data[0]).to_string(),
            UBuiltin::TcpFlags => TcpFlags::from(data[0]).to_string(),
            UBuiltin::Time => todo!(),
            UBuiltin::Ksym => {
                let addr = NativeEndian::read_u64(&data[..8]);
                GLOBAL_KALLSYMS.symbol(addr)
            }
            UBuiltin::Kstack(depth) => {
                let key = NativeEndian::read_i64(&data[..8]);
                if let Some(stack) = get_stackmap(*depth as u8).lookup(key).unwrap() {
                    get_stack_string(&stack)
                } else {
                    "Kernel Stack Missing\n".to_owned()
                }
            }
        }
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
