use anyhow::bail;
use libfirm_rs::{Node, Type};

use crate::types::Types;
use std::fmt;
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BuiltinFunction {
    Print,
    Kstack,

    Iphdr,
    Tcphdr,

    Bswap,
    // translate integer into ip address string
    Ntop,
    /// `static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;`
    BpfProbeRead,

    Ns,
    Pid,
    TcpState,
    TcpFlags,
    TimeStr,
    Ksym,
    Reg,
}

impl fmt::Display for BuiltinFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuiltinFunction::Print => {
                write!(f, "PRINT")
            }
            _ => todo!(),
        }
    }
}

impl TryFrom<&String> for BuiltinFunction {
    type Error = anyhow::Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "print" => Ok(BuiltinFunction::Print),
            "iphdr" => Ok(BuiltinFunction::Iphdr),
            "tcphdr" => Ok(BuiltinFunction::Tcphdr),
            "ntop" => Ok(BuiltinFunction::Ntop),
            "bswap" => Ok(BuiltinFunction::Bswap),
            "kstack" => Ok(BuiltinFunction::Kstack),
            "ns" => Ok(BuiltinFunction::Ns),
            "pid" => Ok(BuiltinFunction::Pid),
            "tcpstate" => Ok(BuiltinFunction::TcpState),
            "tcpflags" => Ok(BuiltinFunction::TcpFlags),
            "timestr" => Ok(BuiltinFunction::TimeStr),
            "ksym" => Ok(BuiltinFunction::Ksym),
            "reg" => Ok(BuiltinFunction::Reg),
            _ => bail!("{}: Unknow builtin function", value),
        }
    }
}

impl BuiltinFunction {
    pub fn return_type(&self) -> Types {
        match self {
            BuiltinFunction::Print => Types::Void,
            _ => todo!(),
        }
    }
}
