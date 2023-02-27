use anyhow::{bail, Result};

use crate::types::Constant;

pub fn try_enum_to_constant(name: &String) -> Result<Constant> {
    match name.as_str() {
        "IPPROTO_IP" => Ok(Constant::I32(libc::IPPROTO_IP)),
        "IPPROTO_TCP" => Ok(Constant::I32(libc::IPPROTO_TCP)),
        "IPPROTO_ICMP" => Ok(Constant::I32(libc::IPPROTO_ICMP)),
        "IPPROTO_UDP" => Ok(Constant::I32(libc::IPPROTO_UDP)),
        _ => bail!("failed to tran"),
    }
}
