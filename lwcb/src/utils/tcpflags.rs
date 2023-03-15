use std::fmt;
use strum_macros::Display;

#[derive(Debug, Display)]
#[repr(C)]
pub enum TcpFlag {
    Fin,
    Syn,
    Rst,
    Psh,
    Ack,
    Urg,
    Ece,
    Cwr,
}

pub struct TcpFlags(Vec<TcpFlag>);

impl From<u8> for TcpFlags {
    fn from(val: u8) -> Self {
        let mut flags = vec![];

        if val & (1 << (TcpFlag::Fin as u8)) != 0 {
            flags.push(TcpFlag::Fin);
        }
        if val & (1 << (TcpFlag::Syn as u8)) != 0 {
            flags.push(TcpFlag::Syn);
        }
        if val & (1 << (TcpFlag::Rst as u8)) != 0 {
            flags.push(TcpFlag::Rst);
        }
        if val & (1 << (TcpFlag::Psh as u8)) != 0 {
            flags.push(TcpFlag::Psh);
        }
        if val & (1 << (TcpFlag::Ack as u8)) != 0 {
            flags.push(TcpFlag::Ack);
        }
        if val & (1 << (TcpFlag::Urg as u8)) != 0 {
            flags.push(TcpFlag::Urg);
        }
        if val & (1 << (TcpFlag::Ece as u8)) != 0 {
            flags.push(TcpFlag::Ece);
        }
        if val & (1 << (TcpFlag::Cwr as u8)) != 0 {
            flags.push(TcpFlag::Cwr);
        }

        return TcpFlags(flags);
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags_str = vec![];
        for flag in &self.0 {
            flags_str.push(flag.to_string());
        }
        write!(f, "{}", flags_str.join("|"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcpflags() {
        assert_eq!(TcpFlags::from(1).to_string(), "Fin");
        assert_eq!(TcpFlags::from(3).to_string(), "Fin|Syn");
    }
}
