use anyhow::bail;
use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Call {
    Print,
    Kstack,
    Iphdr,
    Tcphdr,
    Bswap,
    Ns,
    Pid,
    Reg,
}

impl TryFrom<&str> for Call {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "print" => Ok(Call::Print),
            "iphdr" => Ok(Call::Iphdr),
            "tcphdr" => Ok(Call::Tcphdr),
            "bswap" => Ok(Call::Bswap),
            "kstack" => Ok(Call::Kstack),
            "ns" => Ok(Call::Ns),
            "pid" => Ok(Call::Pid),
            "reg" => Ok(Call::Reg),
            _ => bail!("{}: Unknown kernel space builtin function", value),
        }
    }
}
