use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub fn to_socketaddr(addr: u32, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr))), port)
}
