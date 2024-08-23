use super::types::bpf;
use std::hash::Hash;
use std::hash::Hasher;
pub enum ProbeEvent {
    Trace(RawStack),
}

#[derive(Debug)]
pub enum RawUserStack {
    Native(Vec<u64>),
    Dynamic(Vec<bpf::Frame>),
}

impl Hash for bpf::Frame {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr_or_line.hash(state);
        self.kind.hash(state);
        self.return_address.hash(state);
    }
}

impl PartialEq for bpf::Frame {
    fn eq(&self, other: &Self) -> bool {
        self.addr_or_line == other.addr_or_line
            && self.kind == other.kind
            && self.return_address == other.return_address
    }
}

impl Eq for bpf::Frame {}

impl Hash for RawUserStack {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            RawUserStack::Native(native) => {
                // Hash the Native variant by hashing the vector of u64s
                native.hash(state);
            }
            RawUserStack::Dynamic(dynamic) => {
                // Hash the Dynamic variant by hashing the vector of Frames
                dynamic.hash(state);
            }
        }
    }
}

impl PartialEq for RawUserStack {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RawUserStack::Native(native_self), RawUserStack::Native(native_other)) => {
                native_self == native_other
            }
            (RawUserStack::Dynamic(dynamic_self), RawUserStack::Dynamic(dynamic_other)) => {
                dynamic_self == dynamic_other
            }
            _ => false,
        }
    }
}

impl Eq for RawUserStack {}

#[derive(Hash, PartialEq, Eq, Debug)]
pub struct RawStack {
    pub pid: u32,
    pub kernel: Vec<u64>,
    pub user: RawUserStack,
}

impl RawStack {}
