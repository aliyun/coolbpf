pub mod btf;

mod types;
use std::path::PathBuf;

use btf::Btf;
pub use types::{
    array::Array,
    const_::Const,
    datasec::DataSec,
    decltag::DeclTag,
    enum64::Enum64,
    enum_::Enum,
    float::Float,
    func::Func,
    func_proto::FuncProto,
    fwd::Fwd,
    int::{Int, IntEncoding},
    ptr::Ptr,
    restrict::Restrict,
    struct_::Struct,
    typedef::Typedef,
    typetag::TypeTag,
    union::Union,
    var::Var,
    volatile::Volatile,
    BtfMember,
};

pub use btf::BtfKind;
// pub mod func_map;

use anyhow::Result;

pub fn btf_load(path: &PathBuf) -> Btf {
    Btf::from_file(path).unwrap()
}

pub fn try_btf_load(path: Option<&str>) -> Option<Btf> {
    todo!()
}

fn load(path: &str) -> Result<Btf> {
    Btf::from_file(path)
}
