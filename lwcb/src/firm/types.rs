use libbpf_sys::btf_type;
use libfirm_rs::Type;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub struct Btf {
    raw: *mut libbpf_sys::btf,
}

impl Btf {
    pub fn new() -> Self {
        let raw = unsafe { libbpf_sys::libbpf_find_kernel_btf() };
        assert!(!raw.is_null(), " Failed to load kernel btf");
        Btf { raw }
    }

    pub fn raw(&self) -> *mut libbpf_sys::btf {
        self.raw
    }

    fn btf_type(&self, typeid: u32) -> *const btf_type {
        let ty = unsafe { libbpf_sys::btf__type_by_id(self.raw(), typeid) };
        ty
    }

    pub fn typeid_to_type(&self, typeid: u32) -> Type {
        let ty = self.btf_type(typeid);

        todo!()
    }
}

unsafe impl Send for Btf {}

static GLOBAL_BTF: Lazy<Mutex<Btf>> = Lazy::new(|| Mutex::new(Btf::new()));

pub fn typeid_to_firmtype(typeid: u32) -> Type {
    todo!()
}
