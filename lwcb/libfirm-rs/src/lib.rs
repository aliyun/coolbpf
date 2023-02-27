mod graph;

pub use self::graph::*;

mod mode;
pub use self::mode::Mode;

mod tarval;
pub use self::tarval::Tarval;

mod node;
pub use self::node::*;

mod types;
pub use self::types::*;

mod entity;
pub use self::entity::{Entity, Initializer};

mod ident;
pub use self::ident::Ident;

mod relation;
pub use self::relation::Relation;

use anyhow::Result;
use libfirm_sys::*;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;

pub fn init_libfirm() {
    unsafe {
        let cpu = CString::new("bpf").unwrap();
        ir_init_library();
        let triple = ir_get_host_machine_triple();
        ir_triple_set_cpu_type(triple, cpu.as_ptr());
        let ret = ir_target_set_triple(triple);
        if ret == 0 {
            panic!("Failed to initialize libfirm");
        }
        ir_target_init();

        set_optimize(1);
        set_opt_constant_folding(1);
        set_opt_algebraic_simplification(1);
        set_opt_cse(1);
        set_opt_global_cse(0);
        be_lower_for_target();
    }
}

// cparser:generate_code
pub fn generate_code() -> Result<String> {
    let dir = tempfile::tempdir()?;
    let file_path = dir.path().join("m.txt");
    // let mut file = File::create(&file_path)?;
    unsafe {
        let c_mode = CString::new("w".to_owned()).unwrap();
        let c_path = CString::new(file_path.as_os_str().to_str().unwrap()).unwrap();
        let cu = CString::new("tmp").unwrap();

        let file = libc::fopen(c_path.as_ptr(), c_mode.as_ptr());
        if file.is_null() {
            panic!("Faied to open file: {:?}", c_path);
        }
        be_main(file as *mut _IO_FILE, cu.as_ptr());
        libc::fclose(file);
    }

    let mut buf = "".to_string();
    let mut file = File::open(file_path)?;
    file.read_to_string(&mut buf)?;
    dir.close()?;
    Ok(buf)
}
