use std::path::PathBuf;

use anyhow::{bail, Result};
use libfirm_rs::{generate_code, init_libfirm};

use crate::context::Context;
// use crate::ast::*;
use crate::ast::*;
use crate::bpf::map::StackMap;
use crate::bpf::program::ProgramType;
use crate::btf::{btf_find_funcs_by_typename, btf_find_struct, btf_get_func_name};
use crate::firm::FirmProgram;
use crate::gperf::{perf_poll, perf_open_buffer, perf_read_events};
use crate::utils::bump_memlock_rlimit;


// Light-weight eBPF Tracing
pub struct LwCB {
    // eBPF ir programs
    firms: Vec<FirmProgram>,

    irdump: Option<PathBuf>,
    lirdump: Option<PathBuf>,
    astdump: bool,

    open_buffer: bool,
    ctx: Option<Context>,
}

impl LwCB {
    pub fn new() -> Self {
        init_libfirm();

        bump_memlock_rlimit().unwrap();
        LwCB {
            firms: vec![],
            irdump: None,
            lirdump: None,
            astdump: false,
            open_buffer: false,
            ctx: None,
        }
    }

    /// enable dump ir svg graph
    pub fn set_irdump(&mut self, dump: PathBuf) {
        if !dump.exists() {
            if std::fs::create_dir_all(&dump).is_err() {
                panic!("Failed to create irdump directory: {}", dump.display())
            }
        }
        assert!(
            dump.is_dir(),
            "Expect directory but {} is not a directory",
            dump.display()
        );
        self.irdump = Some(dump);
    }

    /// enable dump lower ir(is being optimized) svg graph
    pub fn set_lirdump(&mut self, dump: PathBuf) {
        if !dump.exists() {
            if std::fs::create_dir_all(&dump).is_err() {
                panic!("Failed to create lirdump directory: {}", dump.display())
            }
        }
        assert!(
            dump.is_dir(),
            "Expect directory but {} is not a directory",
            dump.display()
        );
        self.lirdump = Some(dump);
    }

    pub fn set_astdump(&mut self, dump: bool) {
        self.astdump = dump;
    }

    fn compile_program(&mut self, ctx: &mut Context, expr: &Expr) -> Result<()>{
        if let ExprKind::Program(ty, e) = &expr.kind {
            for i in ty {
                let mut fp = FirmProgram::new();
                match &i.kind {
                    TyKind::Kprobe(name) => {
                        fp.set_func_name(name.clone());
                        fp.set_kprobe();
                    }
                    TyKind::Kretprobe(name) => {
                        fp.set_func_name(name.clone());
                        fp.set_kretprobe();
                    }
                    _ => todo!()
                }
                fp.gen(ctx, i.id, e, 100)?;
                self.firms.push(fp);
            }
        }
        Ok(())
    }

    pub fn compile(&mut self, text: &str) -> Result<()> {
        let ast = Ast::from(text);
        if self.astdump {
            println!("{:#?}", ast);
        }

        let mut ctx = Context::new(TypeBinding::from(&ast));
        for prog in &ast.exprs {
            self.compile_program(&mut ctx, prog)?;
        }

        self.ctx = Some(ctx);
        Ok(())
    }

    pub fn generate_bytecode(&mut self) -> Result<()> {
        generate_code()?;
        for firm in &mut self.firms {
            firm.generate_bytecode();
        }
        Ok(())
    }

    pub fn attach(&mut self) -> Result<()> {
        for firm in &mut self.firms {
            firm.attach()?;
        }
        return Ok(());
    }

    /// Attach the source program to target kprobe in linux kernel
    pub fn attach_kprobe(&mut self, src: &str, tar: &str) -> Result<()> {
        for firm in &mut self.firms {
            if firm.is_name(src) {
                firm.attach_kprobe(tar)?;
                log::debug!("attach eBPF program: {} to kprobe: {}", src, tar);
                return Ok(());
            }
        }

        bail!("Can't find source program named: {}", src)
    }

    pub fn poll(&mut self) {
        let mut ctx = self.ctx.take().unwrap();
        if !self.open_buffer {
            ctx.perf.open_buffer();
            self.open_buffer = true;
        }
        loop {
            let raw_data = ctx.perf.poll();
            for data in raw_data {
                // ctx.handle_data(data);
            }
        }
    }

    pub fn read_events(&mut self) -> Vec<Vec<String>> {
        if !self.open_buffer {
            perf_open_buffer();
            self.open_buffer = true;
        }

        perf_read_events()
    }
}
