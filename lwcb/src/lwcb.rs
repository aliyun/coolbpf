use std::path::PathBuf;

use anyhow::{bail, Result};
use libfirm_rs::{generate_code, init_libfirm};

use crate::ast::*;
use crate::bpf::map::StackMap;
use crate::bpf::program::ProgramType;
use crate::btf::{btf_find_funcs_by_typename, btf_find_struct, btf_get_func_name};
use crate::firm::FirmProgram;
use crate::gperf::{perf_open_buffer, perf_poll, perf_read_events};
use crate::utils::bump_memlock_rlimit;

// Light-weight eBPF Tracing
pub struct LwCB {
    // eBPF ir programs
    firms: Vec<FirmProgram>,

    irdump: Option<PathBuf>,
    lirdump: Option<PathBuf>,
    astdump: bool,

    open_buffer: bool,
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

    pub fn compile(&mut self, text: &str) -> Result<()> {
        let ast = Ast::from(text);
        if self.astdump {
            println!("{:#?}", ast);
        }
        self.visit_ast(&ast);
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
        perf_poll()
    }

    pub fn read_events(&mut self) -> Vec<Vec<String>> {
        if !self.open_buffer {
            perf_open_buffer();
        }

        perf_read_events()
    }
}

impl Visit for LwCB {
    fn visit_ast(&mut self, ast: &Ast) {
        visit_ast(self, ast);
    }

    fn visit_translation_unit(&mut self, unit: &TranslationUnit) {
        visit_translation_unit(self, unit)
    }

    fn visit_bpf_program(&mut self, program: &BpfProgram) {
        let mut program_type;
        let mut funcs = vec![];

        for pt in &program.types {
            let mut func_names = vec![];
            match pt {
                BpfProgramType::Kprobe(k) => {
                    program_type = ProgramType::Kprobe;
                    func_names.push(k.clone());
                }

                BpfProgramType::Kretprobe(k) => {
                    program_type = ProgramType::Kretprobe;
                    func_names.push(k.clone());
                }

                BpfProgramType::DynKprobe(d) => match &d.tn.type_specifier {
                    TypeSpecifier::Struct => {
                        program_type = ProgramType::Kprobe;
                        if let Some(ident) = &d.tn.identifier {
                            funcs = btf_find_funcs_by_typename(&ident.name, d.tn.pointers, 0);
                        }
                        for func in funcs.iter() {
                            func_names.push(btf_get_func_name(*func));
                        }
                    }
                    _ => todo!(),
                },
                _ => todo!(),
            }

            let mut firm = FirmProgram::new(func_names, program_type);
            firm.generate(program).unwrap();

            // dump ir
            if let Some(mut dump) = self.irdump.take() {
                dump.push(format!("ir_{}.vcg", self.firms.len()));
                firm.dump(&dump);
                dump.pop();
                self.irdump = Some(dump);
            }

            firm.optimize();
            // dump low ir
            if let Some(mut dump) = self.lirdump.take() {
                dump.push(format!("lowir_{}.vcg", self.firms.len()));
                firm.dump(&dump);
                dump.pop();
                self.lirdump = Some(dump);
            }

            self.firms.push(firm);
        }
    }
}
