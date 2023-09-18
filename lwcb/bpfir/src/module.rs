use cranelift_codegen::ir::types;
use cranelift_codegen::ir::types::*;
use cranelift_codegen::ir::AbiParam;
use cranelift_codegen::ir::FuncRef;
use cranelift_codegen::ir::Function;
use cranelift_codegen::ir::GlobalValue;
use cranelift_codegen::ir::Signature;
use cranelift_codegen::isa::riscv64::isa_builder;
use cranelift_codegen::isa::CallConv;
use cranelift_codegen::isa::OwnedTargetIsa;
use cranelift_codegen::settings::builder;
use cranelift_codegen::settings::Configurable;
use cranelift_codegen::settings::Flags;
use cranelift_codegen::Context;
use cranelift_module::DataId;
use cranelift_module::FuncId;
use cranelift_module::Linkage;
use cranelift_module::Module as ClifModule;
use cranelift_module::ModuleDeclarations;
use target_lexicon::Architecture;
use target_lexicon::Riscv64Architecture;
use target_lexicon::Triple;

use crate::func::Func;
use crate::object::BPFObject;
use crate::Type;
use std::collections::HashMap;
use std::fmt;

pub struct Module {
    funcs: Vec<Func>,
    isa: OwnedTargetIsa,
    declarations: ModuleDeclarations,

    maps: HashMap<DataId, Type>,
    helpers: HashMap<FuncId, u32>,
    functions: Vec<(Type, Context)>,
}

impl Default for Module {
    fn default() -> Self {
        Self::new()
    }
}

impl Module {
    pub fn new() -> Self {
        let mut triple = Triple::unknown();
        triple.architecture = Architecture::Riscv64(Riscv64Architecture::Riscv64);
        let mut b = builder();
        b.set("opt_level", "speed_and_size")
            .expect("failed to set optimization level");
        let flag = Flags::new(b);
        let isa = isa_builder(triple).finish(flag).unwrap();
        Module {
            funcs: Default::default(),
            isa,
            declarations: ModuleDeclarations::default(),
            maps: Default::default(),
            helpers: Default::default(),
            functions: Default::default(),
        }
    }

    pub fn add_func(&mut self, f: Func) {
        self.funcs.push(f);
    }

    pub fn compile(self) -> BPFObject {
        let mut object = BPFObject::new();

        for func in self.funcs {
            func.compile(&mut object);
        }

        object
    }

    pub fn define_probing_function(&mut self, ty: Type, ctx: Context) {
        self.functions.push((ty, ctx));
    }

    pub fn declare_helper_function(&mut self, id: u32) -> FuncId {
        let mut sig = self.make_signature();

        macro_rules! sig_params {
            ($a:expr,$($b:expr) ,*) => {
                $(
                    sig.params.push(AbiParam::new($b));
                )*
                sig.returns.push(AbiParam::new($a));
            };
        }
        let name;

        match id {
            // static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
            libbpf_sys::BPF_FUNC_map_update_elem => {
                sig_params!(I64, I64, I64, I64, I64);
                name = "bpf_map_lookup_elem";
            }
            // static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
            libbpf_sys::BPF_FUNC_perf_event_output => {
                sig_params!(I64, I64, I64, I64, I64, I64);
                name = "bpf_perf_event_output";
            }
            _ => todo!(),
        }
        let helper = self.declare_function(name, Linkage::Local, &sig).unwrap();
        helper
    }

    pub fn declare_helper_function_in_function(
        &mut self,
        id: FuncId,
        func: &mut Function,
    ) -> FuncRef {
        self.declare_func_in_func(id, func)
    }

    pub fn declare_map(&mut self, name: &str, ty: Type) -> DataId {
        let id = self
            .declare_data(name, Linkage::Local, false, false)
            .unwrap();
        self.maps.insert(id, ty);
        id
    }

    pub fn declare_map_in_function(&mut self, id: DataId, func: &mut Function) -> GlobalValue {
        self.declare_data_in_func(id, func)
    }

    pub fn context(&mut self) -> Context {
        self.make_context()
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (ty, func) in &self.functions {
            writeln!(f, "{}", func.func)?;
        }
        writeln!(f, "")
    }
}

impl ClifModule for Module {
    fn isa(&self) -> &dyn cranelift_codegen::isa::TargetIsa {
        &*self.isa
    }

    fn declarations(&self) -> &cranelift_module::ModuleDeclarations {
        &self.declarations
    }

    fn declare_function(
        &mut self,
        name: &str,
        linkage: cranelift_module::Linkage,
        signature: &cranelift_codegen::ir::Signature,
    ) -> cranelift_module::ModuleResult<cranelift_module::FuncId> {
        let (id, _) = self
            .declarations
            .declare_function(name, linkage, signature)?;
        Ok(id)
    }

    fn declare_anonymous_function(
        &mut self,
        signature: &cranelift_codegen::ir::Signature,
    ) -> cranelift_module::ModuleResult<cranelift_module::FuncId> {
        todo!()
    }

    fn declare_data(
        &mut self,
        name: &str,
        linkage: cranelift_module::Linkage,
        writable: bool,
        tls: bool,
    ) -> cranelift_module::ModuleResult<cranelift_module::DataId> {
        let (id, _) = self
            .declarations
            .declare_data(name, linkage, writable, tls)?;
        Ok(id)
    }

    fn declare_anonymous_data(
        &mut self,
        writable: bool,
        tls: bool,
    ) -> cranelift_module::ModuleResult<cranelift_module::DataId> {
        todo!()
    }

    fn define_function_with_control_plane(
        &mut self,
        func: cranelift_module::FuncId,
        ctx: &mut cranelift_codegen::Context,
        ctrl_plane: &mut cranelift_codegen::control::ControlPlane,
    ) -> cranelift_module::ModuleResult<()> {
        todo!()
    }

    fn define_function_bytes(
        &mut self,
        func_id: cranelift_module::FuncId,
        func: &cranelift_codegen::ir::Function,
        alignment: u64,
        bytes: &[u8],
        relocs: &[cranelift_codegen::MachReloc],
    ) -> cranelift_module::ModuleResult<()> {
        todo!()
    }

    fn define_data(
        &mut self,
        data_id: cranelift_module::DataId,
        data: &cranelift_module::DataDescription,
    ) -> cranelift_module::ModuleResult<()> {
        todo!()
    }

    fn get_name(&self, name: &str) -> Option<cranelift_module::FuncOrDataId> {
        todo!()
    }

    fn target_config(&self) -> cranelift_codegen::isa::TargetFrontendConfig {
        todo!()
    }

    fn make_context(&self) -> cranelift_codegen::Context {
        let mut ctx = Context::new();
        ctx.func.signature.call_conv = self.isa().default_call_conv();
        ctx
    }

    fn clear_context(&self, ctx: &mut cranelift_codegen::Context) {
        todo!()
    }

    fn make_signature(&self) -> Signature {
        Signature::new(self.isa().default_call_conv())
    }

    fn clear_signature(&self, sig: &mut cranelift_codegen::ir::Signature) {
        todo!()
    }
}
