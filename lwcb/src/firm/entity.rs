use libfirm_rs::Entity;

use super::{
    frame::unique_ident,
    ir_type::{global_irtype, method_irtype},
    types::pt_regs_type,
};
use crate::types::Type;

/// create firm method entity by typeid of tracing function
pub fn method_entity(prog_type: &Type) -> Entity {
    let func_name = if let Some(name) = prog_type.try_func_name() {
        name
    } else {
        "anon_function"
    };

    let func_ident = unique_ident(func_name);

    // tracing function has default parameter: struct pt_regs *
    let ctx_type = Type::ptr(Type::u64());

    // don't care return type of tracing function
    Entity::new_global(
        &global_irtype(),
        &func_ident,
        &method_irtype(vec![&ctx_type], None),
    )
}
