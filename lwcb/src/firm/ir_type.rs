use libfirm_rs::Type as IrType;
use libfirm_rs::TypeKind as IrTypeKind;

use crate::types::Type;

pub fn method_irtype(args: Vec<&Type>, return_: Option<&Type>) -> IrType {
    let ir: Vec<IrType> = args.iter().map(|typ| (*typ).irtype()).collect();

    IrType::new_method(&ir, None)
}

// create firm method entity by typeid of tracing function
// pub fn method_entity(prog_type: &Type) {
//     let func_name = if let Some(name) = prog_type.try_func_name() {
//         name
//     } else {
//         "anon_function"
//     };

//     let func_ident = unique_ident(func_name);

//     // tracing function has default parameter: struct pt_regs *
//     let ctx_type = pt_regs_type();
//     let ctx_type_ptr = ctx_type.to_ptr();

//     let method = IrType::new_method(&vec![type_ctx_ptr], None);

//     let global_type = IrType::global_type();
//     let entity = Entity::new_global(&global_type, &func_ident, &method);
// }



pub fn global_irtype() -> IrType{
    IrType::global_type()
}