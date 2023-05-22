use std::ffi::CString;

use libfirm_rs::Entity;
use libfirm_rs::Ident;
use libfirm_rs::Mode;
use libfirm_rs::Node;
use libfirm_rs::Type;

use lazy_static::lazy_static;
use paste::paste;

// static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
fn type_ktime_get_ns() -> Type {
    Type::new_method(&vec![], Some(&TYPE_U64))
}

// static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
fn type_map_lookup_elem() -> Type {
    let key = Type::new_pointer(&TYPE_U8);
    Type::new_method(&vec![TYPE_U64.clone(), key], Some(&key.clone()))
}

// long bpf_get_stackid(void *ctx, struct bpf_map *map, u64 flags) = (void *) 27;
fn type_get_stackid() -> Type {
    let type_arg1 = Type::new_pointer(&TYPE_U8);
    let type_arg2 = TYPE_U64.clone();
    let type_arg3 = TYPE_U64.clone();
    let ret = TYPE_U64.clone();

    Type::new_method(&vec![type_arg1, type_arg2, type_arg3], Some(&ret))
}

// static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
fn type_perf_out() -> Type {
    let type_arg1 = Type::new_pointer(&TYPE_U8);
    let type_arg2 = type_arg1;
    let type_arg3 = TYPE_U64.clone();
    let type_arg4 = Type::new_pointer(&TYPE_U8);
    let type_arg5 = TYPE_U64.clone();
    Type::new_method(
        &vec![type_arg1, type_arg2, type_arg3, type_arg4, type_arg5],
        None,
    )
}

// static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
fn type_probe_read() -> Type {
    let type_arg1 = Type::new_pointer(&TYPE_U8);
    let type_arg2 = TYPE_U32.clone();
    Type::new_method(&vec![type_arg1, type_arg2, type_arg1], None)
}

lazy_static! {
    pub static ref TYPE_BOOL: Type = Type::new_primitive(&Mode::ModeBu());
    pub static ref TYPE_U8: Type = TYPE_BOOL.clone();
    pub static ref TYPE_I8: Type = Type::new_primitive(&Mode::ModeBs());
    pub static ref TYPE_U16: Type = Type::new_primitive(&Mode::ModeHu());
    pub static ref TYPE_I16: Type = Type::new_primitive(&Mode::ModeHs());
    pub static ref TYPE_U32: Type = Type::new_primitive(&Mode::ModeIu());
    pub static ref TYPE_I32: Type = Type::new_primitive(&Mode::ModeIs());
    pub static ref TYPE_U64: Type = Type::new_primitive(&Mode::ModeLu());
    pub static ref TYPE_I64: Type = Type::new_primitive(&Mode::ModeLs());
}

macro_rules! create_builtin_function_firm {
    ($ident: ident, $id: expr) => {
        paste! {
            lazy_static! {
                pub static ref [<CSTRING_ $ident>]: CString = CString::new(format!("{}:{}", stringify!($ident), $id)).unwrap();
                pub static ref [<IDENT_ $ident>]: Ident = Ident::new(&[<CSTRING_ $ident>]);
                pub static ref [<TYPE_ $ident>]: Type = [<type_ $ident:lower>]();
                pub static ref [<ENTITY_ $ident>]: Entity =  Entity::new_global(&Type::global_type(),&[<IDENT_ $ident>], &[<TYPE_ $ident>]);
                pub static ref [<NODE_ $ident>]: Node = Node::new_address(&[<ENTITY_ $ident>]);
            }
        }
    };
}

create_builtin_function_firm!(KTIME_GET_NS, 5);
create_builtin_function_firm!(MAP_LOOKUP_ELEM, 1);
create_builtin_function_firm!(GET_STACKID, 27);
create_builtin_function_firm!(PERF_OUT, 25);
create_builtin_function_firm!(PROBE_READ, 4);
