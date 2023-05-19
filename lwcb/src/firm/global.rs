use std::ffi::CString;

use libfirm_rs::Entity;
use libfirm_rs::Ident;
use libfirm_rs::Mode;
use libfirm_rs::Node;
use libfirm_rs::Type;

use lazy_static::lazy_static;
use paste::paste;

fn type_probe_read() -> Type {
    let type_arg1 = Type::new_pointer(&TYPE_U8);
    let type_arg2 = TYPE_U32.clone();
    Type::new_method(&vec![type_arg1, type_arg2, type_arg1], None)
}

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

fn type_get_stackid() -> Type {
    let type_arg1 = Type::new_pointer(&TYPE_U8);
    let type_arg2 = TYPE_U64.clone();
    let type_arg3 = TYPE_U64.clone();
    let ret = TYPE_U64.clone();

    Type::new_method(&vec![type_arg1, type_arg2, type_arg3], Some(&ret))
}

// static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
fn type_KTIME_GET_NS() -> Type {
    Type::new_method(&vec![], Some(&TYPE_U64))
}

// static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
fn type_MAP_LOOKUP_ELEM() -> Type {
    let key = Type::new_pointer(&TYPE_U8);
    Type::new_method(&vec![TYPE_U64.clone(), key], Some(&key.clone()))
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

    // static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
    pub static ref MAP_LOOKUP_CSTRING: CString = CString::new("lookup_elem:1").unwrap();
    pub static ref IDENT_MAP_LOOKUP: Ident = Ident::new(&MAP_LOOKUP_CSTRING);
    pub static ref TYPE_MAP_LOOKUP: Type = type_probe_read();
    pub static ref ENTITY_MAP_LOOKUP: Entity = Entity::new_global(&Type::global_type(), &IDENT_MAP_LOOKUP, &TYPE_MAP_LOOKUP);
    pub static ref NODE_MAP_LOOKUP: Node = Node::new_address(&ENTITY_MAP_LOOKUP);

    // static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
    pub static ref PROBE_READ_CSTRING: CString = CString::new("probe_read:4").unwrap();
    pub static ref IDENT_PROBE_READ: Ident = Ident::new(&PROBE_READ_CSTRING);
    pub static ref TYPE_PROBE_READ: Type = type_probe_read();
    pub static ref ENTITY_PROBE_READ: Entity =
        Entity::new_global(&Type::global_type(), &IDENT_PROBE_READ, &TYPE_PROBE_READ);
    pub static ref NODE_PROBE_READ: Node = Node::new_address(&ENTITY_PROBE_READ);

    // static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
    pub static ref CSTRING_PERF_OUT: CString = CString::new("perf_out:25").unwrap();
    pub static ref IDENT_PERF_OUT: Ident = Ident::new(&CSTRING_PERF_OUT);
    pub static ref TYPE_PERF_OUT: Type = type_perf_out();
    pub static ref ENTITY_PERF_OUT: Entity =
        Entity::new_global(&Type::global_type(), &IDENT_PERF_OUT, &TYPE_PERF_OUT);
    // todo: remove this, cause we could not use the same node in different irg.
    // which causes error: Edge Verifier: %+F reachable by 1 node(s), but the list contains 2 edge(s)
    pub static ref NODE_PERF_OUT: Node = Node::new_address(&ENTITY_PERF_OUT);

    // long bpf_get_stackid(void *ctx, struct bpf_map *map, u64 flags) = (void *) 27;
    pub static ref CSTRING_GET_STACKID:CString = CString::new("get_stackid:27").unwrap();
    pub static ref IDENT_GET_STACKID: Ident = Ident::new(&CSTRING_GET_STACKID);
    pub static ref TYPE_GET_STACKID:Type = type_get_stackid();
    pub static ref ENTITY_GET_STACKID: Entity = Entity::new_global(&Type::global_type(),&IDENT_GET_STACKID, &TYPE_GET_STACKID);
    pub static ref NODE_GET_STACKID: Node = Node::new_address(&ENTITY_GET_STACKID);

}

macro_rules! create_builtin_function_firm {
    ($ident: ident, $id: expr) => {
        paste! {
            lazy_static! {
                pub static ref [<CSTRING_ $ident>]: CString = CString::new(format!("{}:{}", stringify!($ident), $id)).unwrap();
                pub static ref [<IDENT_ $ident>]: Ident = Ident::new(&[<CSTRING_ $ident>]);
                pub static ref [<TYPE_ $ident>]: Type = [<type_ $ident>]();
                pub static ref [<ENTITY_ $ident>]: Entity =  Entity::new_global(&Type::global_type(),&[<IDENT_ $ident>], &[<TYPE_ $ident>]);
                pub static ref [<NODE_ $ident>]: Node = Node::new_address(&[<ENTITY_ $ident>]);
            }
        }
    };
}

create_builtin_function_firm!(KTIME_GET_NS, 5);
create_builtin_function_firm!(MAP_LOOKUP_ELEM, 1);
