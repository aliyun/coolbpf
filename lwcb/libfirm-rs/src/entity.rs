use crate::{types::Type, Ident, Mode, Tarval};
use libfirm_sys::*;

#[derive(Clone, Copy)]
pub struct Entity(*mut ir_entity);

impl From<*mut ir_entity> for Entity {
    fn from(ptr: *mut ir_entity) -> Self {
        Entity(ptr)
    }
}

unsafe impl Sync for Entity {}

impl Entity {
    pub fn new(entity: *mut ir_entity) -> Self {
        Entity(entity)
    }

    pub fn new_entity(owner: &Type, name: &Ident, ty: &Type) -> Self {
        unsafe { new_entity(owner.raw(), name.raw(), ty.raw()).into() }
    }

    pub fn new_global(segment: &Type, id: &Ident, ty: &Type) -> Self {
        unsafe {
            new_global_entity(
                segment.raw(),
                id.raw(),
                ty.raw(),
                ir_visibility_ir_visibility_external,
                ir_linkage_IR_LINKAGE_DEFAULT,
            )
            .into()
        }
    }

    pub fn raw(&self) -> *mut ir_entity {
        self.0
    }

    pub fn set_initializer(&mut self, initializer: &Initializer) {
        unsafe { set_entity_initializer(self.raw(), initializer.raw()) }
    }

    pub fn initializer(&self) -> Initializer {
        unsafe { get_entity_initializer(self.raw()).into() }
    }

    pub fn set_offset(&mut self, offset: i32) {
        unsafe { set_entity_offset(self.raw(), offset) }
    }

    pub fn set_bitfield_offset(&mut self, bitfield_offset: u32) {
        unsafe { set_entity_bitfield_offset(self.raw(), bitfield_offset) }
    }

    pub fn set_bitfield_size(&mut self, bitfield_size: u32) {
        unsafe { set_entity_bitfield_size(self.raw(), bitfield_size) }
    }

    pub fn type_(&self) -> Type {
        unsafe { get_entity_type(self.raw()).into() }
    }
}

#[derive(Clone, Copy)]
pub struct Initializer(*mut ir_initializer_t);

impl From<*mut ir_initializer_t> for Initializer {
    fn from(ptr: *mut ir_initializer_t) -> Self {
        Initializer(ptr)
    }
}

impl Initializer {
    pub fn raw(&self) -> *mut ir_initializer_t {
        self.0
    }
    pub fn from_tarval(val: &Tarval) -> Self {
        unsafe { create_initializer_tarval(val.raw()).into() }
    }

    pub fn new_compound(len: u64) -> Self {
        unsafe { create_initializer_compound(len).into() }
    }

    pub fn compound_set_value(&self, i: u64, val: &Initializer) {
        unsafe {
            set_initializer_compound_value(self.raw(), i, val.raw());
        }
    }

    pub fn construct_string(&self) -> String {
        assert_eq!(
            unsafe { get_initializer_kind(self.raw()) },
            ir_initializer_kind_t_IR_INITIALIZER_COMPOUND
        );
        let mut ret = String::new();
        for i in unsafe { 0..get_initializer_compound_n_entries(self.raw()) } {
            let tmp: Initializer = unsafe { get_initializer_compound_value(self.raw(), i) }.into();
            let tar: Tarval = unsafe { get_initializer_tarval_value(tmp.raw()) }.into();

            assert_eq!(tar.mode(), Mode::ModeBu());
            let val = tar.long();

            ret.push(val as u8 as char);
        }

        ret
    }
}
