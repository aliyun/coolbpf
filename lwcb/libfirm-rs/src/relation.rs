use libfirm_sys::*;

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum Relation {
    False = ir_relation_ir_relation_false,
    Equal = ir_relation_ir_relation_equal,
    Less = ir_relation_ir_relation_less,
    Greater = ir_relation_ir_relation_greater,
    Unordered = ir_relation_ir_relation_unordered,
    LessEqual = ir_relation_ir_relation_less_equal,
    GreateEqual = ir_relation_ir_relation_greater_equal,
    UnorderedLessGreater = ir_relation_ir_relation_unordered_less_greater,
    // ir_relation_less_greater            = ir_relation_less|ir_relation_greater,  /**< less or greater ('not equal' for integer numbers) */
    // ir_relation_less_equal_greater      = ir_relation_equal|ir_relation_less|ir_relation_greater, /**< less equal or greater ('not unordered') */
    // ir_relation_unordered_equal         = ir_relation_unordered|ir_relation_equal, /**< unordered or equal */
    // ir_relation_unordered_less          = ir_relation_unordered|ir_relation_less,  /**< unordered or less */
    // ir_relation_unordered_less_equal    = ir_relation_unordered|ir_relation_less|ir_relation_equal, /**< unordered, less or equal */
    // ir_relation_unordered_greater       = ir_relation_unordered|ir_relation_greater, /**< unordered or greater */
    // ir_relation_unordered_greater_equal = ir_relation_unordered|ir_relation_greater|ir_relation_equal, /**< unordered, greater or equal */
    // ir_relation_true                    = ir_relation_equal|ir_relation_less|ir_relation_gre
}
