mod be;
pub mod types;
pub use types::Type;
pub use types::TypeKind;
pub mod func;
pub mod module;
pub mod object;

pub const HELPER_NAMESPACE: u32 = 0;
pub const ___MAP_NAMESPACE: u32 = 1;
