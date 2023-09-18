mod blang;
mod btf;
mod call;
mod constant;
mod lexer;
mod parser;
mod passes;
pub use blang::BLang;
pub use blang::BLangBuilder;
pub mod print;

pub const __PERF_EVENT_MAP__: &str = "__event_map__";
