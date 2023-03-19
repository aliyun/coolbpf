mod event;
mod printer;
mod stringify;

pub use {
    self::event::Event,
    self::printer::print_string,
    self::stringify::{stringify, ComplexString},
};

#[macro_export]
macro_rules! readu16 {
    ($data: ident) => {
        byteorder::NativeEndian::read_u16(&$data[..2])
    };
}

#[macro_export]
macro_rules! readi16 {
    ($data: ident) => {
        byteorder::NativeEndian::read_i16(&$data[..2])
    };
}

#[macro_export]
macro_rules! readu32 {
    ($data: ident) => {
        byteorder::NativeEndian::read_u32(&$data[..4])
    };
}

#[macro_export]
macro_rules! readi32 {
    ($data: ident) => {
        byteorder::NativeEndian::read_i32(&$data[..4])
    };
}

#[macro_export]
macro_rules! readu64 {
    ($data: ident) => {
        byteorder::NativeEndian::read_u64(&$data[..8])
    };
}

#[macro_export]
macro_rules! readi64 {
    ($data: ident) => {
        byteorder::NativeEndian::read_i64(&$data[..8])
    };
}
