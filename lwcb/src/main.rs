use blang::{Compiler, CompilerBuilder};

fn main() {
    let compiler = CompilerBuilder::new("kprobe:tcp_sendmsg { a = 2;}".to_owned()).build();

    // println!("{:#?}", compiler.ast());
}
