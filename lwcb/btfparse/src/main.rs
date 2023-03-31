use btfparse::btf::Btf;

fn main() {
    env_logger::init();
    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
    for ty in btf.types() {
        println!("{:?}", ty);
    }
}
