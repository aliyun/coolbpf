use std::env;
use std::path::PathBuf;
use libbpf_cargo::SkeletonBuilder;
use bindgen;

fn generate_skeleton(name: &str) {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
        .join("src")
        .join("bpf")
        .join("skel")
        .join(format!("{}.skel.rs", name));

    let mut builder = SkeletonBuilder::new();
    let builder = builder.source(format!("src/bpf/{}.bpf.c", name));
    // 不依赖本地的vmlinux.h，而是使用libbpf-bootstrap项目提供的vmlinux.h，详见build-dependencies
    // builder.clang_args(["-I."]);
    {
        use std::ffi::OsStr;
        let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");
        builder.clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ]);
    }
    builder.build_and_generate(&out).unwrap();
}

fn generate_header(name: &str) {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
        .join("src")
        .join("bpf")
        .join("skel")
        .join(format!("{}.rs", name));

    let header_path = format!("src/bpf/{}.h", name);

    let bindings = bindgen::Builder::default()
        .header(&header_path)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .unwrap();
    bindings.write_to_file(&out).unwrap();

    println!("cargo:rerun-if-changed={header_path}");
}


fn main() {
    generate_skeleton("capture");
    generate_header("capture");
}