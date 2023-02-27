use std::env;
use std::path::PathBuf;
use std::process::{exit, Command};

#[cfg(debug_assertions)]
fn is_debug() -> bool {
    true
}

#[cfg(not(debug_assertions))]
fn is_debug() -> bool {
    false
}

fn main() {
    let firm_src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("libfirm");
    let firm_src = std::fs::canonicalize(firm_src).unwrap();
    let out_path =
        PathBuf::from(env::var("OUT_DIR").expect("Environment variable OUT_DIR is unset"));

    let exit_code = Command::new("make")
        .current_dir(firm_src.as_path())
        .arg(if is_debug() {
            "variant=debug"
        } else {
            "variant=optimize"
        })
        .status()
        .expect("Failed to run make")
        .code()
        .unwrap_or(1);

    if exit_code != 0 {
        eprintln!("Failed to build libfirm");
        exit(exit_code);
    }

    let include_paths = vec![
        firm_src.clone().join("include/libfirm"),
        firm_src.clone().join("build/gen/include/libfirm"),
    ];

    include_paths
        .iter()
        .for_each(|p| println!("cargo:include={}", p.display()));

    let link_path = if is_debug() {
        firm_src.clone().join("build/debug")
    } else {
        firm_src.clone().join("build/optimize")
    };
    println!("cargo:rustc-link-search={}", link_path.display());
    println!("cargo:rustc-link-lib=static=firm");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(include_paths.iter().map(|p| format!("-I{}", p.display())))
        .generate()
        .expect("Failed to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
