use std::env;
use std::fs::create_dir_all;
use std::path::Path;

use libbpf_cargo::SkeletonBuilder;

const EXAMPLE_SRC: &str = "./src/bpf/example.bpf.c";
const HDR: &str = "./src/bpf/example.h";

fn main() {
    // run by default
    let build_enabled = env::var("SKEL_RS").map(|v| v == "1").unwrap_or(true);

    if !build_enabled {
        return;
    }

    // It's unfortunate we cannot use `OUT_DIR` to store the generated skeleton.
    // Reasons are because the generated skeleton contains compiler attributes
    // that cannot be `include!()`ed via macro. And we cannot use the `#[path = "..."]`
    // trick either because you cannot yet `concat!(env!("OUT_DIR"), "/skel.rs")` inside
    // the path attribute either (see https://github.com/rust-lang/rust/pull/83366).
    //
    // However, there is hope! When the above feature stabilizes we can clean this
    // all up.
    println!("cargo:rerun-if-changed={}", EXAMPLE_SRC);
    println!("cargo:rerun-if-changed={}", HDR);

    create_dir_all("./src/bpf/.output").unwrap();
    let example_skel = Path::new("./src/bpf/.output/example.skel.rs");
    SkeletonBuilder::new(EXAMPLE_SRC).generate(&example_skel).unwrap();

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(HDR)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");
    let bind = Path::new("./src/bpf/.output/bindings.rs");
    bindings
        .write_to_file(bind)
        .expect("Couldn't write bindings!");
}
