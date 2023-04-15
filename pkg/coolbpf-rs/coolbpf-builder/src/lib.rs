use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use libbpf_cargo::SkeletonBuilder;

#[derive(Debug, Clone, Default)]
pub struct CoolBPFBuilder {
    target: Option<PathBuf>,
    source: Vec<String>,
    header: Vec<String>,
}

impl CoolBPFBuilder {
    /// generate skeleton for this source(*.bpf.c) file
    pub fn source<T: Into<String>>(&mut self, source: T) -> &mut CoolBPFBuilder {
        let src = source.into();
        println!("cargo:rerun-if-changed={}", src);
        self.source.push(src);
        self
    }

    /// generate bindings for this c header(*.h) file
    pub fn header<T: Into<String>>(&mut self, header: T) -> &mut CoolBPFBuilder {
        let hdr = header.into();
        println!("cargo:rerun-if-changed={}", hdr);
        self.header.push(hdr);
        self
    }

    /// target directory to store skeleton and bindings file
    ///
    /// default is `OUT_DIR` from environment variable
    pub fn target<P: AsRef<Path>>(&mut self, target: P) -> &mut CoolBPFBuilder {
        self.target = Some(target.as_ref().to_path_buf());
        self
    }

    pub fn build(&mut self) -> Result<()> {
        let mut target = self.target.as_ref().map_or_else(
            || {
                PathBuf::from(
                    std::env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"),
                )
            },
            |x| x.clone(),
        );

        for src in &self.source {
            let src_path = PathBuf::from(src);
            if let Some(filename) = src_path
                .file_name()
                .map(|x| x.to_string_lossy().to_string())
            {
                let dst = source_target_filename(filename);
                target.push(dst);
                build_source(&src_path, &target)?;
                target.pop();
            }
        }

        for hdr in &self.header {
            let hdr_path = PathBuf::from(hdr);
            if let Some(filename) = hdr_path
                .file_name()
                .map(|x| x.to_string_lossy().to_string())
            {
                let dst = header_target_filename(filename);
                target.push(dst);
                build_header(hdr, &target)?;
                target.pop();
            }
        }

        Ok(())
    }
}

fn build_source(source: &PathBuf, target: &PathBuf) -> Result<()> {
    SkeletonBuilder::new()
        .source(source)
        .build_and_generate(target)?;
    Ok(())
}

fn build_header(header: &String, target: &PathBuf) -> Result<()> {
    let bindings = bindgen::Builder::default()
        .header(header)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()?;
    bindings.write_to_file(target)?;
    Ok(())
}

fn source_target_filename<S: AsRef<str>>(src: S) -> String {
    let mut dst = src.as_ref().to_string();
    assert!(dst.ends_with(".bpf.c"));
    dst.truncate(dst.len() - ".bpf.c".len());
    dst.push_str(".skel.rs");
    dst
}

fn header_target_filename<S: AsRef<str>>(hdr: S) -> String {
    let mut dst = hdr.as_ref().to_string();
    assert!(dst.ends_with(".h"));
    dst.truncate(dst.len() - ".h".len());
    dst.push_str(".rs");
    dst
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_source_target_filename() {
        assert_eq!(source_target_filename("test.bpf.c"), "test.skel.rs");
    }

    #[test]
    fn test_header_filename_prefix() {
        assert_eq!(header_target_filename("test.h"), "test.rs");
    }
}
