use blang::BLangBuilder;
use std::env;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;

fn get_test_file_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::new();
    path.push(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/files");
    path.push(filename);
    path
}

fn read_test_file(path: &PathBuf) -> (String, String) {
    let file = File::open(path).expect("failed to open file");
    let lines = BufReader::new(file).lines();

    let mut dollar = 0;
    let mut expected_result = String::default();
    let mut code = String::default();

    for line in lines {
        let mut data = line.unwrap();

        if data.starts_with("$") {
            dollar += 1;
            continue;
        }

        data += "\n";

        if dollar >= 2 {
            code.push_str(&data);
        } else if dollar >= 1 {
            expected_result.push_str(&data);
        }
    }
    (expected_result.trim().to_string(), code)
}

fn run_one_test(filename: &str) {
    let path = get_test_file_path(filename);
    let (expected_result, code) = read_test_file(&path);
    let mut out = vec![];
    BLangBuilder::new(code)
        .btf("../tests/bin/vmlinux")
        .dump_ir(true)
        .build_with_output(&mut out);

    let mut out_string = String::from_utf8(out).unwrap();
    out_string = out_string.trim().to_owned();

    println!("{}", out_string);

    assert_eq!(expected_result, out_string)
}

#[test]
fn test_empty() {
    run_one_test("empty.cb");
}


#[test]
fn test_map() {
    run_one_test("map.cb");
}

#[test]
fn test_binary_add() {
    run_one_test("binary_add.cb");
}

#[test]
fn test_binary_sub() {
    run_one_test("binary_sub.cb");
}

#[test]
fn test_binary_div() {
    run_one_test("binary_div.cb");
}

#[test]
fn test_binary_mul() {
    run_one_test("binary_mul.cb");
}

#[test]
fn test_unary_neg() {
    run_one_test("unary_neg.cb");
}