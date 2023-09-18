use blang::BLangBuilder;
use std::fs::read_to_string;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "lwcb", about = "LightWeight eBPF Tracing")]
pub struct Command {
    #[structopt(help = "The path of script file")]
    script: Option<String>,
    #[structopt(long, short, help = "Raw text")]
    text: Option<String>,
    #[structopt(long, help = "btf file path")]
    btf: Option<String>,
}

fn main() {
    env_logger::init();
    let opts = Command::from_args();

    let code_string;
    if let Some(p) = &opts.script {
        code_string = read_to_string(p).unwrap();
    } else if let Some(t) = &opts.text {
        code_string = t.clone();
    } else {
        panic!("code script not found")
    }

    run(&opts, code_string);
}

fn run(opts: &Command, code: String) {
    let mut builder = BLangBuilder::new(code);
    if let Some(b) = &opts.btf {
        builder = builder.btf(b);
    }
    let blang = builder.build();
    let mut object = load_bpf_object(blang.object());
    let links = attach_program(&mut object);
}

fn load_bpf_object(mem_obj: &Vec<u8>) -> libbpf_rs::Object {
    let mut builder = libbpf_rs::ObjectBuilder::default();
    let object = builder
        .open_memory("lwcb", &mem_obj)
        .expect("failed to open object");
    let mut loaded_object = object
        .load()
        .expect("failed to load eBPF program into kernel");
    loaded_object
}

fn attach_program(object: &mut libbpf_rs::Object) -> Vec<libbpf_rs::Link> {
    let mut res = vec![];
    for prog in object.progs_iter_mut() {
        res.push(prog.attach().unwrap());
    }
    res
}
