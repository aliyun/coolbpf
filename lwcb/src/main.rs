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
}

fn main() {
    env_logger::init();
    let opts = Command::from_args();

    let code_string;
    if let Some(p) = opts.script {
        code_string = Some(read_to_string(&p).unwrap());
    } else if let Some(t) = opts.text {
        code_string = Some(t.clone());
    } else {
        code_string = None;
    }

    if let Some(code) = code_string {
        run(code);
    }
}

fn run(code: String) {
    let blang = BLangBuilder::new(code).build();
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
