use blang::print::Print;
use blang::BLangBuilder;
use blang::__PERF_EVENT_MAP__;
use libbpf_rs::PerfBufferBuilder;
use std::fs::read_to_string;
use std::time::Duration;
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

fn _handle_event(prints: &Vec<Print>, _cpu: i32, data: &[u8]) {
    let id_arr: [u8; 8] = data[0..8].try_into().unwrap();
    let id = usize::from_ne_bytes(id_arr);
    debug_assert!(prints.len() > id);
    println!("{}", prints[id].bytes2string_with_offset(data, 1));
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn run(opts: &Command, code: String) {
    let mut builder = BLangBuilder::new(code);
    if let Some(b) = &opts.btf {
        builder = builder.btf(b);
    }
    let blang = builder.build();
    let mut object = load_bpf_object(blang.object());
    let _links = attach_program(&mut object);

    let prints = blang.prints;

    if prints.len() != 0 {
        let handle_event = move |_cpu: i32, data: &[u8]| {
            _handle_event(&prints, _cpu, data);
        };

        let perf = PerfBufferBuilder::new(object.map_mut(__PERF_EVENT_MAP__).unwrap())
            .sample_cb(handle_event)
            .lost_cb(handle_lost_events)
            .build()
            .expect("failed to start perf buffer");

        loop {
            perf.poll(Duration::from_millis(200)).unwrap();
        }
    }
}

fn load_bpf_object(mem_obj: &Vec<u8>) -> libbpf_rs::Object {
    let mut builder = libbpf_rs::ObjectBuilder::default();
    let object = builder
        .open_memory("lwcb", &mem_obj)
        .expect("failed to open object");
    let loaded_object = object
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
