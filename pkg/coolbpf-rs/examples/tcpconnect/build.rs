use coolbpf_builder::CoolBPFBuilder;

fn main() {
    CoolBPFBuilder::default()
        .source("src/bpf/tcpconnect.bpf.c")
        .header("src/bpf/tcpconnect.h")
        .build()
        .expect("Failed to compile tcpconnect eBPF program");
}
