use agentsight::probes::sslsniff::{self, SslSniff};
use agentsight::config;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "sslsniff", about = "Sniff SSL/TLS plaintext via eBPF uprobes")]
pub struct Command {
    /// PID of the process to trace.
    #[structopt(short, long)]
    pid: i32,
    /// Enable verbose/debug output.
    #[structopt(short, long)]
    verbose: bool,
}

fn main() {
    let opts = Command::from_args();
    config::set_verbose(opts.verbose);


    let mut ssl = SslSniff::new().unwrap();
    ssl.attach_process(opts.pid).unwrap();

    let _stop = ssl.run().unwrap();

    loop {
        if let Some(event) = ssl.recv() {
            println!("{:?}", event);
        }
    }
}
