use agentsight::config;
use agentsight::http_parser::HTTPParser;
use agentsight::probes::sslsniff::{self, SslSniff};
use agentsight::utils::find_openclaw;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "sslsniff", about = "Sniff SSL/TLS plaintext via eBPF uprobes")]
pub struct Command {
    /// Enable verbose/debug output.
    #[structopt(short, long)]
    verbose: bool,
}

fn main() {
    let opts = Command::from_args();
    config::set_verbose(opts.verbose);

    let mut ssl = SslSniff::new().unwrap();
    let pids = find_openclaw().unwrap();
    for pid in pids {
        ssl.attach_process(pid).unwrap();
    }

    let _stop = ssl.run().unwrap();

    loop {
        if let Some(event) = ssl.recv() {
            if let Some(http_event) = HTTPParser::handle_ssl_event(&event, false) {
                println!("{:?}", http_event);
            }
        }
    }
}
