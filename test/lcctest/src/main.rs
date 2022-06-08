mod config;
mod host;
use anyhow::Result;
use config::Config;
use host::Host;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Command {
    /// Verbose debug output
    #[structopt(short, long, help = "verbose output")]
    verbose: bool,
    #[structopt(short, long, help = "configuration file path")]
    config: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = Command::from_args();

    let mut hosts = Vec::new();
    let hostconfig = Config::from_file(&opts.config)?;

    for hc in hostconfig.host {
        let mut host = Host::new(hc);
        host.build_connect()?;
        println!("{:?}", host.execute_command(&hostconfig.cmd)?);
        hosts.push(host);
    }

    Ok(())
}
