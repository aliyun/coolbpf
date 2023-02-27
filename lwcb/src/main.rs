use std::fs::read_to_string;
use std::path::PathBuf;

use anyhow::Result;
use lwcb::LwCB;

use libfirm_rs::init_libfirm;
use structopt::StructOpt;
mod utils;

#[derive(Debug, StructOpt)]
#[structopt(name = "lwbt", about = "LightWeight eBPF Tracing")]
pub struct Command {
    #[structopt(help = "The path of script file")]
    script: Option<String>,

    #[structopt(long, short, help = "Raw text")]
    text: Option<String>,

    #[structopt(
        long,
        parse(from_os_str),
        help = "Folder path to save intermediate code files"
    )]
    irdump: Option<PathBuf>,

    #[structopt(
        long,
        parse(from_os_str),
        help = "Folder path to save lower intermediate code files"
    )]
    lirdump: Option<PathBuf>,

    #[structopt(long, help = "Dump bpf instruction")]
    bpfdump: Option<String>,

    #[structopt(long, help = "Dump ast")]
    astdump: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = Command::from_args();
    let content;
    if let Some(p) = opts.script {
        content = Some(read_to_string(&p)?);
    } else if let Some(t) = opts.text {
        content = Some(t.clone());
    } else {
        content = None;
    }

    let mut lwbt = LwCB::new();

    if let Some(p) = opts.irdump {
        lwbt.set_irdump(p);
    }

    if let Some(p) = opts.lirdump {
        lwbt.set_lirdump(p);
    }

    lwbt.set_astdump(opts.astdump);

    if let Some(c) = content {
        lwbt.compile(&c)?;
        lwbt.generate_bytecode()?;

        lwbt.attach()?;

        lwbt.poll();
    }
    Ok(())
}
