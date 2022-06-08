use anyhow::{bail, Result};
use serde_derive::{Deserialize, Serialize};
use ssh2::Session;
use std::io::prelude::*;
use std::net::TcpStream;

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct HostConfig {
    pub name: String,
    pub ip: String,
    pub port: Option<usize>,
    pub usr: String,
    pub pwd: String,
}

impl HostConfig {
    pub fn get_addr(&self) -> String {
        let mut port = 22;
        if let Some(x) = self.port {
            port = x;
        }
        format!("{}:{}", self.ip, port)
    }

    pub fn get_identifier(&self) -> String {
        format!("{}-{}", self.name, self.ip)
    }
}


pub struct Host {
    hc: HostConfig,
    session: Option<Session>,
}

impl Host {
    pub fn new(hc: HostConfig) -> Host {
        Host { hc, session: None }
    }

    pub fn build_connect(&mut self) -> Result<()> {
        if self.session.is_none() {
            let tcp = TcpStream::connect(self.hc.get_addr())?;
            let mut sess = Session::new()?;
            sess.set_tcp_stream(tcp);
            sess.handshake()?;
            sess.userauth_password(&self.hc.usr, &self.hc.pwd)?;
            self.session = Some(sess);
        }
        log::debug!(
            "{}: connect to host successfully.",
            self.hc.get_identifier()
        );
        Ok(())
    }

    pub fn execute_command(&mut self, cmd: &str) -> Result<(i32, String)> {
        log::debug!("{}: try to run command: {}", self.hc.get_identifier(), cmd);
        if let Some(session) = &mut self.session {
            let mut channel = session.channel_session()?;
            channel.exec(cmd)?;
            let mut s = String::new();
            channel.read_to_string(&mut s).unwrap();
            channel.wait_close()?;
            let code = channel.exit_status()?;
            return Ok((code, s));
        }
        bail!("{}: Not connect", self.hc.get_identifier())
    }
}


