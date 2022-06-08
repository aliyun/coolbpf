use crate::host::HostConfig;
use anyhow::{bail, Result};
use serde_derive::{Deserialize, Serialize};

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct Config {
    pub path: String,
    pub cmd: String,
    pub host: Vec<HostConfig>,
}

impl Config {
    pub fn from_str(s: &str) -> Result<Config> {
        match toml::from_str(s) {
            Ok(x) => Ok(x),
            Err(y) => bail!("str to HostConfigContainer failed: {}", y),
        }
    }

    pub fn from_file(path: &String) -> Result<Config> {
        let contents =
            std::fs::read_to_string(path).expect("Something went wrong reading config file");
        Config::from_str(&contents[..])
    }
}
