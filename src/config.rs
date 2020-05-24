use std::path::PathBuf;

use anyhow::Result;
use clap::Clap;
use serde_derive::Deserialize;

#[derive(Deserialize, Debug, Default)]
pub struct GeoIp {
    #[serde(default, rename = "asn-db")]
    pub asn_db: Option<PathBuf>,
    #[serde(default, rename = "city-db")]
    pub city_db: Option<PathBuf>,
    #[serde(default, rename = "country-db")]
    pub country_db: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Firewall {
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Loki {
    #[serde(rename = "push-url")]
    pub push_url: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    #[serde(default = "default_log_file", rename = "log-file")]
    pub log_file: PathBuf,
    #[serde(default)]
    pub geoip: GeoIp,
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default)]
    pub loki: Loki,
}
impl Config {
    pub fn load(args: &Args) -> Result<Self> {
        let cfg = std::fs::read_to_string(&args.config)?;
        Ok(toml::from_str(&cfg)?)
    }
}

fn default_log_file() -> PathBuf {
    "/var/log/messages".into()
}

/// iptables-to-loki
#[derive(Clap)]
#[clap(version = "1.0", author = "Jordan D. <jordan@doyle.la>")]
pub struct Args {
    /// Names of the iptables rules to watch
    #[clap(short, long)]
    config: PathBuf,
}
