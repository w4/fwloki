#![deny(clippy::all, clippy::pedantic)]

mod config;
mod loki;
mod parser;

use crate::parser::Log;
use bytes::BytesMut;
use chrono::DateTime;
use chrono::Utc;
use clap::Clap;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use log::{debug, error};

use crossbeam_channel::Receiver;
use maxminddb::geoip2;
use notify::{
    event::ModifyKind, immediate_watcher, Event, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use snap::raw::Encoder as SnappyEncoder;

use anyhow::Result;

enum ModifyType {
    Data,
    Rotate,
}

struct LogReader {
    _watcher: RecommendedWatcher,
    reader: BufReader<File>,
    recv: Receiver<ModifyType>,
}

fn open_log_file(path: &Path) -> Result<LogReader> {
    while !path.exists() {
        std::thread::sleep(Duration::new(1, 0));
    }

    // setup an inotify watcher and forward events on to the channel
    let (send, recv) = crossbeam_channel::bounded(0);
    let mut watcher = immediate_watcher(move |e| match e {
        Ok(Event {
            kind: EventKind::Modify(ModifyKind::Data(_)),
            ..
        }) => {
            // we don't really care if the receiever isn't listening on the channel
            let _ = send.try_send(ModifyType::Data);
        }
        Ok(Event {
            kind: EventKind::Modify(ModifyKind::Name(_)),
            ..
        }) => {
            let _ = send.try_send(ModifyType::Rotate);
        }
        Ok(Event { .. }) => {}
        Err(e) => error!("Error watching file: {:?}", e),
    })?;

    watcher.watch(path, RecursiveMode::NonRecursive)?;

    Ok(LogReader {
        _watcher: watcher,
        reader: BufReader::new(File::open(path)?),
        recv,
    })
}

#[derive(Debug)]
struct FirewallEntry<'a> {
    time: &'a DateTime<Utc>,
    hostname: &'a str,
    rule: &'a str,

    interface: &'a str,
    mac: &'a str,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    proto: &'a str,

    asn: Option<u32>,
    asn_org: Option<&'a str>,
    city: Option<&'a str>,
    country_code: Option<&'a str>,
    country: Option<&'a str>,
    lat: Option<f64>,
    lng: Option<f64>,
}
impl<'a> FirewallEntry<'a> {
    fn from(
        log: &'a Log<'a>,
        city: Option<&geoip2::City<'a>>,
        country: Option<&geoip2::Country<'a>>,
        asn: Option<&geoip2::Asn<'a>>,
    ) -> Result<FirewallEntry<'a>> {
        let country = country.and_then(|country| country.country.as_ref());
        let location = city.and_then(|city| city.location.as_ref());

        Ok(FirewallEntry {
            time: &log.time,
            hostname: log.hostname,
            rule: log.rule,

            interface: log.values.get("IN").unwrap_or(&""),
            mac: log.values.get("MAC").unwrap_or(&""),
            src: log.values.get("SRC").unwrap_or(&"").parse()?,
            src_port: log.values.get("SPT").unwrap_or(&"").parse()?,
            dst: log.values.get("DST").unwrap_or(&"").parse()?,
            dst_port: log.values.get("DPT").unwrap_or(&"").parse()?,
            proto: log.values.get("PROTO").unwrap_or(&""),

            asn: asn.and_then(|asn| asn.autonomous_system_number),
            asn_org: asn.and_then(|asn| asn.autonomous_system_organization),
            city: city
                .and_then(|city| city.city.as_ref())
                .and_then(|city| city.names.as_ref())
                .and_then(|names| names.get("en").or_else(|| names.values().next()))
                .copied(),
            country_code: country.and_then(|country| country.iso_code),
            country: country
                .and_then(|country| country.names.as_ref())
                .and_then(|names| names.get("en").or_else(|| names.values().next()))
                .copied(),
            lat: location.and_then(|loc| loc.latitude),
            lng: location.and_then(|loc| loc.longitude),
        })
    }
}
impl Display for FirewallEntry<'_> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            fmt,
            concat!(
                "hostname=\"{}\" rule=\"{}\" interface=\"{}\" mac=\"{}\" src=\"{}\" src_port=\"{}\" ",
                "dst=\"{}\" dst_port=\"{}\" proto=\"{}\" asn=\"{}\" asn_org=\"{}\" city=\"{}\" ",
                "country_code=\"{}\" country=\"{}\" lat=\"{}\" lng=\"{}\"",
            ),
            self.hostname,
            self.rule,
            self.interface,
            self.mac,
            self.src,
            self.src_port,
            self.dst,
            self.dst_port,
            self.proto,
            self.asn.unwrap_or_default(),
            self.asn_org.unwrap_or_default(),
            self.city.unwrap_or_default(),
            self.country_code.unwrap_or_default(),
            self.country.unwrap_or_default(),
            self.lat.unwrap_or_default(),
            self.lng.unwrap_or_default(),
        )
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: config::Args = config::Args::parse();
    let config = match config::Config::load(&args) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to load config file: {}", e);
            std::process::exit(1);
        }
    };

    if !config.log_file.exists() {
        error!("Log file '{}' does not exist.", config.log_file.display());
        std::process::exit(1);
    }

    let open_log_file_or_exit = || match open_log_file(&config.log_file) {
        Ok(v) => v,
        Err(e) => {
            error!(
                "Failed to watch log file '{}': {:?}",
                config.log_file.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let open_geoip_reader = |v: Option<&std::path::PathBuf>| {
        v.map(|v| match maxminddb::Reader::open_mmap(v) {
            Ok(db) => db,
            Err(e) => {
                error!("Failed to load GeoIP DB '{}': {}", v.display(), e);
                std::process::exit(1);
            }
        })
    };

    let asn_db = open_geoip_reader(config.geoip.asn_db.as_ref());
    let city_db = open_geoip_reader(config.geoip.city_db.as_ref());
    let country_db = open_geoip_reader(config.geoip.country_db.as_ref());

    let mut snappy = SnappyEncoder::new();
    let mut encode_buf = BytesMut::new();
    let mut compress_buf = BytesMut::new();

    let mut reader = open_log_file_or_exit();
    let mut buf = String::new();
    let client = reqwest::Client::new();

    let mut entries: Vec<_> = Vec::with_capacity(8);

    loop {
        buf.clear();
        let read_bytes = match reader.reader.read_line(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to read line from file: {:?}", e);
                std::thread::sleep(Duration::new(1, 0));
                continue;
            }
        };

        if read_bytes == 0 {
            // block until we receive a notification from inotify
            match reader.recv.recv() {
                Ok(ModifyType::Data) => {}
                Ok(ModifyType::Rotate) => reader = open_log_file_or_exit(),
                // crossbeam channel disconnected, wait a second before polling file again
                Err(_) => std::thread::sleep(Duration::new(1, 0)),
            }
            continue;
        }

        let (_, log_line) = match parser::parse_log_line(&buf) {
            Ok((_, v)) if !config.firewall.rules.iter().any(|rule| v.rule == rule) => {
                debug!("Non-matching firewall rule: {}", v.rule);
                continue;
            }
            Err(e) => {
                debug!("Non-matching log line: {:?}", e);
                continue;
            }
            Ok(v) => v,
        };

        if let Some(ip) = log_line.values.get("SRC") {
            let ip = if let Ok(ip) = ip.parse() {
                ip
            } else {
                error!("Malformed src ip in iptables logs {}", ip);
                continue;
            };
            let asn: Option<geoip2::Asn> = asn_db.as_ref().and_then(|db| db.lookup(ip).ok());
            let city: Option<geoip2::City> = city_db.as_ref().and_then(|db| db.lookup(ip).ok());
            let country: Option<geoip2::Country> =
                country_db.as_ref().and_then(|db| db.lookup(ip).ok());

            let timestamp = log_line.time.timestamp();
            let entry =
                match FirewallEntry::from(&log_line, city.as_ref(), country.as_ref(), asn.as_ref())
                {
                    Ok(v) => v.to_string(),
                    Err(e) => {
                        error!("Failed to build firewall entry for log: {:?}", e);
                        continue;
                    }
                };

            entries.push((timestamp, entry));

            // once the vec reaches capacity, flush to loki
            if entries.len() == entries.capacity() {
                let req = match crate::loki::create_push_request(
                    &mut snappy,
                    &mut encode_buf,
                    &mut compress_buf,
                    &mut entries,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Error creating a Loki push request: {:?}", e);
                        continue;
                    }
                };

                match client.post(&config.loki.push_url).body(req).send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            error!(
                                "Error pushing log to Loki ({}): {:?}",
                                resp.status(),
                                resp.text().await
                            );
                        }
                    }
                    Err(e) => error!("Error pushing log to Loki: {:?}", e),
                }
            }
        }
    }
}
