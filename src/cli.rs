use clap::{Parser, Subcommand};
use core::ops::RangeInclusive;
use std::net::Ipv4Addr;
use trust_dns_proto::rr::Name;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Network interface
    #[clap(default_value_t = Ipv4Addr::new(0, 0, 0, 0), short, long, value_parser)]
    pub(crate) interface_ip: Ipv4Addr,

    /// Root domain
    #[clap(short, long, value_parser)]
    pub(crate) domain: String,

    /// Port to listen on
    #[clap(default_value_t = 53, short, long, value_parser = port_in_range)]
    pub(crate) port: u16,

    /// NS records (SOA record also points here)
    #[clap(short, long, value_parser, value_delimiter = ',')]
    pub(crate) ns_records: Option<Vec<Name>>,

    /// Public IP address
    #[clap(long, value_parser)]
    pub(crate) ns_public_ip: Option<Ipv4Addr>,

    /// Encode IP addresses for the domain
    #[clap(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// does testing things
    Encode {
        /// primary IP address to encode
        #[clap(short, long, value_parser)]
        primary: Ipv4Addr,

        /// secondary IP address to encode
        #[clap(short, long, value_parser)]
        secondary: Ipv4Addr,
    },
}

const PORT_RANGE: RangeInclusive<u16> = 1..=0xFFFF;

fn port_in_range(s: &str) -> core::result::Result<u16, String> {
    let port: u16 = s
        .parse()
        .map_err(|e| -> String { format!("`{}` isn't a port number: {}", s, e) })?;
    if PORT_RANGE.contains(&port) {
        Ok(port)
    } else {
        Err(format!(
            "Port not in range {}-{}",
            PORT_RANGE.start(),
            PORT_RANGE.end()
        ))
    }
}
