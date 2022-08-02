use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    /// Network interface
    #[clap(default_value_t = Ipv4Addr::new(0, 0, 0, 0), short, long, value_parser)]
    pub interface_ip: Ipv4Addr,

    /// Root domain
    #[clap(short, long, value_parser)]
    pub domain: String,

    /// Port to listen on
    #[clap(default_value_t = 53, short, long, value_parser = port_in_range)]
    pub port: u16,

    /// NS records
    #[clap(short, long, value_parser, value_delimiter = ',')]
    pub ns_records: Option<Vec<String>>,

    /// Encode IP addresses for the domain
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
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

const PORT_RANGE: RangeInclusive<usize> = 1..=65535;

fn port_in_range(s: &str) -> std::result::Result<u16, String> {
    let port: usize = s
        .parse()
        .map_err(|_| format!("`{}` isn't a port number", s))?;
    if PORT_RANGE.contains(&port) {
        Ok(port as u16)
    } else {
        Err(format!(
            "Port not in range {}-{}",
            PORT_RANGE.start(),
            PORT_RANGE.end()
        ))
    }
}
