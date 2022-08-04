#![warn(
    clippy::dbg_macro,
    clippy::unimplemented,
    missing_copy_implementations,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]

use crate::cli::Cli;
use crate::cli::Commands;

use clap::Parser;
use env_logger::Builder;
use log::LevelFilter;
use log::{error, info, warn};
use rand::Rng;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::rdata::SOA;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

mod cli;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

struct Rebinder {
    domain: String,
    ns_records: Option<Vec<Name>>,
    ns_public_ip: Option<Ipv4Addr>,
}

impl Rebinder {
    pub(crate) fn new(
        domain: String,
        ns_records: Option<Vec<Name>>,
        ns_public_ip: Option<Ipv4Addr>,
    ) -> Rebinder {
        Rebinder {
            domain,
            ns_records,
            ns_public_ip,
        }
    }

    fn process_query(
        &mut self,
        query: &Query,
        addr: SocketAddr,
        header_id: u16,
    ) -> Option<Vec<Record>> {
        let mut records: Vec<Record> = Vec::new();
        let qname = query
            .name()
            .to_ascii()
            .strip_suffix('.')?
            .to_ascii_lowercase();

        // only support the root domain that it owns
        if !qname.ends_with(&self.domain) {
            return None;
        }

        match query.query_type() {
            RecordType::A => {
                // accepting <primary>.<secondary>.<optional>.root.domain
                let parts: Vec<&str> = qname.split('.').collect();

                if parts[0].starts_with("ns") {
                    if let Some(ns_public_ip) = self.ns_public_ip {
                        records.push(Record::from_rdata(
                            query.name().clone(),
                            600,
                            RData::A(ns_public_ip),
                        ));
                        return Some(records);
                    }
                }

                let primary = u32::from_str_radix(parts[0], 16).unwrap();
                let secondary = u32::from_str_radix(parts[1], 16).unwrap();

                info!(
                    "{:?}[{:?}] - parsed targets: primary: {:#?}, secondary: {:#?}",
                    addr,
                    header_id,
                    Ipv4Addr::from(primary),
                    Ipv4Addr::from(secondary)
                );

                if primary.eq(&secondary) {
                    warn!(
                    "{:?}[{:?}] - primary and secondary labels are indentical, possibly an abuse",
                    addr, header_id
                );
                    return None;
                }

                let mut rng = rand::thread_rng();
                let is_primary = rng.gen_range(0..2) % 2 == 0;

                records.push(Record::from_rdata(
                    query.name().clone(),
                    1,
                    RData::A(match is_primary {
                        true => Ipv4Addr::from(primary),
                        false => Ipv4Addr::from(secondary),
                    }),
                ));

                return Some(records);
            }
            RecordType::NS => match &self.ns_records {
                Some(ns_records) => {
                    for ns_record in ns_records {
                        records.push(Record::from_rdata(
                            Name::from_ascii(qname.clone()).unwrap(),
                            600,
                            RData::NS(ns_record.clone()),
                        ));
                    }
                    return Some(records);
                }
                None => {}
            },
            RecordType::SOA => {
                let ns_record = self.ns_records.as_ref().unwrap().first()?;

                let soa = SOA::new(
                    ns_record.clone(),
                    Name::from_ascii("").unwrap(),
                    1,
                    86400,
                    7200,
                    4000000,
                    600,
                );

                records.push(Record::from_rdata(
                    Name::from_ascii(qname).unwrap(),
                    600,
                    RData::SOA(soa),
                ));

                return Some(records);
            }
            RecordType::AAAA => return None,
            RecordType::ANY => return None,
            RecordType::AXFR => return None,
            RecordType::CNAME => return None,
            _ => return None,
        }

        None
    }

    pub(crate) fn handle_query(&mut self, socket: &UdpSocket) -> Result<()> {
        let mut buffer = [0_u8; 512];
        let (len, addr) = socket.recv_from(&mut buffer).expect("receive failed");
        let request = Message::from_vec(&buffer[0..len]).expect("failed parse of request");

        let mut message = Message::new();
        message.set_id(request.id());
        message.set_recursion_desired(request.recursion_desired());
        message.set_recursion_available(false);

        // unlikely, see https://stackoverflow.com/a/4083071
        if request.query_count() != 1 {
            let bytes = message.to_vec().unwrap();
            socket.send_to(&bytes, addr).expect("send failed");
            return Ok(());
        }

        if let Some(query) = request.queries().first() {
            info!("{:?}[{:?}] - {:?}", addr, request.id(), query);
            message.add_query(query.clone());
            if let Some(records) = self.process_query(query, addr, request.id()) {
                info!("{:?}[{:?}] - {:?}", addr, request.id(), records);
                message.add_answers(records);
            }
        } else {
            let bytes = message.to_vec().unwrap();
            socket.send_to(&bytes, addr).expect("send failed");
            return Ok(());
        }

        let bytes = message.to_vec().unwrap();
        socket.send_to(&bytes, addr).expect("send failed");

        Ok(())
    }
}

fn main() -> Result<()> {
    Builder::new().filter_level(LevelFilter::Debug).init();
    let cli = Cli::parse();

    let domain = cli.domain.to_ascii_lowercase();
    let port = cli.port;
    let network_interface = cli.interface_ip;
    let ns_records = cli.ns_records;
    let ns_public_ip = cli.ns_public_ip;

    if let Some(Commands::Encode { primary, secondary }) = &cli.command {
        println!(
            "Domain: {}, Primary: {:?}, Secondary: {:?}",
            domain, primary, secondary
        );
        let encoded_primary = hex::encode(&primary.octets());
        let encoded_secondary = hex::encode(&secondary.octets());

        println!(
            "Encoded: {}.{}.{}",
            encoded_primary, encoded_secondary, domain
        );
        return Ok(());
    }

    info!(
        "starting with (domain: {:?}, port: {:?}, interface ip: {:?}, ns records: {:?})",
        domain, port, network_interface, ns_records
    );

    let socket = UdpSocket::bind((network_interface, port))?;
    info!("started listening on port: {:?}", port);

    let mut rebinder = Rebinder::new(domain, ns_records, ns_public_ip);

    let handler = std::thread::Builder::new()
        .name("rebinder:server".to_string())
        .spawn(move || loop {
            match rebinder.handle_query(&socket) {
                Ok(_) => {}
                Err(e) => error!("An error occurred: {}", e),
            }

            std::thread::yield_now();
        })?;

    handler.join().unwrap();

    Ok(())
}
