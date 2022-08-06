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
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::rdata::SOA;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

mod cli;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

fn process_query(
    domain: &str,
    ns_records: &Option<Vec<Name>>,
    ns_public_ip: &Option<Ipv4Addr>,
    query: &Query,
    addr: &SocketAddr,
    header_id: u16,
) -> Result<Vec<Record>> {
    let mut records: Vec<Record> = Vec::new();
    let qname = match query.name().to_ascii().strip_suffix('.') {
        Some(it) => it,
        None => return Ok(records),
    }
    .to_ascii_lowercase();

    // only support the root domain that it owns
    if !qname.ends_with(domain) {
        return Ok(records);
    }

    match query.query_type() {
        RecordType::A => {
            // accepting <primary>.<secondary>.<optional>.root.domain
            let parts: Vec<&str> = qname.split('.').collect();

            if parts[0].starts_with("ns") {
                if let Some(ns_public_ip) = ns_public_ip.as_ref() {
                    records.push(Record::from_rdata(
                        query.name().clone(),
                        600,
                        RData::A(*ns_public_ip),
                    ));
                    return Ok(records);
                }
            }

            if qname.eq(domain) {
                return Ok(records);
            }

            if qname.matches('.').count() != domain.matches('.').count() + 2 {
                return Ok(records);
            }

            let loopback = u32::from_be_bytes(Ipv4Addr::new(127, 0, 0, 1).octets());

            let primary = match u32::from_str_radix(parts[0], 16) {
                Ok(decoded) => decoded,
                Err(_) => return Ok(records),
            };
            let secondary = match u32::from_str_radix(parts[1], 16) {
                Ok(decoded) => decoded,
                Err(_) => return Ok(records),
            };

            info!(
                "{:?}[{:?}] - parsed targets: primary: {:#?}, secondary: {:#?}",
                addr,
                header_id,
                Ipv4Addr::from(primary),
                Ipv4Addr::from(secondary)
            );

            if primary.eq(&secondary) && primary.ne(&loopback) {
                warn!(
                    "{:?}[{:?}] - primary and secondary labels are indentical, possibly an abuse",
                    addr, header_id
                );
                return Ok(records);
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

            Ok(records)
        }
        RecordType::NS => match ns_records {
            Some(ns_records) => {
                for ns_record in ns_records {
                    records.push(Record::from_rdata(
                        Name::from_ascii(qname.clone()).unwrap(),
                        600,
                        RData::NS(ns_record.clone()),
                    ));
                }
                Ok(records)
            }
            None => Ok(records),
        },
        RecordType::SOA => {
            let ns_record = ns_records.as_deref().unwrap().first().unwrap();

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

            Ok(records)
        }
        RecordType::AAAA => Ok(records),
        RecordType::ANY => Ok(records),
        RecordType::AXFR => Ok(records),
        RecordType::CNAME => Ok(records),
        _ => Ok(records),
    }
}

pub(crate) async fn handle_connection(
    socket: &UdpSocket,
    domain: &str,
    ns_records: &Option<Vec<Name>>,
    ns_public_ip: &Option<Ipv4Addr>,
) -> Result<()> {
    let mut buffer = [0_u8; 512];
    let (len, addr) = socket.recv_from(&mut buffer).await.expect("receive failed");
    let request = Message::from_vec(&buffer[0..len]).expect("failed parse of request");

    let mut message = Message::new();
    message.set_id(request.id());
    message.set_recursion_desired(request.recursion_desired());
    message.set_recursion_available(false);

    // unlikely, see https://stackoverflow.com/a/4083071
    if request.query_count() != 1 {
        let bytes = message.to_vec().unwrap();
        socket.send_to(&bytes, addr).await.expect("send failed");
        return Ok(());
    }

    if let Some(query) = request.queries().first() {
        info!("{:?}[{:?}] - {:?}", addr, request.id(), query);
        message.add_query(query.clone());
        let records = process_query(domain, ns_records, ns_public_ip, query, &addr, request.id())?;
        info!("{:?}[{:?}] - {:?}", addr, request.id(), records);
        message.add_answers(records);
    }

    let bytes = message.to_vec().unwrap();
    socket.send_to(&bytes, addr).await.expect("send failed");

    Ok(())
}

#[tokio::main()]
async fn main() -> Result<()> {
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

    let socket = UdpSocket::bind((network_interface, port))
        .await
        .expect("couldn't bind to address");
    info!("started listening on port: {:?}", port);

    let s = Arc::new(socket);
    let d = Arc::new(domain);
    let nsr = Arc::new(ns_records);
    let npip = Arc::new(ns_public_ip);

    loop {
        let sock_param = Arc::clone(&s);
        let domain_param = Arc::clone(&d);
        let ns_records_param = Arc::clone(&nsr);
        let ns_public_ip_param = Arc::clone(&npip);

        let handler = tokio::spawn(async move {
            match handle_connection(
                &sock_param,
                &domain_param,
                &ns_records_param,
                &ns_public_ip_param,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => error!("{}", e),
            }
        });

        match handler.await {
            Ok(_) => {}
            Err(e) => error!("{}", e),
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
