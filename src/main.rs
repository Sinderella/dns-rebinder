// modified from https://github.com/EmilHernvall/dnsguide

extern crate log;

use crate::cli::Cli;
use crate::cli::Commands;

use clap::Parser;
use dns_rebinder::{BytePacketBuffer, DnsRecord};
use dns_rebinder::{DnsPacket, QueryType, ResultCode};
use env_logger::Builder;
use log::LevelFilter;
use log::{error, info, warn};
use rand::Rng;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr};

mod cli;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

struct Rebinder {
    domain: String,
    ns_records: Option<Vec<String>>,
    ns_public_ip: Option<Ipv4Addr>,
}

impl Rebinder {
    pub fn new(
        domain: String,
        ns_records: Option<Vec<String>>,
        ns_public_ip: Option<Ipv4Addr>,
    ) -> Rebinder {
        Rebinder {
            domain,
            ns_records,
            ns_public_ip,
        }
    }

    pub fn rebind(
        &mut self,
        qname: &str,
        qtype: QueryType,
        src_ip: IpAddr,
        header_id: u16,
    ) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();

        match qtype {
            QueryType::A => {
                if !qname.to_string().ends_with(&self.domain) {
                    packet.header.rescode = ResultCode::REFUSED;
                    return Ok(packet);
                }
                // accepting <primary>.<secondary>.<optional>.root.domain
                let parts: Vec<&str> = qname.split('.').collect();

                if parts[0].starts_with("ns") {
                    if let Some(ns_public_ip) = self.ns_public_ip {
                        packet.answers.push(DnsRecord::A {
                            domain: qname.to_string(),
                            addr: ns_public_ip,
                            ttl: 300,
                        });
                        return Ok(packet);
                    }
                }

                let primary = u32::from_str_radix(parts[0], 16)?;
                let secondary = u32::from_str_radix(parts[1], 16)?;
                info!(
                    "{:?}[{:?}] - parsed targets: primary: {:#?}, secondary: {:#?}",
                    src_ip,
                    header_id,
                    Ipv4Addr::from(primary),
                    Ipv4Addr::from(secondary)
                );

                if primary.eq(&secondary) {
                    warn!(
                    "{:?}[{:?}] - primary and secondary labels are indentical, possibly an abuse",
                    src_ip, header_id
                );
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    return Ok(packet);
                }

                let mut rng = rand::thread_rng();
                let is_primary = rng.gen_range(0..2) % 2 == 0;

                packet.header.rescode = ResultCode::NOERROR;
                packet.answers.push(DnsRecord::A {
                    domain: qname.to_string(),
                    addr: match is_primary {
                        true => Ipv4Addr::from(primary),
                        false => Ipv4Addr::from(secondary),
                    },
                    ttl: 1,
                });

                Ok(packet)
            }
            QueryType::NS => {
                if !qname.to_string().ends_with(&self.domain) {
                    packet.header.rescode = ResultCode::REFUSED;
                    return Ok(packet);
                }

                match &self.ns_records {
                    Some(ns_records) => {
                        for ns_record in ns_records {
                            packet.answers.push(DnsRecord::NS {
                                domain: self.domain.clone(),
                                host: ns_record.to_string(),
                                ttl: 300,
                            })
                        }
                    }
                    None => {}
                }

                Ok(packet)
            }
            _ => {
                info!(
                    "{:?}[{:?}] unsupported query ({:?})",
                    src_ip, header_id, qtype
                );
                packet.header.rescode = ResultCode::NOERROR;

                Ok(packet)
            }
        }
    }

    pub fn handle_query(&mut self, socket: &UdpSocket) -> Result<()> {
        // With a socket ready, we can go ahead and read a packet. This will
        // block until one is received.
        let mut req_buffer = BytePacketBuffer::new();

        // The `recv_from` function will write the data into the provided buffer,
        // and return the length of the data read as well as the source address.
        // We're not interested in the length, but we need to keep track of the
        // source in order to send our reply later on.
        let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

        // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
        // a `DnsPacket`.
        let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

        // Create and initialize the response packet
        let mut response = DnsPacket::new();
        response.header.id = request.header.id;
        response.header.recursion_desired = false;
        response.header.recursion_available = false;
        response.header.response = true;

        // In the normal case, exactly one question is present
        if let Some(question) = request.questions.pop() {
            info!(
                "{:?}[{:?}] - received query: {:?}",
                src.ip(),
                request.header.id,
                question
            );

            // Since all is set up and as expected, the query can be forwarded to the
            // target server. There's always the possibility that the query will
            // fail, in which case the `SERVFAIL` response code is set to indicate
            // as much to the client. If rather everything goes as planned, the
            // question and response records as copied into our response packet.
            if let Ok(result) =
                self.rebind(&question.name, question.qtype, src.ip(), request.header.id)
            {
                response.questions.push(question);
                response.header.rescode = result.header.rescode;

                for rec in result.answers {
                    info!(
                        "{:?}[{:?}] - answer: {:?}",
                        src.ip(),
                        request.header.id,
                        rec
                    );
                    response.answers.push(rec);
                }
                for rec in result.authorities {
                    info!(
                        "{:?}[{:?}] - authority: {:?}",
                        src.ip(),
                        request.header.id,
                        rec
                    );
                    response.authorities.push(rec);
                }
                for rec in result.resources {
                    info!(
                        "{:?}[{:?}] - resources: {:?}",
                        src.ip(),
                        request.header.id,
                        rec
                    );
                    response.resources.push(rec);
                }
            } else {
                response.header.rescode = ResultCode::SERVFAIL;
            }
        }
        // Being mindful of how unreliable input data from arbitrary senders can be, we
        // need make sure that a question is actually present. If not, we return `FORMERR`
        // to indicate that the sender made something wrong.
        else {
            response.header.rescode = ResultCode::FORMERR;
        }

        // The only thing remaining is to encode our response and send it off!
        let mut res_buffer = BytePacketBuffer::new();
        response.write(&mut res_buffer)?;

        let len = res_buffer.pos();
        let data = res_buffer.get_range(0, len)?;

        socket.send_to(data, src)?;

        Ok(())
    }
}

fn main() -> Result<()> {
    Builder::new().filter_level(LevelFilter::Info).init();
    let cli = Cli::parse();

    let domain = cli.domain;
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

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match rebinder.handle_query(&socket) {
            Ok(_) => {}
            Err(e) => error!("An error occurred: {}", e),
        }
    }
}
