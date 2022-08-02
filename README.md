# DNS Rebinder [![Rust](https://github.com/Sinderella/dns-rebinder/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/Sinderella/dns-rebinder/actions/workflows/rust.yml)

A DNS rebinder tool written in Rust. The idea is taken from [rbndr](https://github.com/taviso/rbndr) and most of the implementation is taken from [dnsguide](https://github.com/EmilHernvall/dnsguide/).

> Note: This is created for educational and research purposes. As such, it is stil in an experimental stage.

## Public Instance

My personal setup is hosted on the [rebnd.icu]() domain. It is not intended for public use as I am not confident in the stability of the application.

## Build

[Rust](https://www.rust-lang.org/learn/get-started) is required to build.

```bash
$ cargo b -r
```

## Usage

```
$ dns-rebinder -h
dns-rebinder 0.1.0
sinderella

USAGE:
    dns-rebinder [OPTIONS] --domain <DOMAIN> [SUBCOMMAND]

OPTIONS:
    -d, --domain <DOMAIN>                Root domain
    -h, --help                           Print help information
    -i, --interface-ip <INTERFACE_IP>    Network interface [default: 0.0.0.0]
    -n, --ns-records <NS_RECORDS>        NS records
    -p, --port <PORT>                    Port to listen on [default: 53]
    -V, --version                        Print version information

SUBCOMMANDS:
    encode    does testing things
    help      Print this message or the help of the given subcommand(s)

```

Encode IP addresses:

```
$ ./dns-rebinder -d rebnd.icu encode -p 127.0.0.1 -s 192.168.1.1
Domain: rebnd.icu, Primary: 127.0.0.1, Secondary: 192.168.1.1
Encoded: 7f000001.c0a80101.rebnd.icu
```

Serve the DNS:

```
# dns-rebinder -d rebnd.icu
[2022-08-02T11:37:05Z INFO  dns_rebinder] starting with (domain: "rebnd.icu", port: 53, interface ip: 0.0.0.0, ns records: None)
[2022-08-02T11:37:05Z INFO  dns_rebinder] started listening on port: 53
```
