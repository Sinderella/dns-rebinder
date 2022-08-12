use core::fmt;
use core::num::ParseIntError;
use std::error;
use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
pub(crate) struct IP;

#[derive(Debug, Clone)]
pub(crate) struct DecodeError {
    kind: String,
    message: String,
}

impl error::Error for DecodeError {}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "incorrect format, multi-level subdomain is required")
    }
}

impl From<ParseIntError> for DecodeError {
    fn from(error: ParseIntError) -> Self {
        DecodeError {
            kind: String::from("parse"),
            message: error.to_string(),
        }
    }
}

impl IP {
    pub(crate) fn encode(primary: Ipv4Addr, secondary: Ipv4Addr, domain: &str) -> String {
        let encoded_primary = hex::encode(&primary.octets());
        let encoded_secondary = hex::encode(&secondary.octets());

        format!("{}.{}.{}", encoded_primary, encoded_secondary, domain)
    }

    pub(crate) fn decode(encoded_domain: &str) -> Result<(Ipv4Addr, Ipv4Addr), DecodeError> {
        if encoded_domain.matches('.').count() < 2 {
            return Err(DecodeError {
                kind: "input".to_owned(),
                message: "requires multi-level subdomain".to_owned(),
            });
        }
        let parts: Vec<&str> = encoded_domain.split('.').collect();

        let primary_part = match parts.first() {
            Some(part) => part,
            None => {
                return Err(DecodeError {
                    kind: "input".to_owned(),
                    message: "requires multi-level subdomain".to_owned(),
                })
            }
        };
        let primary =
            Ipv4Addr::from(
                u32::from_str_radix(primary_part, 16).map_err(|e| DecodeError {
                    kind: "parse".to_owned(),
                    message: format!("unable to decode: {}", e),
                })?,
            );
        let secondary_part = match parts.get(1) {
            Some(part) => part,
            None => {
                return Err(DecodeError {
                    kind: "input".to_owned(),
                    message: "requires multi-level subdomain".to_owned(),
                })
            }
        };
        let secondary =
            Ipv4Addr::from(
                u32::from_str_radix(secondary_part, 16).map_err(|e| DecodeError {
                    kind: "parse".to_owned(),
                    message: format!("unable to decode: {}", e),
                })?,
            );

        Ok((primary, secondary))
    }
}

#[cfg(test)]
mod tests {
    use crate::ip::IP;
    use std::net::Ipv4Addr;

    use super::DecodeError;

    #[test]
    fn test_ipencoding() {
        let primary = Ipv4Addr::new(127, 0, 0, 1);
        let secondary = Ipv4Addr::new(192, 168, 1, 1);
        let domain = "rebnd.icu";

        assert_eq!(
            IP::encode(primary, secondary, domain),
            "7f000001.c0a80101.rebnd.icu"
        );
    }

    #[test]
    fn test_ipdecoding() -> Result<(), DecodeError> {
        let encoded_domain = "7f000001.c0a80101.rebnd.icu";

        let primary = Ipv4Addr::new(127, 0, 0, 1);
        let secondary = Ipv4Addr::new(192, 168, 1, 1);

        let (primary_decoded, secondary_decoded) = match IP::decode(encoded_domain) {
            Ok((primary_decoded, secondary_decoded)) => (primary_decoded, secondary_decoded),
            Err(e) => return Err(e),
        };
        assert_eq!(primary, primary_decoded);
        assert_eq!(secondary, secondary_decoded);

        Ok(())
    }
}
