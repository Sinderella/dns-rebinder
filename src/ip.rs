use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
pub(crate) struct IP {}

impl IP {
    pub(crate) fn encode(primary: &Ipv4Addr, secondary: &Ipv4Addr, domain: &str) -> String {
        let encoded_primary = hex::encode(&primary.octets());
        let encoded_secondary = hex::encode(&secondary.octets());

        format!("{}.{}.{}", encoded_primary, encoded_secondary, domain)
    }

    pub(crate) fn decode(
        encoded_domain: &str,
    ) -> Result<(Ipv4Addr, Ipv4Addr), Box<dyn std::error::Error>> {
        if encoded_domain.matches('.').count() < 2 {
            panic!("incorrect format, multi-level subdomain is required");
        }
        let parts: Vec<&str> = encoded_domain.split('.').collect();

        let primary = Ipv4Addr::from(u32::from_str_radix(parts[0], 16).unwrap());
        let secondary = Ipv4Addr::from(u32::from_str_radix(parts[1], 16).unwrap());

        Ok((primary, secondary))
    }
}

#[cfg(test)]
mod tests {
    use crate::ip::IP;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipencoding() -> Result<(), Box<dyn std::error::Error>> {
        let primary = Ipv4Addr::new(127, 0, 0, 1);
        let secondary = Ipv4Addr::new(192, 168, 1, 1);
        let domain = "rebnd.icu";

        assert_eq!(
            IP::encode(&primary, &secondary, domain),
            "7f000001.c0a80101.rebnd.icu"
        );

        Ok(())
    }

    #[test]
    fn test_ipdecoding() -> Result<(), Box<dyn std::error::Error>> {
        let encoded_domain = "7f000001.c0a80101.rebnd.icu";

        let primary = Ipv4Addr::new(127, 0, 0, 1);
        let secondary = Ipv4Addr::new(192, 168, 1, 1);

        let (primary_decoded, secondary_decoded) = IP::decode(encoded_domain).unwrap();
        assert_eq!(primary, primary_decoded);
        assert_eq!(secondary, secondary_decoded);

        Ok(())
    }
}
