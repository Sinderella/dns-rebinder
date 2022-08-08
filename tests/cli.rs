#[cfg(test)]
mod tests {
    use assert_cmd::prelude::*; // Add methods on commands
    use predicates::prelude::*; // Used for writing assertions
    use std::process::{Child, Command}; // Run programs

    struct ChildCleanup(Child);

    impl Drop for ChildCleanup {
        fn drop(&mut self) {
            self.0.kill().unwrap();
        }
    }

    #[test]
    fn run_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME"))?;

        cmd.args([
            "-d",
            "rebnd.icu",
            "encode",
            "-p",
            "127.0.0.1",
            "-s",
            "192.168.1.1",
        ]);

        cmd.assert()
            .success()
            .stdout(predicate::str::contains("7f000001.c0a80101.rebnd.icu"));

        Ok(())
    }

    #[test]
    fn run_server() -> Result<(), Box<dyn std::error::Error>> {
        let domain = "rebnd.icu";
        let ns_record1 = "ns1.rebnd.icu";
        let ns_record2 = "ns2.rebnd.icu";
        let ns_public_ip = "49.12.76.13";

        let primary = "127.0.0.1";
        let secondary = "192.168.1.1";
        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();

        let _child = ChildCleanup(
            cmd.args([
                "-p",
                "2053",
                "-d",
                domain,
                "-n",
                &format!("{},{}", ns_record1, ns_record2),
                "--ns-public-ip",
                ns_public_ip,
            ])
            .spawn()
            .unwrap(),
        );

        Command::new("dig")
            .args(["@0", "-p", "2053", domain, "ns", "+short"])
            .assert()
            .stdout(predicate::str::starts_with(format!(
                "{}.\n{}.",
                ns_record1, ns_record2
            )))
            .success();

        Command::new("dig")
            .args(["@0", "-p", "2053", ns_record1, "a", "+short"])
            .assert()
            .stdout(predicate::str::starts_with(ns_public_ip.to_string()))
            .success();

        Command::new("dig")
            .args(["@0", "-p", "2053", ns_record2, "a", "+short"])
            .assert()
            .stdout(predicate::str::starts_with(ns_public_ip.to_string()))
            .success();

        let output_v8 = cmd
            .args(["-d", domain, "encode", "-p", primary, "-s", secondary])
            .output()?
            .stdout;
        let output = std::str::from_utf8(&output_v8)?;
        let encoded_domain = output.split_whitespace().last().unwrap();

        Command::new("dig")
            .args(["@0", "-p", "2053", encoded_domain, "a", "+short"])
            .assert()
            .stdout(predicate::str::starts_with(primary).or(predicate::str::starts_with(secondary)))
            .success();

        Ok(())
    }
}
