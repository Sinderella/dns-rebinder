use dns_rebinder::run;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    run().await
}
