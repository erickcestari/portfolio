use featherserve::{Config, FeatherserveBuilder};

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let builder = FeatherserveBuilder::from(config);
    let server = builder.build().await.expect("Failed to build server");

    server.run().await;
}
