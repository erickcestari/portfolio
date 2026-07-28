use jatai::{Config, JataiBuilder};

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let builder = JataiBuilder::from(config);
    let server = builder.build().await.expect("Failed to build server");

    server.run().await;
}
