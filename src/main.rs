use featherserve::{Config, Featherserve};

fn main() {
    let config = Config::from_env();
    let server = Featherserve::from(config);

    server.run();
}
