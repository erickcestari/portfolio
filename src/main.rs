use std::net::TcpListener;
use featherserve::Featherserve;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:9999").unwrap();

    Featherserve::new(listener)
        .with_static_dir("pages")
        .with_threads(8)
        .run();
}