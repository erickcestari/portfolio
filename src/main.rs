use featherserve::Featherserve;

fn main() {
    Featherserve::new()
        .with_static_dir("pages")
        .with_threads(8)
        .bind_http("0.0.0.0:8080")
        .unwrap()
        .bind_https("0.0.0.0:8443", "./example/cert.pem", "./example/key.pem")
        .unwrap()
        .run();
}
