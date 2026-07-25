use std::{path::Path, process::ExitCode};

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest has a parent");

    match blog_gen::generate(root) {
        Ok(count) => {
            println!("Generated {count} post(s)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("blog-gen: {e}");
            ExitCode::FAILURE
        }
    }
}
