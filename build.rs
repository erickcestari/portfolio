//! Regenerates `static/` from `content/` + `templates/` on every build, so the
//! server never serves HTML that is stale with respect to the sources.

use std::path::Path;

fn main() {
    // Sources of the generated site; touching any of them re-runs this script.
    println!("cargo:rerun-if-changed=content");
    println!("cargo:rerun-if-changed=templates");
    println!("cargo:rerun-if-changed=build.rs");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Err(e) = blog_gen::generate(root) {
        panic!("blog-gen failed: {e}");
    }
}
