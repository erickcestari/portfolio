alias b := build
alias bl := blog
alias c := check
alias d := delete
alias f := fmt
alias r := run
alias t := test
alias w := wasm

_default:
    @just --list

# Build
build:
    cargo build

# Generate blog HTML from content/blog/*.md
blog:
    cargo run -p blog-gen --release

# Check code: formatting, compilation, linting, and commit signature
check:
    cargo +nightly fmt --all -- --check
    cargo check
    cargo clippy --workspace --all-targets -- -D warnings

# Delete files: example, target, lockfile
delete item="examples":
    just _delete-{{ item }}

# Format code
fmt:
    cargo +nightly fmt --all

run: wasm
    cargo run

test:
    cargo test --workspace

# Build the CHIP-8 WebAssembly module played on the 404 page
wasm:
    cargo build -p chip8-wasm --profile wasm --target wasm32-unknown-unknown
    cp target/wasm32-unknown-unknown/wasm/chip8_wasm.wasm static/chip8/chip8.wasm

_delete-target:
    rm -rf target/

_delete-lockfile:
    rm -f Cargo.lock