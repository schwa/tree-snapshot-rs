install-dist-deps:
    cargo install cargo-machete

dist-check:
    cargo machete
    cargo publish --dry-run
    cargo package --list

install-local:
    cargo install --path .

demo:
    vhs scripts/demo.tape

lint-fix:
    cargo fmt
    cargo clippy --fix --allow-dirty
