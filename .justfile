install-dist-deps:
    cargo install cargo-machete

dist-check:
    cargo machete
    cargo publish --dry-run
    cargo package --list
