install-dist-deps:
    cargo install cargo-machete

dist-check:
    cargo machete
