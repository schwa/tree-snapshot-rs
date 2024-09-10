set shell := ["fish", "-c"]

_default: _list

_list:
    just --list

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

####

update-gif:
    cargo install --path .
    vhs scripts/demo.tape -o docs/out.gif

publish:
    #!/usr/bin/env fish
    set CURRENT_BRANCH (git symbolic-ref --short HEAD)
    if [ $CURRENT_BRANCH != main ]
        echo "Not on main branch. Please switch to main before publishing."
        exit 1
    end
    set NEXT_VERSION (just _next-version)
    gum confirm "Confirm next version: '$NEXT_VERSION'?"; or exit 1
    just _check-repo; or exit 1
    cargo clippy --fix
    just _check-repo; or exit 1
    cargo test; or exit 1
    just update-usage
    echo "Updating Cargo.toml to version $NEXT_VERSION"
    toml set Cargo.toml package.version $NEXT_VERSION| sponge Cargo.toml
    gum confirm "Update gif?"; and just update-gif; git add docs/out.gif
    gum confirm "git commit -a"; and git commit -a
    gum confirm "git tag?"; and git tag $NEXT_VERSION
    gum confirm "git push?"; and git push --tags origin main
    gum confirm "Rust publish"; and cargo publish

_check-repo:
    #!/usr/bin/env fish
    set is_dirty (git status --porcelain)
    if test -n "$is_dirty"
        echo "Repo is dirty. Please commit all changes before publishing."
        exit 1
    end

# update-usage:
#     #!/usr/bin/env fish
#     awk -f scripts/replace.awk -v INDEX=2 -v "REPLACEMENT=cargo run -- --help 2> /dev/null" README.md | sponge README.md

_next-version:
    #!/usr/bin/env fish
    set LATEST_TAG (git describe --tags --abbrev=0)
    set PARTS (string split . $LATEST_TAG)
    set MAJOR $PARTS[1]
    set MINOR $PARTS[2]
    set PATCH $PARTS[3]
    set NEXT_PATCH (math $PATCH + 1)
    echo "$MAJOR.$MINOR.$NEXT_PATCH"

# bump-version:
#     toml set Cargo.toml package.version XXXXX | sponge Cargo.toml

# test-opens:
#     cargo build --release
#     rm -f test-1.log
#     rm -f test-2.log
#     ./target/release/simple-disk-benchmark --size 1GB --blocksize 128MB --cycles 10 --mode read --no-progress --no-chart --export-log test-1.log
#     ./target/release/simple-disk-benchmark --size 1GB --blocksize 128MB --cycles 10 --mode read --no-progress --no-chart --export-log test-2.log --no-close-file
#     grep "posix::open" test-1.log | wc -l
#     grep "posix::open" test-2.log | wc -l

cargo-analytics:
    cargo tree > docs/tree.txt
    cargo bloat --release --crates -n 10000 > docs/bloat.txt
    cargo report future-incompatibilities > docs/future-incompatibilities.txt; or true
    unused-features analyze
    unused-features build-report --input report.json
    mv report.json docs/unused-features.json
    mv report.html docs/unused-features.html
    #unused-features prune --input docs/unused-features.json

cargo-installs:
    cargo install cargo-bloat
    # brew install cargo-udeps
    cargo install cargo-machete
    cargo install cargo-unused-features
    cargo install toml-cli
    #rustup toolchain install nightly-aarch64-apple-darwin
    cargo install cargo-edit

linux-setup machine_name:
    #!/usr/bin/env fish
    set MACHINE_NAME {{machine_name}}
    if orb list --format json | jq -e ".[].name == \"$MACHINE_NAME\""
        echo "Machine already exists"
        exit 1
    else
        echo "Machine does not exist. Creating..."
    end

    orb create -a arm64 ubuntu {{machine_name}}
    orb run --machine {{machine_name}} sudo apt install gcc
    orb run --machine {{machine_name}} --shell curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

linux-run_ machine_name: (linux-setup machine_name)
    orb run --machine {{machine_name}} cargo clean
    orb run --machine {{machine_name}} cargo build

linux-run: (linux-run_ "ubuntu")
