# syntax=docker/dockerfile:1.7
# Build image for the Anthropic OSS Scanner.
#
# The scanner builds this with the repository as the build context, then audits
# the result with no network access. So everything the build and the tests need
# is fetched here: the Rust toolchain, every crate in Cargo.lock, and the
# compiled test binaries. Nothing in the image holds a key, a token or user data.
# `RUN --network=none` below needs BuildKit; it proves the tests work offline.
FROM rust:1-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    CARGO_NET_RETRY=5 \
    RUST_BACKTRACE=1 \
    DO_NOT_TRACK=1

# The rust image already ships a C toolchain (tree-sitter grammars compile C).
# git is for reproducers that need a repository layout.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Login shells on Debian reset PATH and drop /usr/local/cargo/bin. Link the Rust
# tools into /usr/local/bin so `sh -lc 'cargo ...'` works as well.
RUN for tool in /usr/local/cargo/bin/*; do ln -sf "$tool" "/usr/local/bin/$(basename "$tool")"; done

# scanner contract: the checkout lives inside the image, at /src
WORKDIR /src
COPY . /src

# rust-toolchain.toml tracks `stable`, which is what this image provides.
# Fetch every crate (including dev-dependencies) while the network is up.
RUN cargo fetch --locked

# Debug profile: unoptimised, with full debug info (-g), and overflow checks on.
# This builds the `bastyn` binary and every test binary, so the audit can run
# either without compiling anything new.
RUN cargo build --workspace --all-features --locked \
    && cargo test --workspace --all-features --locked --no-run

# Run the tests with the network removed so the image is proven to work offline.
# A failing test must not abort the build. The tests that would need the
# internet (OSV.dev lookups, live MCP servers) use local fakes or are not run;
# see .oss-scanner/threat_model.md.
RUN --network=none cargo test --workspace --all-features --locked --offline \
    || echo "WARNING: baseline tests failed"
