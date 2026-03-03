# Contributing to Warden Proxy

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

1. Install [Rust](https://rustup.rs/) (stable toolchain)
2. Clone the repo: `git clone https://github.com/nwcnwc/warden-proxy.git`
3. Build: `cargo build`
4. Run tests: `cargo test`

## Making Changes

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Run `cargo test` to verify all tests pass
4. Run `cargo clippy` to check for lint issues
5. Submit a pull request

## Bug Fixes

All bug fixes **must** include a regression test. Follow this process:

1. Write a test that reproduces the bug (it must fail before the fix)
2. Apply the minimal fix to the production code
3. Verify the test now passes
4. Run the full test suite

See [SECURITY.md](SECURITY.md) for security-specific guidelines.

## Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Keep functions focused and well-documented
- Security-critical code must have inline comments explaining the reasoning

## Security

Warden is a security tool. Any PR that touches auth handling, key injection, or access control will receive extra scrutiny. This is expected and appreciated.

If you find a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.
