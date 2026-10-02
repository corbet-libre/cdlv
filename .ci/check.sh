#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
trap 'sha256sum Cargo.lock' EXIT
export CARGO_BUILD_JOBS=2
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc -Vv
sha256sum Cargo.lock
python3 .github/check-first-party.py --archive
case "${1:?selected check required}" in
  native)
    cargo fmt --all --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    ;;
  browser)
    command -v wasm-bindgen-test-runner >/dev/null
    command -v chromedriver >/dev/null
    : "${CHROMEDRIVER:=$(command -v chromedriver)}"
    export CHROMEDRIVER
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    export WASM_BINDGEN_USE_BROWSER=1 WASM_BINDGEN_TEST_TIMEOUT=60
    cargo test --locked --target wasm32-unknown-unknown --test delivery
    ;;
  coverage)
    command -v cargo-llvm-cov >/dev/null
    case "$(rustc --version)" in *nightly*) ;; *) echo "Branch coverage requires the provisioned nightly toolchain" >&2; exit 1 ;; esac
    cargo llvm-cov --locked --branch --no-cfg-coverage --no-cfg-coverage-nightly --json --output-path coverage.json --ignore-filename-regex '/tests/'
    cargo llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
    cargo llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
    python3 .github/test-source-coverage.py
    python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
    ;;
  dependency-policy)
    bash .ci/advisories.sh
    ;;
  *) exit 2 ;;
esac
