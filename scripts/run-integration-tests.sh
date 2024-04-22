#!/bin/bash

SCRIPT=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT")
cd $SCRIPT_DIR/..

TESTNAME=$1
TEST_THREADS=${2:-2}
POCKET_IC_SERVER_VERSION="3.0.0"

if [[ $OSTYPE == "linux-gnu"* ]] || [[ $RUNNER_OS == "Linux" ]]
then
    PLATFORM=linux
elif [[ $OSTYPE == "darwin"* ]] || [[ $RUNNER_OS == "macOS" ]]
then
    PLATFORM=darwin
else
    echo "OS not supported: ${OSTYPE:-$RUNNER_OS}"
    exit 1
fi

echo "Building canister wasm"
cargo build --target wasm32-unknown-unknown --release -p sign_in_with_email_canister_impl --locked
gzip -fk target/wasm32-unknown-unknown/release/sign_in_with_email_canister_impl.wasm

cd integration_tests
echo "PocketIC download starting"
curl -Ls https://github.com/dfinity/pocketic/releases/download/${POCKET_IC_SERVER_VERSION}/pocket-ic-x86_64-${PLATFORM}.gz -o pocket-ic.gz || exit 1
gzip -df pocket-ic.gz
chmod +x pocket-ic
echo "PocketIC download completed"
cd ..

cargo test --package integration_tests $TESTNAME -- --test-threads $TEST_THREADS
