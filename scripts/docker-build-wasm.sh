#!/bin/bash

SCRIPT=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT")
cd $SCRIPT_DIR/..

GIT_COMMIT_ID=$(git rev-parse HEAD)

echo "CommitId: $GIT_COMMIT_ID"

docker build -t sign_in_with_email --build-arg git_commit_id=$GIT_COMMIT_ID .

container_id=$(docker create sign_in_with_email)
rm -rf wasms
docker cp $container_id:/build/wasms wasms
docker rm --volumes $container_id

cd wasms
for wasm in *; do
    shasum -a 256 "$wasm"
done
cd ..
