#!/bin/bash

IDENTITY=$1
IC_URL=$2
CANISTER_ID=$3
AWS_REGION=$4
AWS_TARGET_ARN=$5
AWS_ACCESS_KEY=$6
AWS_SECRET_KEY=$7

SCRIPT=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT")
cd $SCRIPT_DIR/..

cargo run \
    --bin canister_upgrader -- \
    --identity $IDENTITY \
    --ic-url $IC_URL \
    --canister-id $CANISTER_ID \
    --aws-region $AWS_REGION \
    --aws-target-arn $AWS_TARGET_ARN \
    --aws-access-key $AWS_ACCESS_KEY \
    --aws-secret-key $AWS_SECRET_KEY \