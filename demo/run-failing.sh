#!/usr/bin/env bash

set -o pipefail

ec validate image \
    --image quay.io/konflux-ci/ec-golden-image:latest \
    --policy policy-strict.yaml \
    --public-key cosign.pub \
    --ignore-rekor \
    --output text \
    --info \
    2>&1 | tee validation.log

exit "${PIPESTATUS[0]}"
