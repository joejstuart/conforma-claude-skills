ec validate image \
    --image quay.io/konflux-ci/ec-golden-image:latest \
    --policy policy.yaml \
    --public-key cosign.pub \
    --ignore-rekor \
    --output text \
    --info
