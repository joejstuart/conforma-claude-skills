ec validate image \
    --image quay.io/konflux-ci/ec-golden-image@sha256:e3eaa30f75d18382d4bf2acd84bd2fba57991cbaa6058c6fe9a1b99114cbac97 \
    --policy policy.yaml \
    --public-key cosign.pub \
    --ignore-rekor \
    --output text \
    --info
