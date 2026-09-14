# Conforma Rego policy demo

## Summary

Generate an SBOM registry rule and an SLSA builder-ID rule for
`quay.io/konflux-ci/ec-golden-image:latest`. Run the policy successfully, then
run a strict variant that intentionally fails, display and capture the
`ec validate image` output, and use the captured log to demonstrate policy
violation debugging.

Image:

```text
quay.io/konflux-ci/ec-golden-image:latest
```

The demo creates two rules in the same policy set:

- `approved_image_registries`: verifies OCI image references in the SPDX SBOM.
- `approved_slsa_builder`: verifies the SLSA provenance builder ID.

Detailed copy/paste prompts are also in [rule-prompts.md](rule-prompts.md).

## Prompts

### 1. Create the SBOM rule

```text
Use the generate-policy skill to create a Conforma policy set named
"ec_golden_image_policy" for this image:

quay.io/konflux-ci/ec-golden-image:latest

Create an SBOM rule named "approved_image_registries".

The rule must:

- Use `data.lib.sbom.spdx_sboms`, not `input.attestations`.
- Iterate over SPDX packages and OCI PURLs.
- Read the `repository_url` qualifier.
- Deny repository URLs that do not start with an approved registry.
- Store approved registries in rule data, initially:
  `quay.io`, `registry.redhat.io`, and `registry.access.redhat.com`.
- Skip non-OCI PURLs, packages without PURLs, and empty candidate sets.
- Include complete METADATA and the offending PURL in the result.
- Generate tests for pass, fail, empty, mixed, non-OCI, and missing-PURL cases.

Use the real image for validation. Unit-test fixtures are only for OPA tests;
do not use an in-memory attestation as the validation input.

Run formatting and all policy tests. Then provide the exact `ec validate image`
command using `--policy policy.yaml`, `--public-key cosign.pub`,
`--ignore-rekor`, `--output text`, and `--info`.
```

### 2. Add the SLSA builder-ID rule

```text
Add a SLSA provenance rule named "approved_slsa_builder" to the existing
`ec_golden_image_policy` policy set for:

quay.io/konflux-ci/ec-golden-image:latest

The rule must:

- Import `data.lib` and use `lib.pipelinerun_attestations`.
- Support SLSA v0.2 at `statement.predicate.builder.id`.
- Support SLSA v1.0 at `statement.predicate.runDetails.builder.id`.
- Use a local helper to extract either builder-ID path.
- Deny a missing builder ID with its own violation code.
- Deny an unexpected builder ID with a separate violation code.
- Include the observed builder ID in the result when available.
- Read `allowed_builder_ids` from rule data, initially:
  `https://tekton.dev/chains/v2`.
- Generate tests for approved v0.2, approved v1.0, missing, and unexpected
  builder IDs.

Do not use an in-memory attestation as the validation input. Run formatting,
all policy tests, and provide the complete `ec validate image` command for the
real image.
```

### 3. Create a deliberate failure

```text
Create a strict variant named `policy-strict.yaml` that uses
`./data-strict/approved_registries.yaml` and allows only:

- registry.redhat.io
- registry.access.redhat.com

Do not include `quay.io`. Keep the Rego unchanged. This variant must produce a
real SBOM violation for the image's OCI PURL.

Create a script that runs `ec validate image` against the real image, displays
the output, writes stdout and stderr to `validation.log` with `tee`, and
preserves the `ec validate image` exit status with `set -o pipefail`.
```

## Run the passing policy

From the repository demo directory:

```bash
cd demo
ec opa test ./policy -v
bash run-passing.sh
```

The passing wrapper runs:

```bash
set -o pipefail
ec validate image \
  --image quay.io/konflux-ci/ec-golden-image:latest \
  --policy policy.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info \
  2>&1 | tee validation-pass.log
exit "${PIPESTATUS[0]}"
```

Show on screen:

```text
Success: true
Violations: 0
```

The exact output may include additional component and rule information.

## Run the deliberately failing policy

The repository includes a strict SBOM variant:

```bash
cd demo
bash run-failing.sh
```

It runs:

```bash
ec validate image \
  --image quay.io/konflux-ci/ec-golden-image:latest \
  --policy policy-strict.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info \
  2>&1 | tee validation.log
```

Show on screen:

```text
Success: false
approved_image_registries.approved_image_registries
Image <OCI PURL> is from registry quay.io which is not approved
```

The full output is now available in `demo/validation.log` for the debugging
skill.

## Run the policy debugging workflow

Summarize the captured result:

```bash
python3 .claude/skills/ec-policy-debugging/summarize_violations.py demo/validation.log
```

Run the debugging command:

```text
/ec-debug-violations demo/validation.log --policy demo/policy-strict.yaml
```

Show that the skill:

1. Extracts the violation code and count.
2. Locates the Rego rule from `package.short_name`.
3. Reads the rule METADATA.
4. Reads the adjacent tests.
5. Identifies the affected image and PURL from the log.
6. Compares the actual `quay.io` repository URL with strict rule data.
7. Recommends adding `quay.io` back to the allowlist.

## Fix and rerun

Restore the normal data source and rerun the passing validation:

```bash
cd demo
bash run.sh
```

For the combined SBOM and SLSA policy, also verify that the builder allowlist
contains the intended builder ID, then rerun the same `ec validate image`
command. Preserve any unexpected output and debug it from the captured log.
