# Conforma Rego policy demo

## Summary

Use prompts to create Rego rules that verify the image's SPDX SBOM registry
references and SLSA provenance builder ID. Run the combined policy successfully,
switch to a strict registry allowlist to produce a real failure, capture the
`ec validate image` output, debug the saved violation, and rerun the passing
policy.

The demo uses the digest currently resolved from
`quay.io/konflux-ci/ec-golden-image:latest`:

```text
quay.io/konflux-ci/ec-golden-image@sha256:e3eaa30f75d18382d4bf2acd84bd2fba57991cbaa6058c6fe9a1b99114cbac97
```

Run all shell commands below from the repository root.

## Prompts

### 1. Create the SBOM rule

```text
Use the generate-policy skill to create a Conforma policy set named
"ec_golden_image_policy" for this image:

quay.io/konflux-ci/ec-golden-image@sha256:e3eaa30f75d18382d4bf2acd84bd2fba57991cbaa6058c6fe9a1b99114cbac97

Create a rule named "approved_image_registries" that:

- Uses `data.lib.sbom.spdx_sboms`.
- Fails when no SPDX SBOM is found.
- Checks the `repository_url` qualifier on OCI PURLs in SPDX packages.
- Allows only an exact approved registry host or a repository path below it.
- Reads approved registries from rule data, initially `quay.io`,
  `registry.redhat.io`, and `registry.access.redhat.com`.
- Skips non-OCI PURLs and packages without PURLs.
- Includes complete METADATA and the offending PURL in a violation.
- Includes tests for passing, failing, missing-SBOM, empty, mixed, non-OCI,
  missing-PURL, and registry-prefix-lookalike cases.

Use fixtures only for unit tests. Validate the real image with
`ec validate image`, not an in-memory attestation. Run formatting and all
policy tests, then provide the validation command with `--policy policy.yaml`,
`--public-key cosign.pub`, `--ignore-rekor`, `--output text`, and `--info`.
```

### 2. Add the SLSA builder-ID rule

```text
Add a rule named "approved_slsa_builder" to the existing policy set for the
same image.

Create a local `data.lib.provenance` helper that reads the attestations supplied
by `ec validate image` and exposes PipelineRun SLSA provenance. It must support:

- SLSA v0.2 build type at `statement.predicate.buildType` and builder ID at
  `statement.predicate.builder.id`.
- SLSA v1 build type at `statement.predicate.buildDefinition.buildType` and
  builder ID at `statement.predicate.runDetails.builder.id`.
- Allowed build types from `data.rule_data.allowed_provenance_build_types`.

The rule must:

- Fail when no supported PipelineRun provenance is found.
- Fail with a separate code when a builder ID is missing.
- Fail with another code when a builder ID is not approved.
- Include the observed builder ID in an unapproved-builder violation.
- Read approved IDs from `data.rule_data.allowed_builder_ids`, initially
  `https://tekton.dev/chains/v2`.
- Include complete METADATA and tests for approved v0.2, approved v1, missing,
  unexpected, absent-provenance, disallowed-build-type, and empty-allowlist cases.

Include both rule directories and all violation codes in `policy.yaml`. Use
fixtures only for unit tests. Run formatting and all tests, then validate the
real image with the same `ec validate image` command.
```

### 3. Create the deliberate failure

```text
Create `policy-strict.yaml` using `./data-strict`. Keep both Rego rules and the
SLSA rule data unchanged, but allow only these SBOM registries:

- registry.redhat.io
- registry.access.redhat.com

Do not include `quay.io`. Create `run-failing.sh` so it validates the real
image, displays stdout and stderr, writes both to `validation.log` with `tee`,
and preserves the validation exit status with `set -o pipefail`.
```

## Run the passing policy

```bash
(cd demo && ec opa test ./policy -v)
(cd demo && bash run-passing.sh)
```

Show that validation succeeds with zero violations. The complete output is
also saved to `demo/validation-pass.log`.

## Run the deliberate failure

```bash
(cd demo && bash run-failing.sh)
```

The command is expected to exit nonzero. Show:

```text
Success: false
approved_image_registries.approved_image_registries
Image <OCI PURL> is from registry <quay.io repository URL> which is not approved
```

The complete output is displayed and saved to `demo/validation.log`.

## Debug the saved violation

Optionally summarize it first:

```bash
python3 .claude/skills/ec-policy-debugging/summarize_violations.py demo/validation.log
```

Then prompt the debugging workflow:

```text
/ec-debug-violations demo/validation.log --policy demo/policy-strict.yaml
```

Show that it finds the violation code, Rego rule, METADATA, tests, affected
image and PURL, then compares the observed `quay.io` repository with the strict
allowlist and recommends restoring `quay.io`.

## Fix and rerun

Use the normal policy again:

```bash
(cd demo && bash run-passing.sh)
```

Show that both the SBOM registry rule and SLSA builder rule now pass and that
`demo/validation-pass.log` contains the successful validation.
