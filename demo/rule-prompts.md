# Prompts for generating the demo policy rules

These prompts are intended for the repository's `generate-policy` skill. They
use a real image for Conforma validation; they do not ask the skill to validate
an in-memory attestation.

## Shared setup

Use this policy set name and image in every prompt:

```text
Policy set: ec_golden_image_policy
Image: quay.io/konflux-ci/ec-golden-image:latest
Public key: save the provided verification key as cosign.pub in the policy set directory.
```

If no public key has been supplied, the skill should ask for it. Do not invent
or silently reuse a key. The generated validation command should use
`--public-key cosign.pub`.

## Prompt 1: SBOM verification rule

```text
Create a Conforma policy set called "ec_golden_image_policy" for this image:

quay.io/konflux-ci/ec-golden-image:latest

Create an SBOM rule named "approved_image_registries" that validates the SPDX
SBOM associated with the image at Conforma runtime.

Requirements:

- Access SBOMs through the required `data.lib.sbom.spdx_sboms` library. Do not
  iterate over `input.attestations` directly.
- Iterate over SPDX packages and their `externalRefs` entries.
- Consider only references where `referenceType` is `purl` and the PURL type
  is `oci`.
- Read the `repository_url` qualifier from the OCI PURL.
- Deny an image when its repository URL does not start with an approved
  registry.
- Put the approved registries in rule data, not in Rego. Start with:
  `quay.io`, `registry.redhat.io`, and `registry.access.redhat.com`.
- Skip non-OCI PURLs, packages without a PURL, and SBOMs that do not contain
  candidate packages.
- Include complete METADATA with a stable short name, useful failure message,
  solution, and the offending PURL in the result term.
- Generate the adjacent Rego tests for approved, unapproved, empty, mixed,
  non-OCI, and missing-PURL cases. Unit-test fixtures may be mocked only for
  OPA testing; the real validation must use `ec validate image` against the
  image above.
- Generate `policy.yaml`, rule data, the SBOM library, the public-key file
  placeholder or requested key location, and a runnable command.

Run `opa fmt`/the repository formatter and run the complete OPA test suite.
Then provide the exact `ec validate image` command for the image above.
```

## Prompt 2: SLSA builder-ID rule

Run this as a follow-up against the same policy set, or include it in the
initial generation request if the skill supports multiple rules at once:

```text
Add a SLSA provenance rule named "approved_slsa_builder" to the existing
`ec_golden_image_policy` policy set for:

quay.io/konflux-ci/ec-golden-image:latest

Requirements:

- Validate the builder ID in the image's SLSA provenance attestation at
  Conforma runtime. Do not use an in-memory attestation as the validation
  input.
- Import `data.lib` and use the runtime-provided provenance helpers. Use
  `lib.pipelinerun_attestations` for PipelineRun build attestations.
- Support both SLSA shapes:
  - v0.2: `statement.predicate.builder.id`
  - v1.0: `statement.predicate.runDetails.builder.id`
- Define a local helper that extracts the builder ID from either version.
- Deny a missing builder ID with a dedicated violation code.
- Deny a builder ID that is not in `data.rule_data.allowed_builder_ids` with
  a separate violation code and include the observed ID in the message/term.
- Store the approved builder IDs in YAML rule data. Start with:
  `https://tekton.dev/chains/v2`.
- Treat that builder ID as the initial policy requirement. If validation shows
  a different builder ID, report the mismatch and ask for an explicit policy
  decision; do not silently add the observed ID to the allowlist.
- Do not add a second SBOM library path for this rule. The SBOM rule needs
  `policy/lib`; the provenance rule uses the runtime `data.lib` helpers.
- Add METADATA, tests for approved v0.2, approved v1.0, missing, and
  unexpected builder IDs, and validation of the rule-data shape.
- Keep the tests as unit-test coverage only. The acceptance check must run
  `ec validate image` against the real image above.

Run formatting and all policy tests. Then provide the complete validation
command for the combined policy set.
```

## Prompt 3: Verify the generated command and combined policy

Use this after both rules exist:

```text
Review the generated `ec_golden_image_policy` policy set without regenerating
unrelated files.

Confirm that `policy.yaml` includes both rule directories, the SBOM library,
and the rule-data directory, and that its include list selects both rules.
Confirm that the SBOM rule uses `data.lib.sbom.spdx_sboms` and the SLSA rule
uses `data.lib.pipelinerun_attestations`.

Run all policy tests. Then give me the exact command to validate this image:

quay.io/konflux-ci/ec-golden-image:latest

The command must run from the policy-set directory and use:

--policy policy.yaml
--public-key cosign.pub
--ignore-rekor
--output text
--info

Do not substitute an in-memory input, a local JSON fixture, or a different
image reference.
```

## Prompt 4: Create a deliberate failing policy for debugging

Use this after the passing policy has been generated. It creates a separate
strict configuration so the demo can show a real `ec validate image` failure
without modifying the passing policy:

```text
Create a deliberate failing variant of the generated `ec_golden_image_policy`
policy for the debugging demo.

Keep the same image, rules, and public key, but create `policy-strict.yaml`
that reads registry data from `./data-strict` instead of `./data`. In
`data-strict/approved_registries.yaml`, allow only:

- registry.redhat.io
- registry.access.redhat.com

Do not include `quay.io`. The image being validated is:

quay.io/konflux-ci/ec-golden-image:latest

The purpose is to produce at least one real SBOM policy violation from the
image's OCI PURL repository URL. Do not change the Rego rule to manufacture a
failure and do not use an in-memory attestation.

Generate a runnable script that captures the complete validation output,
including stderr, to `validation.log` while also displaying it on screen. Use
`set -o pipefail` and preserve the `ec validate image` exit status.
```

The script should run the command in this form:

```bash
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
```

## Expected validation command

The final command should have this shape, with the generated policy-set
directory as the working directory:

```bash
cd ec_golden_image_policy
ec validate image \
  --image quay.io/konflux-ci/ec-golden-image:latest \
  --policy policy.yaml \
  --public-key cosign.pub \
  --ignore-rekor \
  --output text \
  --info
```

If the generated policy is expected to fail initially, preserve the output as
a validation log and use it with the debugging workflow:

```text
/ec-debug-violations validation.log --policy policy-strict.yaml
```

The result should identify whether the failure came from the SBOM registry
rule, the SLSA builder-ID rule, missing policy data, or a mismatch between the
actual attestation shape and the rule's expected path.
