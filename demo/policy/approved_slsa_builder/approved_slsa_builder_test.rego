package approved_slsa_builder_test

import rego.v1

import data.approved_slsa_builder

_allowed_builder_ids := ["https://tekton.dev/chains/v2"]

_allowed_build_types := [
	"tekton.dev/v1/PipelineRun",
	"https://tekton.dev/chains/v2/slsa-tekton",
]

_v02(builder) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"builder": builder,
	},
}}

_v1(builder) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {"buildType": "https://tekton.dev/chains/v2/slsa-tekton"},
		"runDetails": {"builder": builder},
	},
}}

test_approved_v02_builder if {
	attestations := [_v02({"id": "https://tekton.dev/chains/v2"})]

	count(approved_slsa_builder.deny) == 0 with input.attestations as attestations
		with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with data.rule_data.allowed_provenance_build_types as _allowed_build_types
}

test_approved_v1_builder if {
	attestations := [_v1({"id": "https://tekton.dev/chains/v2"})]

	count(approved_slsa_builder.deny) == 0 with input.attestations as attestations
		with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with data.rule_data.allowed_provenance_build_types as _allowed_build_types
}

test_missing_builder_id if {
	attestations := [_v02({})]
	result := approved_slsa_builder.deny with input.attestations as attestations
		with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with data.rule_data.allowed_provenance_build_types as _allowed_build_types

	count(result) == 1
	some violation in result
	violation.code == "approved_slsa_builder.slsa_builder_id_found"
}

test_unexpected_builder_id if {
	attestations := [_v1({"id": "https://example.com/untrusted-builder"})]
	result := approved_slsa_builder.deny with input.attestations as attestations
		with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with data.rule_data.allowed_provenance_build_types as _allowed_build_types

	count(result) == 1
	some violation in result
	violation.code == "approved_slsa_builder.slsa_builder_id_accepted"
	violation.term == "https://example.com/untrusted-builder"
}

test_no_slsa_provenance if {
	result := approved_slsa_builder.deny with input.attestations as []
		with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with data.rule_data.allowed_provenance_build_types as _allowed_build_types

	count(result) == 1
	some violation in result
	violation.code == "approved_slsa_builder.slsa_provenance_found"
}

test_unapproved_build_type_is_not_pipeline_provenance if {
	attestation := _v02({"id": "https://tekton.dev/chains/v2"})
	result := approved_slsa_builder.deny with input.attestations as [attestation]
		with data.rule_data.allowed_builder_ids as _allowed_builder_ids
		with data.rule_data.allowed_provenance_build_types as ["example.com/other-build"]

	count(result) == 1
	some violation in result
	violation.code == "approved_slsa_builder.slsa_provenance_found"
}

test_empty_builder_allowlist_rejects_builder if {
	attestations := [_v02({"id": "https://tekton.dev/chains/v2"})]
	result := approved_slsa_builder.deny with input.attestations as attestations
		with data.rule_data.allowed_builder_ids as []
		with data.rule_data.allowed_provenance_build_types as _allowed_build_types

	count(result) == 1
	some violation in result
	violation.code == "approved_slsa_builder.slsa_builder_id_accepted"
}
