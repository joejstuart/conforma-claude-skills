#
# METADATA
# title: Approved SLSA Builder
# description: >-
#   Validates that an image has SLSA PipelineRun provenance and that its
#   builder ID is present and approved.
#
package approved_slsa_builder

import rego.v1

import data.lib.provenance

# METADATA
# title: SLSA provenance found
# description: Verify that the image has a supported SLSA PipelineRun attestation.
# custom:
#   short_name: slsa_provenance_found
#   failure_msg: "SLSA PipelineRun provenance not found"
#   solution: >-
#     Attach SLSA v0.2 or v1 provenance whose build type is included in
#     allowed_provenance_build_types.
deny contains result if {
	count(provenance.pipelinerun_attestations) == 0

	result := {
		"code": "approved_slsa_builder.slsa_provenance_found",
		"msg": "SLSA PipelineRun provenance not found",
		"severity": "failure",
	}
}

# METADATA
# title: SLSA builder ID found
# description: Verify that each SLSA PipelineRun attestation has a builder ID.
# custom:
#   short_name: slsa_builder_id_found
#   failure_msg: "SLSA provenance builder ID not found"
#   solution: Configure the provenance generator to include the builder ID.
deny contains result if {
	some att in provenance.pipelinerun_attestations
	not _builder_id(att)

	result := {
		"code": "approved_slsa_builder.slsa_builder_id_found",
		"msg": "SLSA provenance builder ID not found",
		"severity": "failure",
	}
}

# METADATA
# title: SLSA builder ID accepted
# description: Verify that each SLSA PipelineRun attestation has an approved builder ID.
# custom:
#   short_name: slsa_builder_id_accepted
#   failure_msg: "SLSA provenance builder ID %s is not approved"
#   solution: >-
#     Use an approved builder or add the trusted builder ID to
#     allowed_builder_ids after review.
deny contains result if {
	some att in provenance.pipelinerun_attestations
	builder_id := _builder_id(att)
	allowed := object.get(data.rule_data, "allowed_builder_ids", [])
	not builder_id in allowed

	result := {
		"code": "approved_slsa_builder.slsa_builder_id_accepted",
		"msg": sprintf("SLSA provenance builder ID %s is not approved", [builder_id]),
		"severity": "failure",
		"term": builder_id,
	}
}

_builder_id(att) := builder_id if {
	att.statement.predicateType == provenance.slsa_provenance_predicate_type_v02
	builder_id := att.statement.predicate.builder.id
	builder_id != ""
} else := builder_id if {
	att.statement.predicateType == provenance.slsa_provenance_predicate_type_v1
	builder_id := att.statement.predicate.runDetails.builder.id
	builder_id != ""
}
