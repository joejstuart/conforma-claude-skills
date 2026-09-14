package lib.provenance

import rego.v1

slsa_provenance_predicate_type_v02 := "https://slsa.dev/provenance/v0.2"
slsa_provenance_predicate_type_v1 := "https://slsa.dev/provenance/v1"

slsa_provenance_attestations := [att |
	some att in input.attestations
	att.statement.predicateType in {
		slsa_provenance_predicate_type_v02,
		slsa_provenance_predicate_type_v1,
	}
]

pipelinerun_attestations := [att |
	some att in slsa_provenance_attestations
	build_type := _build_type(att)
	allowed := object.get(data.rule_data, "allowed_provenance_build_types", [])
	build_type in allowed
]

_build_type(att) := build_type if {
	att.statement.predicateType == slsa_provenance_predicate_type_v02
	build_type := att.statement.predicate.buildType
} else := build_type if {
	att.statement.predicateType == slsa_provenance_predicate_type_v1
	build_type := att.statement.predicate.buildDefinition.buildType
}
