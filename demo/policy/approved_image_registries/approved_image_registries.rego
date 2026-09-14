#
# METADATA
# title: Approved Image Registries
# description: >-
#   Validates that container images referenced in the SBOM come from
#   approved registries by checking the repository_url qualifier in
#   OCI PURLs.
#
package approved_image_registries

import rego.v1

import data.lib.sbom

# METADATA
# title: Approved image registries
# description: >-
#   Verify that OCI images referenced in SPDX packages come from approved
#   container registries. The repository_url qualifier in OCI PURLs is
#   checked against the list of approved registries.
# custom:
#   short_name: approved_image_registries
#   failure_msg: "Image %s is from registry %s which is not approved"
#   solution: >-
#     Ensure container images are sourced only from approved registries.
#     Configure the approved_image_registries rule data with permitted registries.
deny contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages

	# Get PURL from externalRefs
	some ref in pkg.externalRefs
	ref.referenceType == "purl"
	purl := ref.referenceLocator

	# Only check OCI PURLs
	parsed := ec.purl.parse(purl)
	parsed.type == "oci"

	# Get repository_url qualifier (qualifiers is an array of {key, value} objects)
	some q in parsed.qualifiers
	q.key == "repository_url"
	repo_url := q.value

	# Check against approved registries
	approved := object.get(data.rule_data, "approved_image_registries", [])
	not _registry_approved(repo_url, approved)

	result := {
		"code": "approved_image_registries.approved_image_registries",
		"msg": sprintf("Image %s is from registry %s which is not approved", [purl, repo_url]),
		"severity": "failure",
		"term": purl,
	}
}

# Helper: check if repository_url starts with any approved registry
_registry_approved(repo_url, approved) if {
	some registry in approved
	startswith(repo_url, registry)
}
