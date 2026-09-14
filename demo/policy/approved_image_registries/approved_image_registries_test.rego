#
# METADATA
# title: Approved Image Registries Tests
# description: >-
#   Tests for the approved_image_registries policy rule.
#
package approved_image_registries_test

import rego.v1

import data.approved_image_registries

# =============================================================================
# Mock Data Helpers
# =============================================================================

# Helper: Create an SPDX SBOM with packages
_mock_spdx_sbom(packages) := {
	"SPDXID": "SPDXRef-DOCUMENT",
	"spdxVersion": "SPDX-2.3",
	"packages": packages,
}

# Helper: Create an SPDX package with an OCI PURL
_mock_oci_package(name, repo_url) := {
	"SPDXID": sprintf("SPDXRef-%s", [name]),
	"name": name,
	"externalRefs": [{
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceType": "purl",
		"referenceLocator": sprintf("pkg:oci/%s@sha256:abc123?repository_url=%s", [name, repo_url]),
	}],
}

# Helper: Create an SPDX package with a non-OCI PURL
_mock_non_oci_package(purl) := {
	"SPDXID": "SPDXRef-Package-NonOCI",
	"name": "non-oci-package",
	"externalRefs": [{
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceType": "purl",
		"referenceLocator": purl,
	}],
}

_approved_registries := [
	"registry.redhat.io",
	"registry.access.redhat.com",
]

# =============================================================================
# Pass Cases - No Violations Expected
# =============================================================================

test_approved_registry_redhat_io if {
	packages := [_mock_oci_package("ubi9", "registry.redhat.io/ubi9")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 0 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_approved_registry_access_redhat if {
	packages := [_mock_oci_package("ubi8", "registry.access.redhat.com/ubi8")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 0 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_multiple_approved_registries if {
	packages := [
		_mock_oci_package("ubi9", "registry.redhat.io/ubi9"),
		_mock_oci_package("httpd", "registry.access.redhat.com/rhscl/httpd-24-rhel7"),
	]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 0 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

# =============================================================================
# Fail Cases - Violations Expected
# =============================================================================

test_unapproved_registry_fails if {
	packages := [_mock_oci_package("myapp", "quay.io/myorg/myapp")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 1 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_dockerhub_registry_fails if {
	packages := [_mock_oci_package("nginx", "docker.io/library/nginx")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 1 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_empty_approved_registries_denies_all if {
	packages := [_mock_oci_package("ubi9", "registry.redhat.io/ubi9")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 1 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as []
}

# =============================================================================
# Edge Cases
# =============================================================================

test_no_sboms if {
	result := approved_image_registries.deny with data.lib.sbom.spdx_sboms as []
		with data.rule_data.approved_image_registries as _approved_registries

	count(result) == 1
	some violation in result
	violation.code == "approved_image_registries.spdx_sbom_found"
}

test_no_packages if {
	sboms := [_mock_spdx_sbom([])]

	count(approved_image_registries.deny) == 0 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_non_oci_purl_skipped if {
	packages := [_mock_non_oci_package("pkg:rpm/rhel/openssl@3.0.7")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 0 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_package_without_purl_skipped if {
	packages := [{
		"SPDXID": "SPDXRef-NoPurl",
		"name": "no-purl-package",
		"externalRefs": [{
			"referenceCategory": "SECURITY",
			"referenceType": "cpe23Type",
			"referenceLocator": "cpe:2.3:a:example:pkg:1.0:*:*:*:*:*:*:*",
		}],
	}]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 0 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_registry_prefix_lookalike_fails if {
	packages := [_mock_oci_package("myapp", "registry.redhat.io.example.com/myapp")]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 1 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

# =============================================================================
# Multiple Items
# =============================================================================

test_mixed_approved_and_unapproved if {
	packages := [
		_mock_oci_package("ubi9", "registry.redhat.io/ubi9"),
		_mock_oci_package("myapp", "quay.io/myorg/myapp"),
		_mock_oci_package("httpd", "registry.access.redhat.com/rhscl/httpd-24-rhel7"),
	]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 1 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

test_multiple_unapproved if {
	packages := [
		_mock_oci_package("app1", "quay.io/org/app1"),
		_mock_oci_package("app2", "docker.io/library/app2"),
	]
	sboms := [_mock_spdx_sbom(packages)]

	count(approved_image_registries.deny) == 2 with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries
}

# =============================================================================
# Violation Content
# =============================================================================

test_violation_contains_purl_and_registry if {
	packages := [_mock_oci_package("myapp", "quay.io/myorg/myapp")]
	sboms := [_mock_spdx_sbom(packages)]

	result := approved_image_registries.deny with data.lib.sbom.spdx_sboms as sboms
		with data.rule_data.approved_image_registries as _approved_registries

	count(result) == 1
	some violation in result
	contains(violation.msg, "pkg:oci/myapp")
	contains(violation.msg, "quay.io/myorg/myapp")
	violation.code == "approved_image_registries.approved_image_registries"
	violation.severity == "failure"
}
