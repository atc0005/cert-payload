// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format0

import (
	"time"
)

const (
	// FormatVersion indicates the format version support provided by this
	// package. Version 0 is the pre-release version that we'll continue to
	// use until the types in this package stabilize.
	FormatVersion int = 0
)

// Server reflects the host value and resolved IP Address used to retrieve the
// certificate chain.
type Server struct {
	// HostValue is the original hostname value. While usually a FQDN, this
	// value could also be a fixed IP Address (e.g., if SNI support wasn't
	// used to retrieve the certificate chain).
	HostValue string `json:"host_value"`

	// IPAddress is the resolved IP Address for the hostname value used to
	// retrieve a certificate chain.
	IPAddress string `json:"ip_address"`
}

// CertificateStatus is the overall status of a certificate.
//
//   - no problems (ok)
//   - expired
//   - expiring (based on given threshold values)
//   - revoked (not yet supported)
//
// TODO: Any useful status values to borrow here?
// They have `Active`, `Revoked` and then a `Pending*` variation for both.
// https://developers.cloudflare.com/ssl/reference/certificate-statuses/#client-certificates
type CertificateStatus struct {
	OK       bool `json:"status_ok"`       // No observed issues; shouldn't this be calculated?
	Expiring bool `json:"status_expiring"` // Based on given monitoring thresholds
	Expired  bool `json:"status_expired"`  // Based on certificate NotAfter field

	// This is a feature to add later
	// RevokedPerCRL  bool `json:"status_revoked_per_crl"`  // Based on CRL or OCSP check?
	// RevokedPerOCSP bool `json:"status_revoked_per_ocsp"` // Based on CRL or OCSP check?
	// ?
}

// Certificate is a subset of the metadata for an evaluated certificate.
type Certificate struct {
	// Subject is the full subject value for a certificate. This is intended
	// for (non-cryptographic) comparison purposes.
	Subject string `json:"subject"`

	// CommonName is the short subject value of a certificate. This is
	// intended for display purposes.
	CommonName string `json:"common_name"`

	// SANsEntries is the full list of Subject Alternate Names for a
	// certificate.
	SANsEntries []string `json:"sans_entries"`

	// SANsEntriesCount is the number of Subject Alternate Names for a
	// certificate.
	//
	// This field allows the payload creator to omit SANs entries to conserve
	// plugin output size and still indicate the number of SANs entries
	// present for a certificate for use in display or for metrics purposes.
	SANsEntriesCount int `json:"sans_entries_count"`

	// Issuer is the full CommonName of the signing certificate. This is
	// intended for (non-cryptographic) comparison purposes.
	Issuer string `json:"issuer"`

	// IssuerShort is the short CommonName of the signing certificate. This is
	// intended for display purposes.
	IssuerShort string `json:"issuer_short"`

	// SerialNumber is the serial number for a certificate in hex format with
	// a colon inserted after each two digits.
	//
	// For example, `77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D`.
	SerialNumber string `json:"serial_number"`

	// IssuedOn is a RFC3389 time value for when a certificate is first
	// valid or usable.
	IssuedOn time.Time `json:"not_before"`

	// ExpiresOn is a RFC3389 time value for when the certificate expires.
	ExpiresOn time.Time `json:"not_after"`

	// DaysRemaining is the number of days remaining for a certificate in two
	// digit decimal precision.
	DaysRemaining float64 `json:"days_remaining"`

	// DaysRemainingTruncated is the number of days remaining for a
	// certificate as a whole number rounded down.
	//
	// For example, if five and a half days remain then this value would be
	// `5`.
	DaysRemainingTruncated int `json:"days_remaining_truncated"`

	// LifetimePercent is percentage of life remaining for a certificate.
	//
	// For example, if 43% life is remaining for a cert (a rounded value) this
	// field would be set to `43`.
	LifetimePercent int `json:"lifetime_remaining_percent"`

	// ValidityPeriodDescription is the human readable value such as "90 days"
	// or "1 year".
	ValidityPeriodDescription string `json:"validity_period_description"`

	// ValidityPeriodDays is the number of total days a certificate is valid
	// for using `Not Before` & `Not After` as the starting & ending range.
	ValidityPeriodDays int `json:"validity_period_days"`

	// human readable summary such as, `[OK] 1199d 2h remaining (43%)`
	Summary string `json:"summary"`

	// Status is the overall status of the certificate.
	Status CertificateStatus `json:"status"`

	// SignatureAlgorithm indicates what certificate signature algorithm was
	// used by a certification authority (CA)'s private key to sign a checksum
	// calculated by a signature hash algorithm (i.e., what algorithm was used
	// to sign the certificate). The verifying party must use the same
	// algorithm to decrypt and verify the checksum using the CA's public key.
	//
	// A cryptographically weak hashing algorithm (e.g. MD2, MD4, MD5, SHA1)
	// used to sign a certificate is considered to be a vulnerability.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// Type indicates the type of certificate (leaf, intermediate or root).
	Type string `json:"type"`
}

// Certificates is a collection of Certificate values from a single
// certificate chain.
type Certificates []Certificate

// CertificateChainIssues is an aggregated collection of problems detected for
// the certificate chain.
type CertificateChainIssues struct {
	// MissingIntermediateCerts indicates that intermediate certificates are
	// missing from the certificate chain.
	MissingIntermediateCerts bool `json:"missing_intermediate_certs"`

	// MissingSANsEntries indicates that SANs entries are missing from a leaf
	// certificate within the certificates chain.
	MissingSANsEntries bool `json:"missing_sans_entries"`

	// DuplicateCerts indicates that there are one or more duplicate copies of
	// a certificate in the certificate chain.
	DuplicateCerts bool `json:"duplicate_certs"`

	// MisorderedCerts indicates that certificates in the chain are out of the
	// expected order.
	//
	// E.g., instead of leaf, intermediate(s), root (technically not best
	// practice) the chain has something like leaf, root, intermediate(s) or
	// intermediates and then leaf.
	MisorderedCerts bool `json:"misordered_certs"`

	// ExpiredCerts indicates that there are one or more expired certificates
	// in the certificate chain.
	ExpiredCerts bool `json:"expired_certs"`

	// HostnameMismatch indicates that the name or IP Address used to
	// establish a connection to a certificate-enabled service does not match
	// the list of valid host names honored by the leaf certificate.
	//
	// Historically the Common Name (CN) field was searched in addition to the
	// Subject Alternate Names (SANs) field for a match, but this practice is
	// deprecated and many clients (e.g., web browsers) no longer support
	// this.
	HostnameMismatch bool `json:"hostname_mismatch"`

	// SelfSignedLeafCert indicates that the leaf certificate is self-signed.
	// This is fairly common for development/test environments but is not best
	// practice for certificates used outside of temporary / lab environments.
	SelfSignedLeafCert bool `json:"self_signed_leaf_cert"`

	// WeakSignatureAlgorithm indicates that the certificate chain has been
	// signed using a cryptographically weak hashing algorithm (e.g. MD2, MD4,
	// MD5, or SHA1). These signature algorithms are known to be vulnerable to
	// collision attacks. An attacker can exploit this to generate another
	// certificate with the same digital signature, allowing an attacker to
	// masquerade as the affected service.
	//
	// NOTE: This does not apply to trusted root certificates; TLS clients
	// trust them by their identity instead of the signature of their hash;
	// client code setting this field would need to exclude root certificates
	// from the determination whether the chain is vulnerable to weak
	// signature algorithms.
	//
	//   - https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html
	//   - https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html
	//   - https://superuser.com/questions/1122069/why-are-root-cas-with-sha1-signatures-not-a-risk
	//   - https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm
	//   - https://www.tenable.com/plugins/nessus/35291
	//   - https://docs.ostorlab.co/kb/WEAK_HASHING_ALGO/index.html
	WeakSignatureAlgorithm bool `json:"weak_signature_algorithm"`

	// SelfSignedIntermediateCerts indicates that an intermediate certificate
	// in the chain is self-signed.
	//
	// NOTE: This is unlikely to occur in practice, so we're likely not going
	// to keep this field.
	//
	// SelfSignedIntermediateCerts bool `json:"self_signed_intermediate_certs"`

	// This is a later TODO item.
	// RevokedCerts                bool `json:"revoked_certs"`
}

// CertChainPayload is the "parent" data structure which represents the
// information to be encoded as a payload and later decoded for use in
// reporting (and other) tools.
//
// This data structure is (future design) intended to be generated by this
// library and not directly by client code. Instead, client code is meant to
// pass in data using the `InputData` (name subject to change) struct.
type CertChainPayload struct {
	// FormatVersion is the format version of the generated certificate
	// metadata payload.
	FormatVersion int `json:"format_version"`

	// Errors is intended to represent a potential collection of errors
	// encountered while retrieving a certificate chain from a service. Due to
	// limitations in the JSON encoding/decoding process (exported fields are
	// required and interfaces do not provide those), we cannot provide this
	// collection as a collection of native Go errors.
	//
	// See also:
	//
	//   - https://stackoverflow.com/a/44990051/903870
	//
	Errors []string `json:"errors"`

	// CertChainOriginal is the original certificate chain entries encoded in
	// PEM format.
	//
	// Due to size constraints this field may not be populated if the user did
	// not explicitly opt into bundling the full certificate chain.
	CertChainOriginal []string `json:"cert_chain_original"`

	// CertChainSubset is a customized subset of the original certificate
	// chain metadata. This field should always be populated.
	CertChainSubset []Certificate `json:"cert_chain_subset"`

	// Server reflects the host value and resolved IP Address (which could be
	// the same value) used to retrieve the certificate chain.
	Server Server `json:"server"`

	// A fully-qualified domain name or IP Address in the Subject Alternate
	// Names (SANs) list for the leaf certificate.
	//
	// Depending on how the check_cert plugin was called this value may not be
	// set (e.g., the `server` flag is sufficient if specifying a valid FQDN
	// associated with the leaf certificate).
	DNSName string `json:"dns_name"`

	// TCPPort is the TCP port of the remote certificate-enabled service. This
	// is usually 443 (HTTPS) or 636 (LDAPS).
	TCPPort int `json:"tcp_port"`

	// Issues is an aggregated collection of problems detected for the
	// certificate chain.
	Issues CertificateChainIssues `json:"cert_chain_issues"`

	// ServiceState is the monitoring system's evaluated state for the service
	// check performed against a given certificate chain (e.g., OK, CRITICAL,
	// WARNING, UNKNOWN).
	ServiceState string `json:"service_state"`
}
