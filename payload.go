// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package payload

import (
	"errors"
	"time"
)

// Nagios plugin/service check state "labels". These values are used (where
// applicable) by the CertChainPayload `ServiceState` field.
const (
	StateOKLabel        string = "OK"
	StateWARNINGLabel   string = "WARNING"
	StateCRITICALLabel  string = "CRITICAL"
	StateUNKNOWNLabel   string = "UNKNOWN"
	StateDEPENDENTLabel string = "DEPENDENT"
)

// Validity period keywords intended as human readable output.
//
// Common historical certificate lifetimes:
//
// - 5 year (1825 days, 60 months)
// - 3 year (1185 days, 39 months)
// - 2 year (825 days, 27 months)
// - 1 year (398 days, 13 months)
//
// See also:
//
// - https://www.sectigo.com/knowledge-base/detail/TLS-SSL-Certificate-Lifespan-History-2-3-and-5-year-validity/kA01N000000zFKp
// - https://support.sectigo.com/Com_KnowledgeDetailPage?Id=kA03l000000o6cv
// - https://www.digicert.com/faq/public-trust-and-certificates/how-long-are-tls-ssl-certificate-validity-periods
// - https://docs.digicert.com/en/whats-new/change-log/older-changes/change-log--2023.html#certcentral--changes-to-multi-year-plan-coverage
// - https://knowledge.digicert.com/quovadis/ssl-certificates/ssl-general-topics/maximum-validity-changes-for-tls-ssl-to-drop-to-825-days-in-q1-2018
// - https://chromium.googlesource.com/chromium/src/+/666712ff6c7ba7aa5da380bc0a617b637c9232b3/net/docs/certificate_lifetimes.md
// - https://www.entrust.com/blog/2017/03/maximum-certificate-lifetime-drops-to-825-days-in-2018
const (
	ValidityPeriod1Year   string = "1 year"
	ValidityPeriod90Days  string = "90 days"
	ValidityPeriod45Days  string = "45 days"
	ValidityPeriodUNKNOWN string = "UNKNOWN"
)

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")
)

// CertificateStatus is the overall status of a certificate.
//
// - no problems (ok)
// - expired
// - expiring (based on given threshold values)
// - revoked (not yet supported)
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

	// Type indicates the type of certificate (leaf, intermediate or root).
	Type string `json:"type"`
}

// CertificateChainIssues is an aggregated collection of problems detected for
// the certificate chain.
type CertificateChainIssues struct {
	// MissingIntermediateCerts indicates that intermediate certificates are
	// missing from the certificate chain.
	MissingIntermediateCerts bool `json:"missing_intermediate_certs"`

	// MissingSANsEntries indicates that SANs entries are missing from a leaf
	// certificate within the certificates chain.
	MissingSANsEntries bool `json:"missing_sans_entries"`

	// MultipleLeafCerts indicates that there are more than the single
	// permitted leaf certificate in the certificate chain.
	MultipleLeafCerts bool `json:"multiple_leaf_certs"`

	// MisorderedCerts indicates that certificates in the chain are out of the
	// expected order.
	//
	// E.g., instead of leaf, intermediate(s), root (technically not best
	// practice) the chain has something like leaf, root, intermediate(s) or
	// intermediates and then leaf.
	// MisorderedCerts bool `json:"misordered_certs"`

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
type CertChainPayload struct {
	// CertChainOriginal is the original certificate chain entries encoded in
	// PEM format.
	//
	// Due to size constraints this field may not be populated if the user did
	// not explicitly opt into bundling the full certificate chain.
	CertChainOriginal []string `json:"cert_chain_original"`

	// CertChainSubset is a customized subset of the original certificate
	// chain metadata. This field should always be populated.
	CertChainSubset []Certificate `json:"cert_chain_subset"`

	// Server is the FQDN or IP Address specified to the plugin which was used
	// to retrieve the certificate chain.
	//
	// TODO: Considering making this a struct with fields for resolved IP
	// Address and original CLI flag value (often a FQDN, but just as often a
	// fixed IP Address).
	Server string `json:"server"`

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
