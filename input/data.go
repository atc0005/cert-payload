// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package input

import "crypto/x509"

// Server reflects the host value and resolved IP Address (which could be
// the same value) used to retrieve the certificate chain.
type Server struct {
	// HostValue is the original hostname value. While usually a FQDN, this
	// value could also be a fixed IP Address (e.g., if SNI support wasn't
	// used to retrieve the certificate chain).
	HostValue string

	// IPAddress is the resolved IP Address for the hostname value used to
	// retrieve a certificate chain.
	IPAddress string
}

// Values is a collection of input data values that was provided to the plugin
// (e.g., CLI flags), gathered by the plugin (e.g., CertChain) without any
// sysadmin-specified filtering applied (e.g., "ignore expiring intermediates"
// to create a certificate metadata payload.
type Values struct {
	// CertChainOriginal is the original certificate chain entries as-is
	// without any "problematic" entries removed.
	CertChain []*x509.Certificate

	// Errors represents a potential collection of errors encountered while
	// retrieving a certificate chain from a service.
	Errors []error

	// IncludeFullCertChain indicates that the full certificate chain should
	// be included in the generated metadata payload. This is not included by
	// default due to the not insignificant size increase.
	IncludeFullCertChain bool

	// OmitSANsEntries indicates that Subject Alternate Names entries should
	// be omitted from the generate metadata payload. This option may be
	// chosen to reduce the output payload size.
	OmitSANsEntries bool

	// ExpirationAgeInDaysWarningThreshold is the number of days remaining
	// before certificate expiration when the certificate should be considered
	// to be expiring and in a WARNING state.
	ExpirationAgeInDaysWarningThreshold int

	// ExpirationAgeInDaysCriticalThreshold is the number of days remaining
	// before certificate expiration when the certificate should be considered
	// to be expiring and in a CRITICAL state.
	ExpirationAgeInDaysCriticalThreshold int

	// Server is the host value (FQDN or IP Address) and resolved IP Address
	// which was used to retrieve the certificate chain.
	Server Server

	// A fully-qualified domain name or IP Address in the Subject Alternate
	// Names (SANs) list for the leaf certificate.
	//
	// Depending on how the check_cert plugin was called this value may not be
	// set. For example, the `server` flag is sufficient if specifying a valid
	// FQDN associated with the leaf certificate or if SNI support is not
	// used.
	DNSName string

	// TCPPort is the TCP port of the remote certificate-enabled service. This
	// is usually 443 (HTTPS) or 636 (LDAPS).
	TCPPort int

	// ServiceState is the monitoring system's evaluated state for the service
	// check performed against a given certificate chain (e.g., OK, CRITICAL,
	// WARNING, UNKNOWN).
	ServiceState string
}
