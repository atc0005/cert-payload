// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format0

// Confirmed is a helper function to indicate whether issues are present
// with the evaluated certificate chain.
func (cci CertificateChainIssues) Confirmed() bool {
	switch {
	case cci.MissingIntermediateCerts:
		return true

	case cci.MissingSANsEntries:
		return true

	case cci.DuplicateCerts:
		return true

	case cci.MisorderedCerts:
		return true

	case cci.ExpiredCerts:
		return true

	case cci.HostnameMismatch:
		return true

	case cci.SelfSignedLeafCert:
		return true

	case cci.WeakSignatureAlgorithm:
		return true

	default:
		return false
	}
}
