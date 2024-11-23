// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.
//
// Code in this file inspired by or generated with the help of ChatGPT, OpenAI.

package shared

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/atc0005/cert-payload/internal/certs"
)

// CertExpirationMetadata is a bundle of certificate expiration related
// metadata used when preparing a certificate payload for inclusion in plugin
// output.
type CertExpirationMetadata struct {
	ValidityPeriodDays     int
	DaysRemainingTruncated int
	DaysRemainingPrecise   float64
	CertLifetimePercent    int
}

// LookupCertExpMetadata is a helper function used to lookup specific
// certificate expiration metadata values used when preparing a certificate
// payload for inclusion in plugin output.
func LookupCertExpMetadata(cert *x509.Certificate, certNumber int, certChain []*x509.Certificate) (CertExpirationMetadata, error) {
	if cert == nil {
		return CertExpirationMetadata{}, fmt.Errorf(
			"cert in chain position %d of %d is nil: %w",
			certNumber,
			len(certChain),
			certs.ErrMissingValue,
		)
	}

	certLifetime, certLifeTimeErr := certs.LifeRemainingPercentageTruncated(cert)
	if certLifeTimeErr != nil {
		return CertExpirationMetadata{}, fmt.Errorf(
			"error calculating lifetime for cert %q: %w",
			cert.Subject.CommonName,
			certLifeTimeErr,
		)
	}

	daysRemainingTruncated, expLookupErr := certs.ExpiresInDays(cert)
	if expLookupErr != nil {
		return CertExpirationMetadata{}, fmt.Errorf(
			"error calculating the number of days until the certificate %q expires: %w",
			cert.Subject.CommonName,
			expLookupErr,
		)
	}

	daysRemainingPrecise, expLookupErrPrecise := certs.ExpiresInDaysPrecise(cert)
	if expLookupErrPrecise != nil {
		return CertExpirationMetadata{}, fmt.Errorf(
			"error calculating the number of days until the certificate %q expires: %w",
			cert.Subject.CommonName,
			expLookupErr,
		)
	}

	validityPeriodDays, lifespanLookupErr := certs.MaxLifespanInDays(cert)
	if lifespanLookupErr != nil {
		return CertExpirationMetadata{}, fmt.Errorf(
			"error calculating the maximum lifespan in days for certificate %q: %w",
			cert.Subject.CommonName,
			lifespanLookupErr,
		)
	}

	return CertExpirationMetadata{
		CertLifetimePercent:    certLifetime,
		DaysRemainingPrecise:   daysRemainingPrecise,
		DaysRemainingTruncated: daysRemainingTruncated,
		ValidityPeriodDays:     validityPeriodDays,
	}, nil
}

// LookupValidityPeriodDescription is a helper function to lookup human
// readable validity period description for a certificate's maximum lifetime
// value.
func LookupValidityPeriodDescription(cert *x509.Certificate) string {
	maxLifeSpanInDays, err := certs.MaxLifespanInDays(cert)
	if err != nil {
		return ValidityPeriodUNKNOWN
	}

	maxLifeSpanInTruncatedYears := int(math.Trunc(float64(maxLifeSpanInDays) / 365))

	switch {
	case maxLifeSpanInTruncatedYears >= 1:
		return fmt.Sprintf("%d year", maxLifeSpanInTruncatedYears)

	default:
		return fmt.Sprintf("%d days", maxLifeSpanInDays)
	}
}

// isBetween is a small helper function to determine whether a given value is
// between a specified minimum and maximum number (inclusive).
// func isBetween(val, min, max int) bool {
// 	if (val >= min) && (val <= max) {
// 		return true
// 	}
//
// 	return false
// }

// HasWeakSignatureAlgorithm indicates that the certificate chain has been
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
//
// TODO: Replace with slog debug calls
func HasWeakSignatureAlgorithm(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	nonRootCerts := certs.NonRootCerts(certChain)

	// log := cfg.Log.With().Logger()

	// log.Debug().Int("num_certs", len(nonRootCerts)).Msg("Evaluating non-root certificates for weak signature algorithm")

	// logIgnored := func(cert *x509.Certificate) {
	// 	log.Debug().
	// 		Bool("cert_signature_algorithm_ok", true).
	// 		Str("cert_signature_algorithm", cert.SignatureAlgorithm.String()).
	// 		Str("cert_common_name", cert.Subject.CommonName).
	// 		Msg("Certificate signature algorithm ignored")
	// }

	// 	logWeak := func(cert *x509.Certificate) {
	// 		log.Debug().
	// 			Bool("cert_signature_algorithm_ok", false).
	// 			Str("cert_signature_algorithm", cert.SignatureAlgorithm.String()).
	// 			Str("cert_common_name", cert.Subject.CommonName).
	// 			Msg("Certificate signature algorithm weak")
	// 	}
	//
	// 	logOK := func(cert *x509.Certificate) {
	// 		log.Debug().
	// 			Bool("cert_signature_algorithm_ok", true).
	// 			Str("cert_signature_algorithm", cert.SignatureAlgorithm.String()).
	// 			Str("cert_common_name", cert.Subject.CommonName).
	// 			Msg("Certificate signature algorithm ok")
	// 	}

	for _, cert := range nonRootCerts {
		// chainPos := certs.ChainPosition(cert, certChain)

		// 		switch {
		// 		// case chainPos == "root":
		// 		// 	logIgnored(cert)
		//
		// 		case certs.HasWeakSignatureAlgorithm(cert, certChain, false):
		// 			logWeak(cert)
		//
		// 			return true
		//
		// 		default:
		// 			logOK(cert)
		// 		}

		if certs.HasWeakSignatureAlgorithm(cert, certChain, false) {
			return true
		}

	}

	return false
}

// HasSelfSignedLeaf asserts that a given certificate chain has a self-signed
// leaf certificate.
func HasSelfSignedLeaf(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	leafCerts := certs.LeafCerts(certChain)
	for _, leafCert := range leafCerts {
		// NOTE: We may need to perform actual signature verification here for
		// the most reliable results.
		//
		if leafCert.Issuer.String() == leafCert.Subject.String() {
			return true
		}
	}

	return false
}

// HasDuplicateCertsInChain asserts that there are duplicate certificates
// within a given certificate chain.
func HasDuplicateCertsInChain(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	certIdx := make(map[string]int, len(certChain))

	for _, cert := range certChain {
		certIdx[certs.FormatCertSerialNumber(cert.SerialNumber)]++
	}

	for _, v := range certIdx {
		if v > 1 {
			return true
		}
	}

	return false
}

// HasMissingSANsEntries asserts that the first leaf certificate for a given
// certificate chain is missing Subject Alternate Names (SANs) entries.
func HasMissingSANsEntries(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	leafCerts := certs.LeafCerts(certChain)

	if len(leafCerts) == 0 {
		return false
	}

	if len(leafCerts[0].DNSNames) > 0 {
		return false
	}

	return true
}

// HasExpiredCerts asserts that the given certificate chain has one or more
// expired certificates.
func HasExpiredCerts(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	return certs.HasExpiredCert(certChain)
}

// HasExpiringCerts asserts that the given certificate chain has one or more
// expiring certificates.
func HasExpiringCerts(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) bool {
	if len(certChain) == 0 {
		return false
	}

	return certs.HasExpiringCert(certChain, ageCritical, ageWarning)
}

// HasHostnameMismatch asserts that the given hostname value is valid for the
// first certificate in the chain. If an empty hostname value or empty
// certificate chain is provided a mismatch cannot be determined and false is
// returned.
func HasHostnameMismatch(hostnameValue string, certChain []*x509.Certificate) bool {
	switch {
	case len(certChain) == 0:
		return false
	case hostnameValue == "":
		return false
	default:
		return certChain[0].VerifyHostname(hostnameValue) != nil
	}
}

// HasMissingIntermediateCerts asserts that a given certificate chain is
// missing intermediate certificates.
func HasMissingIntermediateCerts(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	return certs.NumIntermediateCerts(certChain) == 0
}

// HasMisorderedCerts asserts that a given certificate chain contains
// certificates out of the expected order.
func HasMisorderedCerts(certChain []*x509.Certificate) bool {
	if len(certChain) == 0 {
		return false
	}

	for i := 0; i < len(certChain)-1; i++ {
		currentCert := certChain[i]
		nextCert := certChain[i+1]

		// fmt.Printf("Comparing %s against %s\n", currentCert.Subject, nextCert.Subject)

		// Check if the issuer of the current certificate matches the subject
		// of the next certificate.
		if !pkixNameEqual(currentCert.Issuer, nextCert.Subject) {
			// return fmt.Errorf("certificate at index %d is not signed by the certificate at index %d", i, i+1)
			return true
		}

		// Verify the current certificate is signed by the next certificate's
		// public key.
		if err := currentCert.CheckSignatureFrom(nextCert); err != nil {
			// return fmt.Errorf("signature verification failed between certificate at index %d and %d: %w", i, i+1, err)
			return true
		}
	}

	return false
}

// pkixNameEqual compares two pkix.Name values for equality.
func pkixNameEqual(name1 pkix.Name, name2 pkix.Name) bool {
	return name1.CommonName == name2.CommonName &&
		strings.Join(name1.Organization, ",") == strings.Join(name2.Organization, ",") &&
		strings.Join(name1.OrganizationalUnit, ",") == strings.Join(name2.OrganizationalUnit, ",") &&
		strings.Join(name1.Locality, ",") == strings.Join(name2.Locality, ",") &&
		strings.Join(name1.Province, ",") == strings.Join(name2.Province, ",") &&
		strings.Join(name1.Country, ",") == strings.Join(name2.Country, ",")
}

// ErrorsToStrings converts a collectin of error interfaces to string values.
func ErrorsToStrings(errs []error) []string {
	stringErrs := make([]string, 0, len(errs))
	for _, err := range errs {
		stringErrs = append(stringErrs, err.Error())
	}

	return stringErrs
}
