// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto"
	"crypto/md5" //nolint:gosec // Used to verify MD5WithRSA signatures
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/atc0005/cert-payload/internal/textutils"
)

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")
)

// Certificate type values for display and comparison purposes.
const (
	CertChainPositionLeaf           string = "leaf"
	CertChainPositionLeafSelfSigned string = "leaf; self-signed"
	CertChainPositionIntermediate   string = "intermediate"
	CertChainPositionRoot           string = "root"
	CertChainPositionUnknown        string = "UNKNOWN cert chain position; please submit a bug report"
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

// isSelfSigned is a helper function that attempts to validate whether a given
// certificate is self-signed by asserting that its signature can be validated
// with its own public key. Any errors encountered during signature validation
// are assumed to be an indication that a certificate is not self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Issuer.String() == cert.Subject.String() {
		sigVerifyErr := cert.CheckSignature(
			cert.SignatureAlgorithm,
			cert.RawTBSCertificate,
			cert.Signature,
		)

		switch {
		// examine signature verification errors
		case errors.Is(sigVerifyErr, x509.InsecureAlgorithmError(cert.SignatureAlgorithm)):

			// fmt.Println("errors.Is match")

			// Handle MD5 signature verification ourselves since Go considers
			// the MD5 algorithm to be insecure (rightly so).
			if cert.SignatureAlgorithm == x509.MD5WithRSA {

				// fmt.Println("SignatureAlgorithm match")

				// nolint:gosec
				h := md5.New()
				if _, err := h.Write(cert.RawTBSCertificate); err != nil {
					// fmt.Println(
					// 	"isSelfSigned: failed to generate MD5 hash of RawTBSCertificate:",
					// 	err,
					// )
					return false
				}
				hashedBytes := h.Sum(nil)

				if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {

					// fmt.Println("type assertion for rsa.PublicKey successful")

					md5RSASigVerifyErr := rsa.VerifyPKCS1v15(
						pub, crypto.MD5, hashedBytes, cert.Signature,
					)

					switch {

					case md5RSASigVerifyErr != nil:
						// fmt.Println(
						// 	"isSelfSigned: failed to validate MD5WithRSA signature:",
						// 	md5RSASigVerifyErr,
						// )

						return false

					default:
						// fmt.Println("MD5 signature verified")

						return true
					}
				}
			}

			// TODO: Do we need to check this ourselves in Go 1.18?
			// if cert.SignatureAlgorithm == x509.SHA1WithRSA {
			// }

			return false

		// no problems verifying self-signed signature
		case sigVerifyErr == nil:

			return true
		}
	}

	return false
}

// ChainPosition receives a cert and the cert chain that it belongs to and
// returns a string indicating what position or "role" it occupies in the
// certificate chain.
//
// https://en.wikipedia.org/wiki/X.509
// https://tools.ietf.org/html/rfc5280
func ChainPosition(cert *x509.Certificate, certChain []*x509.Certificate) string {

	// We require a valid certificate chain. Fail if not provided.
	if certChain == nil {
		return CertChainPositionUnknown
	}

	switch cert.Version {

	// Because v1 and v2 certs lack the more descriptive "intention"
	// fields of v3 certs, we are limited in what checks we can apply. We
	// rely on a combination of self-signed and literal chain position to
	// help determine the purpose of each v1 and v2 certificate.
	case 1, 2:

		switch {
		case isSelfSigned(cert):
			if cert == certChain[0] {
				return CertChainPositionLeafSelfSigned
			}

			return CertChainPositionRoot

		default:
			if cert == certChain[0] {
				return CertChainPositionLeaf
			}

			return CertChainPositionIntermediate
		}

	case 3:

		switch {
		case isSelfSigned(cert):

			// FIXME: What pattern to use for self-signed v3 leaf?

			// The cA boolean indicates whether the certified public key may be
			// used to verify certificate signatures.
			if cert.IsCA {
				return CertChainPositionRoot
			}

			// The Extended key usage extension indicates one or more purposes
			// for which the certified public key may be used, in addition to
			// or in place of the basic purposes indicated in the key usage
			// extension. In general, this extension will appear only in end
			// entity certificates.
			if cert.ExtKeyUsage != nil {
				return CertChainPositionLeafSelfSigned
			}

			// CA certs are intended for cert and CRL signing.
			//
			// In the majority of cases (all?), the cA boolean field will
			// already be set if either of these under `X509v3 Basic
			// Constraints` are specified.
			switch cert.KeyUsage {
			case cert.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign:
				return CertChainPositionRoot
			case cert.KeyUsage | x509.KeyUsageCertSign:
				return CertChainPositionRoot
			default:
				return CertChainPositionLeafSelfSigned
			}

		default:

			// The cA boolean indicates whether the certified public key may be
			// used to verify certificate signatures.
			if cert.IsCA {
				return CertChainPositionIntermediate
			}

			// The Extended key usage extension indicates one or more purposes
			// for which the certified public key may be used, in addition to
			// or in place of the basic purposes indicated in the key usage
			// extension. In general, this extension will appear only in end
			// entity certificates.
			if cert.ExtKeyUsage != nil {
				return CertChainPositionLeaf
			}

			// CA certs are intended for cert and CRL signing.
			//
			// In the majority (all?) of cases, the cA boolean field will
			// already be set if either of these under `X509v3 Basic
			// Constraints` are specified.
			switch cert.KeyUsage {
			case cert.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign:
				return CertChainPositionIntermediate
			case cert.KeyUsage | x509.KeyUsageCertSign:
				return CertChainPositionIntermediate
			default:
				return CertChainPositionLeaf
			}

		}
	}

	// no known match, so position unknown
	return CertChainPositionUnknown

}

// MaxLifespanInDays returns the maximum lifespan in days for a given
// certificate from the date it was issued until the time it is scheduled to
// expire.
func MaxLifespanInDays(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func MaxLifespanInDays: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	maxCertLifespan := cert.NotAfter.Sub(cert.NotBefore)
	daysMaxLifespan := int(math.Trunc(maxCertLifespan.Hours() / 24))

	return daysMaxLifespan, nil
}

// NumLeafCerts receives a slice of x509 certificates and returns a count of
// leaf certificates present in the chain.
func NumLeafCerts(certChain []*x509.Certificate) int {
	var num int
	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		switch chainPos {
		case CertChainPositionLeaf:
			num++
		case CertChainPositionLeafSelfSigned:
			num++
		}
	}

	return num
}

// NumIntermediateCerts receives a slice of x509 certificates and returns a
// count of intermediate certificates present in the chain.
func NumIntermediateCerts(certChain []*x509.Certificate) int {
	var num int
	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos == CertChainPositionIntermediate {
			num++
		}
	}

	return num
}

// NonRootCerts receives a slice of x509 certificates and returns a collection
// of certificates present in the chain which are not root certificates.
func NonRootCerts(certChain []*x509.Certificate) []*x509.Certificate {
	numPresent := NumLeafCerts(certChain) + NumIntermediateCerts(certChain)
	nonRootCerts := make([]*x509.Certificate, 0, numPresent)

	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos != CertChainPositionRoot {
			nonRootCerts = append(nonRootCerts, cert)
		}
	}

	return nonRootCerts
}

// LeafCerts receives a slice of x509 certificates and returns a (potentially
// empty) collection of leaf certificates present in the chain.
func LeafCerts(certChain []*x509.Certificate) []*x509.Certificate {
	numPresent := NumLeafCerts(certChain)
	leafCerts := make([]*x509.Certificate, 0, numPresent)

	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		switch chainPos {
		case CertChainPositionLeaf:
			leafCerts = append(leafCerts, cert)
		case CertChainPositionLeafSelfSigned:
			leafCerts = append(leafCerts, cert)
		}

	}

	return leafCerts
}

// HasExpiringCert receives a slice of x509 certificates, CRITICAL age
// threshold and WARNING age threshold values and ignoring any certificates
// already expired, uses the provided thresholds to determine if any
// certificates are about to expire. A boolean value is returned to indicate
// the results of this check.
func HasExpiringCert(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) bool {
	for idx := range certChain {
		switch {
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageCritical):
			return true
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageWarning):
			return true
		}
	}

	return false

}

// HasExpiredCert receives a slice of x509 certificates and indicates whether
// any of the certificates in the chain have expired.
func HasExpiredCert(certChain []*x509.Certificate) bool {

	for idx := range certChain {
		if certChain[idx].NotAfter.Before(time.Now()) {
			return true
		}
	}

	return false

}

// FormattedExpiration receives a Time value and converts it to a string
// representing the largest useful whole units of time in days and hours. For
// example, if a certificate has 1 year, 2 days and 3 hours remaining until
// expiration, this function will return the string '367d 3h remaining', but
// if only 3 hours remain then '3h remaining' will be returned. If a
// certificate has expired, the 'ago' suffix will be used instead. For
// example, if a certificate has expired 3 hours ago, '3h ago' will be
// returned.
func FormattedExpiration(expireTime time.Time) string {

	// hoursRemaining := time.Until(certificate.NotAfter)/time.Hour)/24,
	timeRemaining := time.Until(expireTime).Hours()

	var certExpired bool
	var formattedTimeRemainingStr string
	var daysRemainingStr string
	var hoursRemainingStr string

	// Flip sign back to positive, note that cert is expired for later use
	if timeRemaining < 0 {
		certExpired = true
		timeRemaining *= -1
	}

	// Toss remainder so that we only get the whole number of days
	daysRemaining := math.Trunc(timeRemaining / 24)

	if daysRemaining > 0 {
		daysRemainingStr = fmt.Sprintf("%dd", int64(daysRemaining))
	}

	// Multiply the whole number of days by 24 to get the hours value, then
	// subtract from the original number of hours until cert expiration to get
	// the number of hours leftover from the days calculation.
	hoursRemaining := math.Trunc(timeRemaining - (daysRemaining * 24))

	hoursRemainingStr = fmt.Sprintf("%dh", int64(hoursRemaining))

	// Only join days and hours remaining if there *are* days remaining.
	switch {
	case daysRemainingStr != "":
		formattedTimeRemainingStr = strings.Join(
			[]string{daysRemainingStr, hoursRemainingStr},
			" ",
		)
	default:
		formattedTimeRemainingStr = hoursRemainingStr
	}

	switch {
	case !certExpired:
		formattedTimeRemainingStr = strings.Join([]string{formattedTimeRemainingStr, "remaining"}, " ")
	case certExpired:
		formattedTimeRemainingStr = strings.Join([]string{formattedTimeRemainingStr, "ago"}, " ")
	}

	return formattedTimeRemainingStr

}

// ExpirationStatus receives a certificate and the expiration threshold values
// for CRITICAL and WARNING states and returns a human-readable string
// indicating the overall status at a glance. If requested, an expiring or
// expired certificate is marked as ignored.
func ExpirationStatus(cert *x509.Certificate, ageCritical time.Time, ageWarning time.Time, ignoreExpiration bool) string {
	var expiresText string
	certExpiration := cert.NotAfter

	var lifeRemainingText string
	if remaining, err := LifeRemainingPercentageTruncated(cert); err == nil {
		lifeRemainingText = fmt.Sprintf(" (%d%%)", remaining)
	}

	switch {
	case certExpiration.Before(time.Now()) && ignoreExpiration:
		expiresText = fmt.Sprintf(
			"[EXPIRED, IGNORED] %s%s",
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(time.Now()):
		expiresText = fmt.Sprintf(
			"[EXPIRED] %s%s",
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(ageCritical) && ignoreExpiration:
		expiresText = fmt.Sprintf(
			"[EXPIRING, IGNORED] %s%s",
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(ageCritical):
		expiresText = fmt.Sprintf(
			"[%s] %s%s",
			StateCRITICALLabel,
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(ageWarning) && ignoreExpiration:
		expiresText = fmt.Sprintf(
			"[EXPIRING, IGNORED] %s%s",
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(ageWarning):
		expiresText = fmt.Sprintf(
			"[%s] %s%s",
			StateWARNINGLabel,
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	default:
		expiresText = fmt.Sprintf(
			"[%s] %s%s",
			StateOKLabel,
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)

	}

	return expiresText
}

// HasWeakSignatureAlgorithm evaluates the given certificate (within the
// context of a given certificate chain) and indicates whether a known weak
// signature algorithm was found.
//
// Root certificates evaluate to false (by default) as TLS clients trust them
// by their identity instead of the signature of their hash.
//
// If explicitly requested root certificates are also evaluated.
//
// - https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html
// - https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html
// - https://superuser.com/questions/1122069/why-are-root-cas-with-sha1-signatures-not-a-risk
// - https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm
// - https://www.tenable.com/plugins/nessus/35291
// - https://docs.ostorlab.co/kb/WEAK_HASHING_ALGO/index.html
func HasWeakSignatureAlgorithm(cert *x509.Certificate, certChain []*x509.Certificate, evalRoot bool) bool {
	chainPos := ChainPosition(cert, certChain)

	if chainPos == CertChainPositionRoot && !evalRoot {
		return false
	}

	switch {
	case cert.SignatureAlgorithm == x509.MD2WithRSA:
		return true

	case cert.SignatureAlgorithm == x509.MD5WithRSA:
		return true

	case cert.SignatureAlgorithm == x509.SHA1WithRSA:
		return true

	case cert.SignatureAlgorithm == x509.DSAWithSHA1:
		return true

	case cert.SignatureAlgorithm == x509.ECDSAWithSHA1:
		return true

	default:
		return false
	}
}

// FormatCertSerialNumber receives a certificate serial number in its native
// type and formats it in the text format used by OpenSSL (and many other
// tools).
//
// Example: DE:FD:50:2B:C5:7F:79:F4
func FormatCertSerialNumber(sn *big.Int) string {

	// convert serial number from native *bit.Int format to a hex string
	// snHexStr := sn.Text(16)
	//
	// use Sprintf hex formatting in order to retain leading zero (GH-114)
	// credit: inspired by discussion on mozilla/tls-observatory#245
	snHexStr := fmt.Sprintf("%X", sn.Bytes())

	delimiterPosition := 2
	delimiter := ":"

	// ignore the leading negative sign if present
	if sn.Sign() == -1 {
		snHexStr = strings.TrimPrefix(snHexStr, "-")
	}

	formattedSerialNum := textutils.InsertDelimiter(snHexStr, delimiter, delimiterPosition)
	formattedSerialNum = strings.ToUpper(formattedSerialNum)

	// add back negative sign if originally present
	if sn.Sign() == -1 {
		return "-" + formattedSerialNum
	}

	return formattedSerialNum

}

// IsExpiredCert receives a x509 certificate and returns a boolean value
// indicating whether the cert has expired.
func IsExpiredCert(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// ExpiresInDays evaluates the given certificate and returns the number of
// days until the certificate expires. If already expired, a negative number
// is returned indicating how many days the certificate is past expiration.
//
// An error is returned if the pointer to the given certificate is nil.
func ExpiresInDays(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func ExpiresInDays: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	timeRemaining := time.Until(cert.NotAfter).Hours()

	// Toss remainder so that we only get the whole number of days
	daysRemaining := int(math.Trunc(timeRemaining / 24))

	return daysRemaining, nil
}

// ExpiresInDaysPrecise evaluates the given certificate and returns the number
// of days until the certificate expires as a floating point number. This
// number is rounded down.
//
// If already expired, a negative number is returned indicating how many days
// the certificate is past expiration.
//
// An error is returned if the pointer to the given certificate is nil.
func ExpiresInDaysPrecise(cert *x509.Certificate) (float64, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func ExpiresInDaysPrecise: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	timeRemaining := time.Until(cert.NotAfter).Hours()

	// Round down to the nearest two decimal places.
	daysRemaining := timeRemaining / 24
	daysRemaining = math.Floor(daysRemaining*100) / 100

	return daysRemaining, nil
}

// LifeRemainingPercentage returns the percentage of remaining time before a
// certificate expires.
func LifeRemainingPercentage(cert *x509.Certificate) (float64, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func LifeRemainingPercentage: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	if IsExpiredCert(cert) {
		return 0.0, nil
	}

	daysMaxLifespan, err := MaxLifespanInDays(cert)
	if err != nil {
		return 0, err
	}

	daysRemaining, err := ExpiresInDays(cert)
	if err != nil {
		return 0, err
	}

	certLifeRemainingPercentage := float64(daysRemaining) / float64(daysMaxLifespan) * 100

	return certLifeRemainingPercentage, nil
}

// LifeRemainingPercentageTruncated returns the truncated percentage of
// remaining time before a certificate expires.
func LifeRemainingPercentageTruncated(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func LifeRemainingPercentageTruncated: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	if IsExpiredCert(cert) {
		return 0, nil
	}

	certLifeRemainingPercentage, err := LifeRemainingPercentage(cert)
	if err != nil {
		return 0, err
	}

	certLifespanRemainingTruncated := int(math.Trunc(certLifeRemainingPercentage))

	return certLifespanRemainingTruncated, nil
}
