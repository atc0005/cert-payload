// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format1

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atc0005/cert-payload/format/internal/shared"
	"github.com/atc0005/cert-payload/input"
	"github.com/atc0005/cert-payload/internal/certs"
)

// Encode processes the given certificate chain and returns a JSON payload of
// the specified format version. An error is returned if one occurs during
// processing or if an invalid payload version format is specified.
func Encode(inputData input.Values) ([]byte, error) {
	// FIXME: We may want to accept this as an argument for testing purposes.
	now := time.Now().UTC()

	certsExpireAgeWarning := now.AddDate(0, 0, inputData.ExpirationAgeInDaysWarningThreshold)
	certsExpireAgeCritical := now.AddDate(0, 0, inputData.ExpirationAgeInDaysCriticalThreshold)

	certChain := inputData.CertChain

	certChainSubset := make([]Certificate, 0, len(certChain))
	for certNumber, origCert := range certChain {
		if origCert == nil {
			return nil, fmt.Errorf(
				"cert in chain position %d of %d is nil: %w",
				certNumber,
				len(certChain),
				ErrMissingValue,
			)
		}

		expiresText := certs.ExpirationStatus(
			origCert,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
			false,
		)

		hasExpiring := shared.HasExpiringCerts(certChain, certsExpireAgeCritical, certsExpireAgeWarning)
		hasExpired := shared.HasExpiredCerts(certChain)

		certStatus := CertificateStatus{
			OK:       !hasExpired && !hasExpiring,
			Expiring: hasExpiring,
			Expired:  hasExpired,
		}

		certExpMeta, lookupErr := shared.LookupCertExpMetadata(origCert, certNumber, certChain)
		if lookupErr != nil {
			return nil, lookupErr
		}

		validityPeriodDescription := shared.LookupValidityPeriodDescription(origCert)

		certSubset := Certificate{
			Subject:                   origCert.Subject.String(),
			CommonName:                origCert.Subject.CommonName,
			SANsEntries:               sansEntries(origCert, inputData),
			SANsEntriesCount:          len(origCert.DNSNames),
			Issuer:                    origCert.Issuer.String(),
			IssuerShort:               origCert.Issuer.CommonName,
			SerialNumber:              certs.FormatCertSerialNumber(origCert.SerialNumber),
			IssuedOn:                  origCert.NotBefore,
			ExpiresOn:                 origCert.NotAfter,
			DaysRemaining:             certExpMeta.DaysRemainingPrecise,
			DaysRemainingTruncated:    certExpMeta.DaysRemainingTruncated,
			LifetimePercent:           certExpMeta.CertLifetimePercent,
			ValidityPeriodDescription: validityPeriodDescription,
			ValidityPeriodDays:        certExpMeta.ValidityPeriodDays,
			Summary:                   expiresText,
			Status:                    certStatus,
			SignatureAlgorithm:        origCert.SignatureAlgorithm.String(),
			Type:                      certs.ChainPosition(origCert, certChain),
		}

		certChainSubset = append(certChainSubset, certSubset)
	}

	hostVal := hostnameValue(inputData)

	certChainIssues := CertificateChainIssues{
		MissingIntermediateCerts: shared.HasMissingIntermediateCerts(certChain),
		MissingSANsEntries:       shared.HasMissingSANsEntries(certChain),
		DuplicateCerts:           shared.HasDuplicateCertsInChain(certChain),
		MisorderedCerts:          shared.HasMisorderedCerts(certChain),
		ExpiredCerts:             shared.HasExpiredCerts(certChain),
		HostnameMismatch:         shared.HasHostnameMismatch(hostVal, certChain),
		SelfSignedLeafCert:       shared.HasSelfSignedLeaf(certChain),
		WeakSignatureAlgorithm:   shared.HasWeakSignatureAlgorithm(certChain),
	}

	// Only if the user explicitly requested the full cert payload do we
	// include it (due to significant payload size increase and risk of
	// exceeding size constraints).
	var certChainOriginal []string
	switch {
	case inputData.IncludeFullCertChain:
		pemCertChain, err := shared.CertChainToPEM(certChain)
		if err != nil {
			return nil, fmt.Errorf("error converting original cert chain to PEM format: %w", err)
		}

		certChainOriginal = pemCertChain

	default:
		certChainOriginal = nil
	}

	server := Server{
		HostValue: inputData.Server.HostValue,
		IPAddress: inputData.Server.IPAddress,
	}

	payload := CertChainPayload{
		FormatVersion:     FormatVersion,
		Errors:            shared.ErrorsToStrings(inputData.Errors),
		CertChainOriginal: certChainOriginal,
		CertChainSubset:   certChainSubset,
		Server:            server,
		DNSName:           inputData.DNSName,
		TCPPort:           inputData.TCPPort,
		Issues:            certChainIssues,
		ServiceState:      inputData.ServiceState,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf(
			"error marshaling cert chain payload as JSON: %w",
			err,
		)
	}

	return payloadJSON, nil
}

// sansEntries evaluates given input options and either returns all Subject
// Alternate Names for a given certificate or nil to indicate that a sysadmin
// opted out of recording SANs entries.
func sansEntries(cert *x509.Certificate, inputData input.Values) []string {
	if inputData.OmitSANsEntries {
		return nil
	}

	return cert.DNSNames
}

// hostnameValue is a helper function that evaluates the given hostname values
// used to perform a certificate service check and returns either the default
// server value or a custom DNS name value (e.g., virtual host value) if one
// was specified.
func hostnameValue(inputData input.Values) string {
	// Default to using the server FQDN or IP Address used to make the
	// connection as our hostname value.
	hostnameValue := inputData.Server.HostValue

	// Allow the user to explicitly specify which hostname should be used
	// for comparison against the leaf certificate. This works for a
	// certificate retrieved by a server as well as a certificate
	// retrieved from a file.
	if inputData.DNSName != "" {
		hostnameValue = inputData.DNSName
	}

	return hostnameValue
}
