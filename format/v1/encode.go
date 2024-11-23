// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format1

import (
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

		var SANsEntries []string
		if inputData.OmitSANsEntries {
			SANsEntries = nil
		} else {
			SANsEntries = origCert.DNSNames
		}

		validityPeriodDescription := shared.LookupValidityPeriodDescription(origCert)

		certSubset := Certificate{
			Subject:                   origCert.Subject.String(),
			CommonName:                origCert.Subject.CommonName,
			SANsEntries:               SANsEntries,
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

	certChainIssues := CertificateChainIssues{
		MissingIntermediateCerts: shared.HasMissingIntermediateCerts(certChain),
		MissingSANsEntries:       shared.HasMissingSANsEntries(certChain),
		DuplicateCerts:           shared.HasDuplicateCertsInChain(certChain),
		MisorderedCerts:          shared.HasMisorderedCerts(certChain),
		ExpiredCerts:             shared.HasExpiredCerts(certChain),
		HostnameMismatch:         shared.HasHostnameMismatch(hostnameValue, certChain),
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

	payload := CertChainPayload{
		FormatVersion:     FormatVersion,
		Errors:            shared.ErrorsToStrings(inputData.Errors),
		TestingOutofTacos: false, // fake; force payload conflict with format version 0
		CertChainOriginal: certChainOriginal,
		CertChainSubset:   certChainSubset,
		Server:            inputData.Server.HostValue,
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
