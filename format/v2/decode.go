// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/atc0005/cert-payload/format/common"
	"github.com/atc0005/cert-payload/format/ffc"
	format1 "github.com/atc0005/cert-payload/format/v1"
)

// Decode accepts a certificate metadata payload and decodes/unmarshals it
// into the given destination. If enabled, automatic Forward Format
// Compatibility (FFC) conversion is used.
//
// If the input payload is format version 2 FFC conversion is not used and a
// clean decoding result is provided. If FFC is enabled and the input payload
// is format version 1 (v1) then an automatic conversion from v1 format to
// version 2 (v2) is attempted. If the input payload is newer than payload v2
// an error is returned: downgrading format versions is not supported.
//
// An error is returned if one occurs when decoding the payload or if the
// payload format version is unsupported.
//
// NOTE: payload format v1 does not provide all fields that payload format v2
// does. Empty or placeholder values will be substituted as appropriate during
// conversion.
func Decode(dest *CertChainPayload, input io.Reader, allowAutomaticForwardFormatCompatibility bool) error {
	data, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf(
			"failed to read input cert payload: %w",
			err,
		)
	}

	decoderReader := bytes.NewReader(data)

	inputPayloadFormatVersion, inputIdentifyErr := ffc.IdentifyPayloadFormatVersion(string(data))
	if inputIdentifyErr != nil {
		return inputIdentifyErr
	}

	// Assert that the given payload format version is within known range.
	//
	// The most likely cause of failure here is for a consuming application
	// processing a payload to have an older version of this library than the
	// generating application which created it.
	validateErr := ffc.ValidatePayloadFormatVersion(inputPayloadFormatVersion)
	if validateErr != nil {
		return validateErr
	}

	switch {
	case inputPayloadFormatVersion == FormatVersion:
		return decode(dest, decoderReader, false)

	case allowAutomaticForwardFormatCompatibility:
		// Assert that input payload format version is compatible with this
		// format version.
		ffcErr := ffc.AssertInputFormatCompatibleWithDecodeDest(inputPayloadFormatVersion, FormatVersion)
		if ffcErr != nil {
			return ffcErr
		}

		// Perform forward compatible conversion
		return Format1ToFormat2(decoderReader, dest)

	default:
		// fail conversion; FFC is disabled and we have a mismatch between
		// input payload format version and format version of decoding
		// destination.
		return fmt.Errorf(
			"input payload version %d incompatible with this package: %w",
			inputPayloadFormatVersion,
			common.ErrAutomaticPayloadFormatConversionDisabled,
		)

	}
}

// decode is a helper function to concentrate the core decoding logic.
func decode(dest *CertChainPayload, input io.Reader, allowUnknownFields bool) error {
	dec := json.NewDecoder(input)

	if !allowUnknownFields {
		dec.DisallowUnknownFields()
	}

	// Decode the first JSON object.
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf(
			"failed to decode cert payload: %w",
			err,
		)
	}

	// If there is more than one object, something is off.
	if dec.More() {
		return fmt.Errorf(
			"input contains multiple JSON objects;"+
				" only one JSON object is supported: %w",
			ErrInvalidPayloadFormat,
		)
	}

	return nil
}

// Format1ToFormat2 accepts an io.Reader wrapped original input payload format
// version 1 and a destination format version 2 [format2.CertChainPayload].
//
// The input payload is first decoded into a format version 1
// [format1.CertChainPayload] using [format1.Decode]; any
// limitations/requirements for [format1.Decode] apply here also.
//
// Payload format version 1 struct fields are then manually copied to format
// version 2 fields by constructing equivalent values wherever possible.
// Completely missing optional values are omitted and missing required values
// are given a placeholder value that indicates the original value is missing.
func Format1ToFormat2(input io.Reader, fv2 *CertChainPayload) error {
	if input == nil || fv2 == nil {
		return fmt.Errorf(
			"convert from payload format version 1 to payload format version 2: %w",
			common.ErrMissingValue,
		)
	}

	fv1 := format1.CertChainPayload{}
	decodeErr := format1.Decode(&fv1, input)
	if decodeErr != nil {
		return decodeErr
	}

	fv2.FormatVersion = FormatVersion
	fv2.Errors = fv1.Errors
	fv2.CertChainOriginal = fv1.CertChainOriginal

	v2CertChainSubset := make([]Certificate, 0, len(fv1.CertChainSubset))
	for _, v1CertSubset := range fv1.CertChainSubset {
		v2Cert := Certificate{
			Subject:                   v1CertSubset.Subject,
			CommonName:                v1CertSubset.CommonName,
			SANsEntries:               v1CertSubset.SANsEntries,
			SANsEntriesCount:          v1CertSubset.SANsEntriesCount,
			Issuer:                    v1CertSubset.Issuer,
			IssuerShort:               v1CertSubset.IssuerShort,
			SerialNumber:              v1CertSubset.SerialNumber,
			IssuedOn:                  v1CertSubset.IssuedOn,
			ExpiresOn:                 v1CertSubset.ExpiresOn,
			DaysRemaining:             v1CertSubset.DaysRemaining,
			DaysRemainingTruncated:    v1CertSubset.DaysRemainingTruncated,
			LifetimePercent:           v1CertSubset.LifetimePercent,
			ValidityPeriodDescription: v1CertSubset.ValidityPeriodDescription,
			ValidityPeriodDays:        v1CertSubset.ValidityPeriodDays,
			Summary:                   v1CertSubset.Summary,
			Status: CertificateStatus{
				OK:       v1CertSubset.Status.OK,
				Expiring: v1CertSubset.Status.Expiring,
				Expired:  v1CertSubset.Status.Expired,
			},
			SignatureAlgorithm: v1CertSubset.SignatureAlgorithm,
			PublicKeyAlgorithm: common.OriginalValueUnavailable,
			Type:               v1CertSubset.Type,
		}

		v2CertChainSubset = append(v2CertChainSubset, v2Cert)
	}

	fv2.CertChainSubset = v2CertChainSubset
	// fv2.Owners = []string{}     // Not provided by format version 1, but not a required value so we leave it empty.
	// fv2.ServiceEnvironment = "" // Not provided by format version 1, but not a required value so we leave it empty.
	fv2.Server = Server{
		HostValue: fv1.Server.HostValue,
		IPAddress: fv1.Server.IPAddress,
	}
	fv2.DNSName = fv1.DNSName
	fv2.TCPPort = fv1.TCPPort
	fv2.Issues = CertificateChainIssues{
		MissingIntermediateCerts: fv1.Issues.MissingIntermediateCerts,
		MissingSANsEntries:       fv1.Issues.MissingSANsEntries,
		DuplicateCerts:           fv1.Issues.DuplicateCerts,
		MisorderedCerts:          fv1.Issues.MisorderedCerts,
		ExpiredCerts:             fv1.Issues.ExpiredCerts,
		HostnameMismatch:         fv1.Issues.HostnameMismatch,
		SelfSignedLeafCert:       fv1.Issues.SelfSignedLeafCert,
		WeakSignatureAlgorithm:   fv1.Issues.WeakSignatureAlgorithm,
	}
	fv2.ServiceState = fv1.ServiceState

	return nil
}
