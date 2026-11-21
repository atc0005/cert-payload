// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package payload

import (
	"fmt"
	"strings"

	"github.com/atc0005/cert-payload/format/common"
	"github.com/atc0005/cert-payload/format/ffc"
	format0 "github.com/atc0005/cert-payload/format/v0"
	format1 "github.com/atc0005/cert-payload/format/v1"
	format2 "github.com/atc0005/cert-payload/format/v2"
	"github.com/atc0005/cert-payload/input"
)

// Payload format versions.
const (
	// UnstablePayloadVersion is the development or unstable format version.
	// Despite the low payload format version number this format is used for
	// ongoing development purposes. No stability guarantees are provided.
	UnstablePayloadVersion = common.UnstablePayloadVersion

	// Initial stable payload format version.
	StablePayloadFormatVersion1 = common.StablePayloadFormatVersion1

	// Stable payload format version.
	StablePayloadFormatVersion2 = common.StablePayloadFormatVersion2

	// MaxStablePayloadVersion indicates the newest stable payload format
	// version supported by this project. Update to the very latest project
	// release to support the most recent stable format version.
	MaxStablePayloadVersion = common.MaxStablePayloadVersion

	// MinStablePayloadVersion indicates the oldest stable payload format
	// version supported by this project.
	MinStablePayloadVersion = common.MinStablePayloadVersion

	// MaxPayloadVersion indicates the latest payload format version provided
	// by this project. This value does not necessarily indicate the latest
	// stable version. Update to the very latest project release to support
	// the most recent format version.
	MaxPayloadVersion = common.MaxPayloadVersion

	// MinPayloadVersion indicates the minimum payload format version
	// supported by this project.
	MinPayloadVersion = common.MinPayloadVersion
)

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = common.ErrMissingValue

	// ErrUnsupportedPayloadFormatVersion indicates that a specified payload
	// format version is unsupported.
	ErrUnsupportedPayloadFormatVersion = common.ErrUnsupportedPayloadFormatVersion

	// ErrPayloadFormatVersionTooOld indicates that a specified payload format
	// version is no longer supported.
	// ErrPayloadFormatVersionTooOld = common.ErrPayloadFormatVersionTooOld

	// ErrPayloadFormatVersionTooNew indicates that a specified payload format
	// version is not supported by this package release version.
	ErrPayloadFormatVersionTooNew = common.ErrPayloadFormatVersionTooNew

	// ErrUnsupportedPayloadFormatDecodingDestination indicates that a given
	// payload format decoding target is unsupported.
	ErrUnsupportedPayloadFormatDecodingDestination = common.ErrUnsupportedPayloadFormatDecodingDestination

	// ErrAutomaticPayloadFormatConversionFailed indicates that an attempt to
	// convert an older supported payload format to a newer supported payload
	// format failed. This could occur if attempting to convert the unstable
	// payload format 0 to a later stable format version (e.g., 1 or 2).
	ErrAutomaticPayloadFormatConversionFailed = common.ErrAutomaticPayloadFormatConversionFailed

	// ErrAutomaticPayloadFormatConversionUnsupported indicates that
	// automatically converting convert an older supported payload to a newer
	// payload format is unsupported.
	ErrAutomaticPayloadFormatConversionUnsupported = common.ErrAutomaticPayloadFormatConversionUnsupported

	// ErrAutomaticPayloadFormatConversionDisabled indicates that
	// automatically converting convert an older supported payload to a newer
	// payload format is disabled by the caller.
	ErrAutomaticPayloadFormatConversionDisabled = common.ErrAutomaticPayloadFormatConversionDisabled
)

// Encode processes the given certificate chain and returns a JSON payload of
// the specified format version. An error is returned if one occurs during
// processing or if an invalid payload version format is specified.
//
// Newer stable format versions offer more fields but are not guaranteed to be
// backwards compatible with earlier formats. While Forward Format
// Compatibility (FFC) attempts to make dealing with multiple payload format
// versions easier, there are some known shortcomings (e.g., placeholder or
// missing values when an older format does not provide fields that newer
// formats do).
//
// Any reporting/processing tools consuming payloads generated with this
// library will have best results if the generating application "locks" the
// payload format to a specific version (e.g., the `check_cert` plugin
// provides a `payload-format` flag for just such a purpose).
func Encode(payloadVersion int, inputData input.Values) ([]byte, error) {
	switch {
	case payloadVersion < MinPayloadVersion:
		return nil, fmt.Errorf("payload version %d specified (min stable is %d, min possible is %d): %w",
			payloadVersion,
			MinStablePayloadVersion,
			MinPayloadVersion,
			ErrUnsupportedPayloadFormatVersion,
		)

	case payloadVersion > MaxPayloadVersion:
		return nil, fmt.Errorf("payload version %d specified (max stable is %d, max possible is %d): %w",
			payloadVersion,
			MaxStablePayloadVersion,
			MaxPayloadVersion,
			ErrPayloadFormatVersionTooNew,
		)

	case payloadVersion == 0:
		return format0.Encode(inputData)

	case payloadVersion == 1:
		return format1.Encode(inputData)

	case payloadVersion == 2:
		return format2.Encode(inputData)

	// REMINDER: A new case statement needs to be added every time a new format version is introduced.

	default:
		return nil, fmt.Errorf("payload version %d specified: %w",
			payloadVersion,
			ErrUnsupportedPayloadFormatVersion,
		)
	}
}

// EncodeLatest processes the given input data and returns a JSON payload in
// the latest format version. An error is returned if one occurs during
// processing.
func EncodeLatest(inputData input.Values) ([]byte, error) {
	return latestVersionEncoder()(inputData)
}

// Decode accepts a certificate metadata payload and decodes/unmarshals it
// into the given destination.
//
// Automatic format conversion from an older stable format to a newer stable
// format is attempted (e.g., when attempting to decode format version 1 into
// format version 2). This is referred to by this library as "Forward Format
// Compatibility" (FFC).
//
// NOTE: FFC conversion from earlier stable payloads is a best-effort attempt;
// earlier stable payload formats may not provide all fields that later
// payload format versions do. Empty or placeholder values will be substituted
// as appropriate in those cases.
//
// To disable FFC conversion, see the Decode functions provided by the
// specific payload format version packages in this project (e.g.,
// [format2.Decode]).
//
// An error is returned if one occurs when decoding the payload or if the
// payload format version or given decoding destination is unsupported (e.g.,
// an attempt is made to decode a stable format version into the unstable
// format version).
func Decode(inputPayload string, dest interface{}) error {
	payloadFormatVersion, identifyErr := ffc.IdentifyPayloadFormatVersion(inputPayload)
	if identifyErr != nil {
		return identifyErr
	}

	validateErr := ffc.ValidatePayloadFormatVersion(payloadFormatVersion)
	if validateErr != nil {
		return validateErr
	}

	outputPayloadFormatVersion, outputIdentifyErr := identifyPayloadDecodeDestFormatVersion(dest)
	if outputIdentifyErr != nil {
		return outputIdentifyErr
	}

	compatibleDestErr := ffc.ValidatePayloadDecodingDestination(inputPayload, outputPayloadFormatVersion)
	if compatibleDestErr != nil {
		return compatibleDestErr
	}

	inputReader := strings.NewReader(inputPayload)

	// Assert that we've been given a pointer (we need write access to the
	// value) to a supported destination format to decode into.
	//
	// The fallback behavior for an unrecognized destination format is to
	// reject the destination format instead of attempting to "guess" a
	// specific version. Based on earlier validation checks in this function
	// we should not encounter that scenario (unless the given payload just
	// happens to share the same `format_version` field with a recognized
	// payload format version value).
	switch v := dest.(type) {
	case *format0.CertChainPayload:
		// Input format version other than 0 with dest format version 0 was
		// previously rejected by the [ffc.ValidatePayloadDecodingDestination]
		// function.
		return format0.Decode(v, inputReader, false)

	case *format1.CertChainPayload:
		// The caller has already rejected input format version 0 and anything
		// newer than this format version.
		return format1.Decode(v, inputReader)

	case *format2.CertChainPayload:
		// The caller has already rejected input format version 0 and anything
		// newer than this format version.
		//
		// This leaves an input payload format version 1 which can be forward
		// format converted into this format version or input payload format
		// version 2 which can be directly decoded. We explicitly enable FFC
		// behavior; FFC conversion will be skipped for v2 input payloads.
		return format2.Decode(v, inputReader, true)

	// REMINDER: A new case statement needs to be added every time a new format version is introduced.

	default:
		// This should *not* be reachable.
		return fmt.Errorf("valid payload version %d specified, but decoding target/destination is unrecognized: %w",
			payloadFormatVersion,
			ErrUnsupportedPayloadFormatDecodingDestination,
		)
	}
}

// AvailableFormatVersions provides a list of available format versions that
// client applications may choose from when encoding or decoding certificate
// metadata payloads.
func AvailableFormatVersions() []int {
	return append(
		[]int{UnstablePayloadVersion},
		AvailableStableFormatVersions()...,
	)
}

// AvailableStableFormatVersions provides a list of all available stable
// format versions that client applications may choose from when encoding or
// decoding certificate metadata payloads.
func AvailableStableFormatVersions() []int {
	stableFormats := make([]int, 0, MaxStablePayloadVersion)

	for i := MinStablePayloadVersion; i <= MaxStablePayloadVersion; i++ {
		stableFormats = append(stableFormats, i)
	}

	return stableFormats
}

// latestVersionEncoder is a helper function that provides the latest format
// version Encode function.
func latestVersionEncoder() func(input.Values) ([]byte, error) {
	return format2.Encode // REMINDER: This needs to be updated every time a new format version is introduced.
}

// identifyPayloadDecodeDestFormatVersion identifies the specified format version for a
// given payload decode destination. An error is returned if the
// identification attempt fails.
func identifyPayloadDecodeDestFormatVersion(dest interface{}) (int, error) {
	switch dest.(type) {
	case *format0.CertChainPayload:
		return common.UnstablePayloadVersion, nil

	case *format1.CertChainPayload:
		return common.StablePayloadFormatVersion1, nil

	case *format2.CertChainPayload:
		return common.StablePayloadFormatVersion2, nil

	// REMINDER: A new case statement needs to be added every time a new format version is introduced.

	default:
		return common.UnsupportedDecodeDestinationFormatVersion, fmt.Errorf("decoding target/destination is unrecognized: %w",
			common.ErrUnsupportedPayloadFormatDecodingDestination,
		)
	}
}
