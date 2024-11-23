// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package payload

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	format0 "github.com/atc0005/cert-payload/format/v0"
	format1 "github.com/atc0005/cert-payload/format/v1"
	"github.com/atc0005/cert-payload/input"
)

const (
	// MaxSupportedPayloadVersion indicates the latest payload format version
	// supported by this project. Update to the very latest project release to
	// support the most recent format version.
	//
	// FIXME: Bump to `1` once the format stabilizes. Keep bumping version to
	// reflect the most recent format version.
	//
	MaxSupportedPayloadVersion int = 1 // FIXME: Only for testing purposes.

	// MinSupportedPayloadVersion indicates the oldest payload format version
	// supported by this project. Versions older than this are considered
	// unstable and associated with early development releases and are no
	// longer supported.
	//
	// FIXME: Bump to `1` once the format stabilizes.
	//
	MinSupportedPayloadVersion int = 0
)

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")

	// ErrUnsupportedPayloadFormatVersion indicates that a specified payload
	// format version is unsupported.
	ErrUnsupportedPayloadFormatVersion = errors.New("requested payload format version is unsupported")

	// ErrPayloadFormatVersionTooOld indicates that a specified payload format
	// version is no longer supported.
	ErrPayloadFormatVersionTooOld = errors.New("request payload format version is no longer supported")

	// ErrPayloadFormatVersionTooNew indicates that a specified payload format
	// version is not supported by this package release version.
	ErrPayloadFormatVersionTooNew = errors.New("requested payload format version is too new for this package version; check for newer update")
)

// minimumFormat reflects the target data structure that we'll unmarshal a
// JSON payload into in order to properly identify the format version.
type minimumFormat struct {
	Version int `json:"format_version"`
}

// Encode processes the given certificate chain and returns a JSON payload of
// the specified format version. An error is returned if one occurs during
// processing or if an invalid payload version format is specified.
func Encode(payloadVersion int, inputData input.Values) ([]byte, error) {
	switch {
	case payloadVersion < MinSupportedPayloadVersion:
		return nil, fmt.Errorf("payload version %d specified (min supported is %d): %w",
			payloadVersion,
			MinSupportedPayloadVersion,
			ErrPayloadFormatVersionTooOld,
		)

	case payloadVersion > MaxSupportedPayloadVersion:
		return nil, fmt.Errorf("payload version %d specified (max supported is %d): %w",
			payloadVersion,
			MaxSupportedPayloadVersion,
			ErrPayloadFormatVersionTooNew,
		)

	case payloadVersion == 0:
		return format0.Encode(inputData)

	case payloadVersion == 1:
		return format1.Encode(inputData)

	default:
		return nil, fmt.Errorf("payload version %d specified: %w",
			payloadVersion,
			ErrUnsupportedPayloadFormatVersion,
		)
	}
}

// EncodeLatest processes the given input data and returns a JSON payload in
// the latest format version. An error is returned if one occurs during
// processing or if an invalid payload version format is specified.
func EncodeLatest(inputData input.Values) ([]byte, error) {
	// 	latestEncoder := latestVersionEncoder()
	//
	// 	return latestEncoder(inputData)

	return format1.Encode(inputData)
}

// Decode accepts a certificate metadata payload and decodes/unmarshals it
// into the given destination. An error is returned if one occurs when
// decoding the payload or if the payload format version is unsupported.
func Decode(inputPayload string, dest interface{}) error {
	var format minimumFormat

	if err := json.Unmarshal([]byte(inputPayload), &format); err != nil {
		return fmt.Errorf(
			"failed to identify payload version: %w",
			ErrUnsupportedPayloadFormatVersion,
		)
	}

	switch {
	case format.Version < MinSupportedPayloadVersion:
		return fmt.Errorf("payload version %d specified: %w",
			format.Version,
			ErrPayloadFormatVersionTooOld,
		)

	case format.Version > MaxSupportedPayloadVersion:
		return fmt.Errorf("payload version %d specified: %w",
			format.Version,
			ErrPayloadFormatVersionTooNew,
		)
	}

	inputReader := strings.NewReader(inputPayload)

	// Assert that we've been given a pointer (we need write access to the
	// value) to a supported destination format to decode into.
	switch v := dest.(type) {
	case *format0.CertChainPayload:
		return format0.Decode(v, inputReader, false)

	case *format1.CertChainPayload:
		return format1.Decode(v, inputReader, false)
	default:

	}

	return nil
}

// AvailableFormatVersions provides a list of available format versions that
// client applications may choose from when encoding or decoding certificate
// metadata payloads.
func AvailableFormatVersions() []int {
	return []int{
		0,
		1, // FIXME: Fake value for testing (for now)
		2, // FIXME: Fake value for testing
		3, // FIXME: Fake value for testing
		4, // FIXME: Fake value for testing
	}
}

// latestVersionEncoder is a helper function that provides the latest format
// version Encode function.
// func latestVersionEncoder() func(input.Values) ([]byte, error) {
// 	return format1.Encode
// }
