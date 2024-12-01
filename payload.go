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

// Minimum and Maximum supported (stable) format versions. There may be format
// versions outside of these values but they are not considered
// stable/supported.
const (
	// MaxStablePayloadVersion indicates the newest stable payload format
	// version supported by this project. Update to the very latest project
	// release to support the most recent stable format version.
	MaxStablePayloadVersion int = 1

	// MinStablePayloadVersion indicates the oldest stable payload format
	// version supported by this project.
	MinStablePayloadVersion int = 1
)

// Minimum and Maximum format versions, regarding of stability expectations.
const (
	// UnstablePayloadVersion is the development or unstable format version.
	// Despite the low payload format version number this format is used for
	// ongoing development purposes. No stability guarantees are provided.
	UnstablePayloadVersion int = 0

	// MaxPayloadVersion indicates the latest payload format version provided
	// by this project. This value does not necessarily indicate the latest
	// stable version. Update to the very latest project release to support
	// the most recent format version.
	MaxPayloadVersion int = MaxStablePayloadVersion

	// MinPayloadVersion indicates the minimum payload format version
	// supported by this project.
	MinPayloadVersion int = UnstablePayloadVersion
)

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")

	// ErrUnsupportedPayloadFormatVersion indicates that a specified payload
	// format version is unsupported.
	ErrUnsupportedPayloadFormatVersion = errors.New("requested payload format version is unsupported")

	// ErrPayloadFormatVersionTooOld indicates that a specified payload format
	// version is no longer supported.
	// ErrPayloadFormatVersionTooOld = errors.New("requested payload format version is no longer supported")

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
	case format.Version < MinPayloadVersion:
		return fmt.Errorf("payload version %d specified: %w",
			format.Version,
			ErrUnsupportedPayloadFormatVersion,
		)

	case format.Version > MaxPayloadVersion:
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
		UnstablePayloadVersion,
		MaxStablePayloadVersion,
	}
}

// AvailableStableFormatVersions provides a list of all available stable
// format versions that client applications may choose from when encoding or
// decoding certificate metadata payloads.
func AvailableStableFormatVersions() []int {
	stableFormats := make([]int, 0, len(AvailableFormatVersions()))

	for i := MinStablePayloadVersion; i <= MaxStablePayloadVersion; i++ {
		stableFormats = append(stableFormats, i)
	}

	return stableFormats
}

// latestVersionEncoder is a helper function that provides the latest format
// version Encode function.
// func latestVersionEncoder() func(input.Values) ([]byte, error) {
// 	return format1.Encode
// }
