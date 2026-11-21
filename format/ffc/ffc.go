// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package ffc

import (
	"encoding/json"
	"fmt"

	"github.com/atc0005/cert-payload/format/common"
)

// IdentifyPayloadFormatVersion identifies the specified format version for a
// given payload. An error is returned if the identification attempt fails.
func IdentifyPayloadFormatVersion(inputPayload string) (int, error) {
	var format common.MinimumFormat

	if err := json.Unmarshal([]byte(inputPayload), &format); err != nil {
		return common.UnsupportedPayloadFormatVersion, fmt.Errorf(
			"failed to identify payload version: %w",
			common.ErrUnsupportedPayloadFormatVersion,
		)
	}

	return format.Version, nil
}

// ValidatePayloadFormatVersion asserts that the given format version is
// within the range of available/supported format versions.
func ValidatePayloadFormatVersion(payloadFormatVersion int) error {
	switch {
	case payloadFormatVersion < common.MinPayloadVersion:
		return fmt.Errorf("payload version %d specified: %w",
			payloadFormatVersion,
			common.ErrUnsupportedPayloadFormatVersion,
		)

	case payloadFormatVersion > common.MaxPayloadVersion:
		return fmt.Errorf("payload version %d specified: %w",
			payloadFormatVersion,
			common.ErrPayloadFormatVersionTooNew,
		)
	}

	return nil
}

// ValidatePayloadDecodingDestination asserts that the given input payload is
// compatible with the given payload decoding destination. This also asserts
// that Forward Format Compatibility is viable between the given input payload
// format version and the decoding destination.
func ValidatePayloadDecodingDestination(inputPayload string, outputDestFormatVer int) error {
	inputPayloadFormatVersion, inputIdentifyErr := IdentifyPayloadFormatVersion(inputPayload)
	if inputIdentifyErr != nil {
		return inputIdentifyErr
	}

	// Assert that the given payload format version is within known range.
	//
	// The most likely cause of failure here is for a consuming application
	// processing a payload to have an older version of this library than the
	// generating application which created it.
	validateErr := ValidatePayloadFormatVersion(inputPayloadFormatVersion)
	if validateErr != nil {
		return validateErr
	}

	return AssertInputFormatCompatibleWithDecodeDest(inputPayloadFormatVersion, outputDestFormatVer)
}

// AssertInputFormatCompatibleWithDecodeDest is a helper function that asserts
// the given input format is compatible with the decode destination.
func AssertInputFormatCompatibleWithDecodeDest(inputFormatVersion int, outputDestFormatVersion int) error {
	switch {
	// Object to:
	// - attempts to "upgrade" unstable format to stable
	// - attempts to "downgrade" stable format to unstable
	case inputFormatVersion == common.UnstablePayloadVersion && outputDestFormatVersion != common.UnstablePayloadVersion:
		return fmt.Errorf("input payload version %d given; decoding unstable input format version %d into stable destination format version %d: %w",
			inputFormatVersion,
			common.UnstablePayloadVersion,
			outputDestFormatVersion,
			common.ErrUnsupportedPayloadFormatDecodingDestination,
		)

	// Object to:
	// - attempts to "downgrade" stable format to earlier stable format
	case inputFormatVersion > outputDestFormatVersion:
		return fmt.Errorf("input payload version %d given; decoding newer format version into earlier format version %d: %w",
			inputFormatVersion,
			outputDestFormatVersion,
			common.ErrUnsupportedPayloadFormatDecodingDestination,
		)

	case !assertForwardFormatCompatibility(inputFormatVersion, outputDestFormatVersion):
		return fmt.Errorf("input payload version %d and destination format version %d given; forward format conversion unavailable: %w",
			inputFormatVersion,
			outputDestFormatVersion,
			common.ErrUnsupportedPayloadFormatDecodingDestination,
		)

	default:
		// Input payload format version is equal to or lower than destination
		// format version and Forward Format Compatibility (FFC) checks
		// passed.
		//
		// No special case format version matching (case statements above) was
		// made, so as a general rule, this is a compatible scenario.
		return nil
	}
}

// assertInputFormatCompatibleWithDecodeDest is a helper function that asserts
// Forward Format Compatibility (FFC) between the given input format and the
// decode destination.
func assertForwardFormatCompatibility(inputPayloadFormatVersion int, outputPayloadFormatVersion int) bool {
	stableInputFormatVersion := inputPayloadFormatVersion > common.UnstablePayloadVersion
	unstableInputFormatVersion := inputPayloadFormatVersion == common.UnstablePayloadVersion

	downgradeAttempt := inputPayloadFormatVersion > outputPayloadFormatVersion
	upgradeAttempt := inputPayloadFormatVersion < outputPayloadFormatVersion
	formatVersionsAreEqual := inputPayloadFormatVersion == outputPayloadFormatVersion

	switch {
	case downgradeAttempt && stableInputFormatVersion:
		// Object to:
		// - attempts to "downgrade" stable format to earlier stable format
		// - attempts to "downgrade" stable format to unstable
		return false

	case upgradeAttempt && unstableInputFormatVersion:
		// Object to:
		// - attempts to "upgrade" unstable format to stable
		return false

	case formatVersionsAreEqual:
		// no conversion necessary: input payload matches dest
		return true

	case inputPayloadFormatVersion == common.StablePayloadFormatVersion1:
		switch outputPayloadFormatVersion {
		case common.StablePayloadFormatVersion2:
			// payload format 2 a superset of format 1
			return true

		// REMINDER: A new inner case statement needs to be added every time a new format version is introduced.

		default:
			return false
		}

	case inputPayloadFormatVersion == common.StablePayloadFormatVersion2:
		switch outputPayloadFormatVersion {
		case common.StablePayloadFormatVersion2:
			// this is a duplication of the `formatVersionsAreEqual` assertion
			// which is being used to effectively "hold the spot" for the next
			// format version
			return true

		// REMINDER: A new inner case statement needs to be added every time a new format version is introduced.

		default:
			return false
		}

	// REMINDER: A new outer case statement needs to be added every time a new format version is introduced.

	default:
		return true
	}
}
