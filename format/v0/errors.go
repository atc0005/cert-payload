// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format0

import "errors"

// NOTE: Format version 0 is for the UNSTABLE payload format version 0.
// You are encouraged to use a stable format version instead of this
// UNSTABLE format version for any real work; the UNSTABLE payload format
// version 0 is for prototype and testing purposes only.
var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")

	// ErrInvalidPayloadFormat indicates that a given payload is in an
	// unexpected format.
	ErrInvalidPayloadFormat = errors.New("given payload format is invalid")
)
