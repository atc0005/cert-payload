package format1

import "errors"

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")

	// ErrInvalidPayloadFormat indicates that a given payload is in an
	// unexpected format.
	ErrInvalidPayloadFormat = errors.New("given payload format is invalid")
)
