package format0

import "errors"

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")
)
