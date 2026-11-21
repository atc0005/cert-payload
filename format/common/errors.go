// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package common

import "errors"

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

	// ErrUnsupportedPayloadFormatDecodingDestination indicates that a given
	// payload format decoding target is unsupported.
	ErrUnsupportedPayloadFormatDecodingDestination = errors.New("unsupported payload format decoding destination")

	// ErrAutomaticPayloadFormatConversionFailed indicates that an attempt to
	// convert an older supported payload format to a newer supported payload
	// format failed. This could occur if attempting to convert the unstable
	// payload format 0 to a later stable format version (e.g., 1 or 2).
	ErrAutomaticPayloadFormatConversionFailed = errors.New("automatic older payload format conversion to newer format failed")

	// ErrAutomaticPayloadFormatConversionUnsupported indicates that
	// automatically converting convert an older supported payload to a newer
	// payload format is unsupported.
	ErrAutomaticPayloadFormatConversionUnsupported = errors.New("automatic payload format conversion is unsupported")

	// ErrAutomaticPayloadFormatConversionDisabled indicates that
	// automatically converting convert an older supported payload to a newer
	// payload format is disabled by the caller.
	ErrAutomaticPayloadFormatConversionDisabled = errors.New("automatic payload format conversion is disabled")
)
