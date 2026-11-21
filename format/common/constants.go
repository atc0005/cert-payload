// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package common

const (
	// OriginalValueUnavailable indicates that the original value needed for
	// forward format conversion (e.g., converting from format version 1 to
	// formation version 2) is unavailable or "missing".
	OriginalValueUnavailable string = "missing"
)

// Payload format versions.
const (
	// UnsupportedPayloadFormatVersion indicates that a payload format version
	// is unrecognized or unsupported.
	UnsupportedPayloadFormatVersion int = -1

	// UnsupportedDecodeDestinationFormatVersion indicates that a given
	// decoding destination format version could not be determined.
	UnsupportedDecodeDestinationFormatVersion int = -1

	// UnstablePayloadVersion is the development or unstable format version.
	// Despite the low payload format version number this format is used for
	// ongoing development purposes. No stability guarantees are provided.
	UnstablePayloadVersion int = 0

	// Initial stable payload format version.
	StablePayloadFormatVersion1 int = 1

	// Stable payload format version.
	StablePayloadFormatVersion2 int = 2

	// MaxStablePayloadVersion indicates the newest stable payload format
	// version supported by this project. Update to the very latest project
	// release to support the most recent stable format version.
	MaxStablePayloadVersion int = StablePayloadFormatVersion2 // REMINDER: This needs to be updated every time a new format version is introduced.

	// MinStablePayloadVersion indicates the oldest stable payload format
	// version supported by this project.
	MinStablePayloadVersion int = StablePayloadFormatVersion1

	// MaxPayloadVersion indicates the latest payload format version provided
	// by this project. This value does not necessarily indicate the latest
	// stable version. Update to the very latest project release to support
	// the most recent format version.
	MaxPayloadVersion int = MaxStablePayloadVersion

	// MinPayloadVersion indicates the minimum payload format version
	// supported by this project.
	MinPayloadVersion int = UnstablePayloadVersion
)
