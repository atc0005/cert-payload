// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/atc0005/cert-payload/format/common"
	"github.com/atc0005/cert-payload/format/ffc"
)

// Decode accepts a Reader which provides a certificate metadata payload and
// decodes/unmarshals it into the given destination. An error is returned if
// one occurs when decoding the payload.
//
// NOTE: Unlike newer stable payload format versions, automatic Forward Format
// Compatibility (FFC) is unsupported for format version 1.
func Decode(dest *CertChainPayload, input io.Reader) error {
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

	switch inputPayloadFormatVersion {
	case FormatVersion:
		return decode(dest, decoderReader, false)

	default:
		// fail conversion; FFC is unsupported and we have a mismatch between
		// input payload format version and format version of decoding
		// destination.
		return fmt.Errorf(
			"input payload version %d incompatible with this package: %w",
			inputPayloadFormatVersion,
			common.ErrUnsupportedPayloadFormatDecodingDestination,
		)
	}
}

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
