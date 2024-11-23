// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Decode accepts a Reader which provides a certificate metadata payload and
// decodes/unmarshals it into the given destination. An error is returned if
// one occurs when decoding the payload.
func Decode(dest *CertChainPayload, input io.Reader, allowUnknownFields bool) error {
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
		return errors.New(
			"input contains multiple JSON objects; only one JSON object is supported",
		)
	}

	return nil
}
