// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package common

// MinimumFormat reflects the target data structure that we'll unmarshal a
// JSON payload into in order to properly identify the format version.
type MinimumFormat struct {
	Version int `json:"format_version"`
}
