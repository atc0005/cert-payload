// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package textutils

import "bytes"

// Confirmed newline/EOL values.
const (
	WindowsEOL = "\r\n"
	MacEOL     = "\r"
	UnixEOL    = "\n"
)

// NormalizeNewlines replaces all Windows and Mac newlines with Unix newlines.
//
// Use this with caution if applying directly to binary files (e.g., it can
// break parsing of DER binary certificate files).)
func NormalizeNewlines(input []byte) []byte {
	input = bytes.ReplaceAll(input, []byte(WindowsEOL), []byte(UnixEOL))
	input = bytes.ReplaceAll(input, []byte(MacEOL), []byte(UnixEOL))

	return input
}

// StripBlankLines removes all blank lines from given input. Newlines are not
// normalized.
func StripBlankLines(input []byte) []byte {
	input = bytes.ReplaceAll(input, []byte(WindowsEOL+WindowsEOL), []byte(WindowsEOL))
	input = bytes.ReplaceAll(input, []byte(MacEOL+MacEOL), []byte(MacEOL))
	input = bytes.ReplaceAll(input, []byte(UnixEOL+UnixEOL), []byte(UnixEOL))

	return input
}

// StripBlankAndNormalize removes all blank lines and normalizes all remaining
// newlines (converting Windows and Mac-specific EOLs to Unix EOLs) from given
// input.
func StripBlankAndNormalize(input []byte) []byte {
	return bytes.ReplaceAll(NormalizeNewlines(input), []byte("\n\n"), []byte("\n"))
}
