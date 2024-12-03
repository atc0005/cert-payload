// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

//nolint:gocognit // ignore function complexity
package payload_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	payload "github.com/atc0005/cert-payload"
	format1 "github.com/atc0005/cert-payload/format/v1"
)

// Example of parsing a previously retrieved Nagios XI API response (saved to
// a JSON file) from the /nagiosxi/api/v1/objects/servicestatus endpoint,
// extracting and decoding an embedded certificate metadata payload from each
// status entry and then unmarshalling the result into a specific format
// version (in this case format 1).
func Example_extractandDecodePayloadsFromNagiosXIAPI() {
	if len(os.Args) < 2 {
		fmt.Println("Missing input file")
		os.Exit(1)
	}

	sampleInputFile := os.Args[1]

	jsonInput, readErr := os.ReadFile(filepath.Clean(sampleInputFile))
	if readErr != nil {
		fmt.Println("Failed to read sample input file:", readErr)
		os.Exit(1)
	}

	var serviceStatusResponse ServiceStatusResponse
	decodeErr := json.Unmarshal(jsonInput, &serviceStatusResponse)
	if decodeErr != nil {
		fmt.Println("Failed to decode JSON input:", decodeErr)
		os.Exit(1)
	}

	for i, serviceStatus := range serviceStatusResponse.ServiceStatuses {
		fmt.Printf("\n\nProcess service check result %d ...", i)

		longServiceOutput := serviceStatus.LongServiceOutput

		// We use a pretend nagios.ExtractAndDecodePayload implementation.
		unencodedPayload, payloadDecodeErr := ExtractAndDecodePayload(
			longServiceOutput,
			"",
			DefaultASCII85EncodingDelimiterLeft,
			DefaultASCII85EncodingDelimiterRight,
		)

		if payloadDecodeErr != nil {
			fmt.Println(" WARNING: Failed to extract and decode payload from original plugin output:", payloadDecodeErr)
			// os.Exit(1)
			continue // we have some known cases of explicitly excluding payload generation
		}

		format1Payload := format1.CertChainPayload{}
		jsonDecodeErr := payload.Decode(unencodedPayload, &format1Payload)
		if jsonDecodeErr != nil {
			fmt.Println("Failed to decode JSON payload from original plugin output:", jsonDecodeErr)
			os.Exit(1)
		}

		if !format1Payload.Issues.Confirmed() {
			fmt.Print(" Skipping (no cert chain issues detected)")
			continue
		}

		fmt.Printf(
			"\nJSON payload for %s (flagged as problematic):\n",
			format1Payload.Server,
		)

		var prettyJSON bytes.Buffer
		err := json.Indent(&prettyJSON, []byte(unencodedPayload), "", "    ")
		if err == nil {
			_, _ = fmt.Fprintln(os.Stdout, prettyJSON.String())
		}

	}

}

// Pulled from go-nagios repo to remove external dependency.
const (
	// DefaultASCII85EncodingDelimiterLeft is the left delimiter often used
	// with ascii85-encoded data.
	DefaultASCII85EncodingDelimiterLeft string = "<~"

	// DefaultASCII85EncodingDelimiterRight is the right delimiter often used
	// with ascii85-encoded data.
	DefaultASCII85EncodingDelimiterRight string = "~>"
)

// ExtractAndDecodePayload is a mockup for nagios.ExtractAndDecodePayload.
func ExtractAndDecodePayload(text string, customRegex string, leftDelimiter string, rightDelimiter string) (string, error) {
	_ = text
	_ = customRegex
	_ = leftDelimiter
	_ = rightDelimiter

	return "placeholder", nil
}

// BoolString is a boolean value that is represented in JSON API input as a
// string value ("1" or "0").
type BoolString bool

// MarshalJSON implements the json.Marshaler interface. This compliments the
// custom Unmarshaler implementation to handle conversion of Go boolean field
// to JSON API expectations of a "1" or "0" string value.
func (bs BoolString) MarshalJSON() ([]byte, error) {
	switch bs {
	case true:
		return json.Marshal("1")
	case false:
		return json.Marshal("0")

	}

	return nil, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface to handle
// converting a string value of "1" or "0" to a native boolean value.
func (bs *BoolString) UnmarshalJSON(data []byte) error {

	// Per json.Unmarshaler convention we treat "null" value as a no-op.
	str := string(data)
	if str == "null" {
		return nil
	}

	// The 1 or 0 value is double-quoted, so we remove those before attempting
	// to parse as a boolean value.
	str = strings.Trim(str, `"`)

	boolValue, err := strconv.ParseBool(str)
	if err != nil {
		return err
	}

	*bs = BoolString(boolValue)

	return nil
}

// credit: https://romangaranin.net/posts/2021-02-19-json-time-and-golang/

// DateTimeLayout is the time layout format as used by the JSON API.
const DateTimeLayout string = "2006-01-02 15:04:05"

// DateTime is time value as represented in the JSON API input. It uses the
// DateTimeLayout format.
type DateTime time.Time

// String implements the fmt.Stringer interface as a convenience method.
func (dt DateTime) String() string {
	return dt.Format(DateTimeLayout)
}

// Format calls (time.Time).Format as a convenience for the caller.
func (dt DateTime) Format(layout string) string {
	return time.Time(dt).Format(layout)
}

// MarshalJSON implements the json.Marshaler interface. This compliments the
// custom Unmarshaler implementation to handle conversion of a native Go
// time.Time format to the JSON API expectations of a time value in the
// DateTimeLayout format.
func (dt DateTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(dt).Format(DateTimeLayout))
}

// UnmarshalJSON implements the json.Unmarshaler interface to handle
// converting a time string from the JSON API to a native Go time.Time value
// using the DateTimeLayout format.
func (dt *DateTime) UnmarshalJSON(data []byte) error {
	value := strings.Trim(string(data), `"`) // get rid of "
	if value == "" || value == "null" {

		// Per json.Unmarshaler convention we treat "null" value as a no-op.
		return nil
	}

	t, err := time.Parse(DateTimeLayout, value) // parse time
	if err != nil {
		return err
	}

	*dt = DateTime(t) // set result using the pointer

	return nil
}

type ServiceStatus struct {
	HostAddress          string     `json:"host_address"`
	HostAlias            string     `json:"host_alias"`
	HostName             string     `json:"host_name"`
	ServiceDescription   string     `json:"service_description"`
	ActiveChecksEnabled  BoolString `json:"active_checks_enabled"`
	NotificationsEnabled BoolString `json:"notifications_enabled"`
	LongServiceOutput    string     `json:"long_output"`
	Notes                string     `json:"notes"`
	StatusUpdateTime     DateTime   `json:"status_update_time"`
	LastCheck            DateTime   `json:"last_check"`
	NextCheck            DateTime   `json:"next_check"`
	LastNotification     DateTime   `json:"last_notification"`
	NextNotification     DateTime   `json:"next_notification"`
	RawPerfData          string     `json:"perfdata"`
}

type ServiceStatusResponse struct {
	RecordCount     int             `json:"recordcount"`
	ServiceStatuses []ServiceStatus `json:"servicestatus"`
}
