// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package shared

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// CertChainToJSON encodes the certificate chain in PEM format and then
// marshals the PEM-encoded certificates to JSON. An error is returned if an
// invalid cert chain is provided or if the marshaling process fails.
func CertChainToJSON(certChain []*x509.Certificate) ([]byte, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf(
			"failed to encode cert chain: %w",
			ErrMissingValue,
		)
	}

	pemCerts, err := CertChainToPEM(certChain)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to encode cert chain: %w",
			err,
		)
	}

	certChainJSON, err := json.Marshal(pemCerts)
	if err != nil {
		return nil, fmt.Errorf(
			"error marshaling JSON: %w",
			err,
		)
	}

	return certChainJSON, nil
}

// CertChainToPEM encodes the certificate chain in PEM format as a slice of
// string values. An error is returned if an invalid cert chain is provided.
func CertChainToPEM(certChain []*x509.Certificate) ([]string, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf(
			"failed to encode cert chain: %w",
			ErrMissingValue,
		)
	}

	pemCerts := make([]string, 0, len(certChain))

	var buf bytes.Buffer
	for i, cert := range certChain {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		err := pem.Encode(&buf, pemBlock)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to encode cert %d in PEM format: %w",
				i,
				err,
			)
		}

		pemCerts = append(pemCerts, buf.String())

		buf.Reset()
	}

	return pemCerts, nil
}
