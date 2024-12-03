// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package format0

import (
	"fmt"
	"math"

	"github.com/atc0005/cert-payload/internal/certs"
)

// Certificate evaluation status values.
const (
	// CertNotPresent indicates that a certificate chain was successfully
	// retrieved, but a specific certificate was not present in the chain.
	CertNotPresentInChain string = "not present"

	// CertChainNotFound indicates that a certificate chain was not
	// successfully retrieved, so we can not make a determination whether a
	// specific certificate is present in the chain.
	CertChainNotFound string = "cert chain not found"
)

// LowestCertLifetimeValue returns the lowest remaining lifetime between
// certificates in the certificate chain.
func (cs Certificates) LowestCertLifetimeValue() float64 {
	var lowest float64

	// Seed starting value
	if len(cs) > 0 {
		lowest = cs[0].DaysRemaining
	}

	for _, cert := range cs {
		if cert.DaysRemaining < lowest {
			lowest = cert.DaysRemaining
		}
	}

	return lowest
}

// HighestCertLifetimeValue returns the highest remaining lifetime between
// certificates in the certificate chain.
func (cs Certificates) HighestCertLifetimeValue() float64 {
	var highest float64

	for _, cert := range cs {
		if cert.DaysRemaining > highest {
			highest = cert.DaysRemaining
		}
	}

	return highest
}

// LowestLeafCertLifetimeValue returns the lowest remaining lifetime between
// leaf certificates in the certificate chain.
func (cs Certificates) LowestLeafCertLifetimeValue() float64 {
	var lowest float64

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			if lowest == 0 {
				lowest = cert.DaysRemaining
			}

			if cert.DaysRemaining < lowest {
				lowest = cert.DaysRemaining
			}
		}
	}

	return lowest
}

// HighestLeafCertLifetimeValue returns the highest remaining lifetime between
// leaf certificates in the certificate chain.
func (cs Certificates) HighestLeafCertLifetimeValue() float64 {
	var highest float64

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			if cert.DaysRemaining > highest {
				highest = cert.DaysRemaining
			}
		}
	}

	return highest
}

// HasExpiringLeafs indicates that there is an expiring intermediate
// certificate in the certificate chain.
func (cs Certificates) HasExpiringLeafs() bool {
	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			if cert.Status.Expiring {
				return true
			}
		}
	}

	return false
}

// HasExpiredLeafs indicates that there is an expired leaf certificate
// in the certificate chain.
func (cs Certificates) HasExpiredLeafs() bool {
	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			if cert.Status.Expired {
				return true
			}
		}
	}

	return false
}

// LowestIntermediateCertLifetimeValue returns the lowest remaining lifetime
// between intermediate certificates in the certificate chain.
func (cs Certificates) LowestIntermediateCertLifetimeValue() float64 {
	var lowest float64

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionIntermediate {
			if lowest == 0 {
				lowest = cert.DaysRemaining
			}

			if cert.DaysRemaining < lowest {
				lowest = cert.DaysRemaining
			}
		}
	}

	return lowest
}

// HighestIntermediateCertLifetimeValue returns the highest remaining lifetime
// between intermediate certificates in the certificate chain.
func (cs Certificates) HighestIntermediateCertLifetimeValue() float64 {
	var highest float64

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionIntermediate {
			if cert.DaysRemaining > highest {
				highest = cert.DaysRemaining
			}
		}
	}

	return highest
}

// HasExpiringIntermediates indicates that there is an expiring intermediate
// certificate in the certificate chain.
func (cs Certificates) HasExpiringIntermediates() bool {
	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionIntermediate {
			if cert.Status.Expiring {
				return true
			}
		}
	}

	return false
}

// HasExpiredIntermediates indicates that there is an expired intermediate
// certificate in the certificate chain.
func (cs Certificates) HasExpiredIntermediates() bool {
	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionIntermediate {
			if cert.Status.Expired {
				return true
			}
		}
	}

	return false
}

// IntermediateExpiringFirst returns the intermediate certificate expiring
// first in the certificate chain or a zero value Certificate.
func (cs Certificates) IntermediateExpiringFirst() Certificate {
	var lowestIntermediate Certificate

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionIntermediate {
			if lowestIntermediate.IssuedOn.IsZero() {
				lowestIntermediate = cert
			}

			if cert.DaysRemaining < lowestIntermediate.DaysRemaining {
				lowestIntermediate = cert
			}
		}
	}

	return lowestIntermediate
}

// FirstLeaf returns the first leaf certificate in the certificate chain or a
// zero value Certificate if there isn't one (e.g., a manually constructed
// chain).
func (cs Certificates) FirstLeaf() Certificate {
	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			return cert
		}
	}

	return Certificate{}
}

// LeafExpirationDescription returns a human readable version of the
// expiration details for the first leaf certificate in the certificate chain.
func (cs Certificates) LeafExpirationDescription() string {
	var firstLeaf Certificate

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			firstLeaf = cert
		}
	}

	switch {
	case len(cs) == 0:
		return CertChainNotFound

	case firstLeaf.IssuedOn.IsZero():
		// We couldn't find a leaf cert. This could happen when we're
		// monitoring an intermediates bundle on disk.
		return CertNotPresentInChain

	default:
		return fmt.Sprintf(
			"%s (%s)",
			FormattedExpiration(firstLeaf, "", ""),
			FormattedLifetime(firstLeaf),
		)
	}
}

// LeafLengthDescription returns a human readable version of the certificate
// lifetime for the first leaf certificate in the certificate chain. If a leaf
// certificate is not available (e.g., if monitoring an intermediates bundle)
// "N/A" will be returned.
func (cs Certificates) LeafLengthDescription() string {
	var firstLeaf Certificate

	for _, cert := range cs {
		if cert.Type == certs.CertChainPositionLeaf || cert.Type == certs.CertChainPositionLeafSelfSigned {
			firstLeaf = cert
		}
	}

	switch {
	case len(cs) == 0:
		return CertChainNotFound

	case firstLeaf.IssuedOn.IsZero():
		// We couldn't find a leaf cert. This could happen when we're
		// monitoring an intermediates bundle on disk.
		return "N/A"

	default:
		return firstLeaf.ValidityPeriodDescription
	}
}

// IntermediateExpirationDescription returns a human readable version of the
// expiration details for the intermediate certificate expiring first in the
// certificate chain.
func (cs Certificates) IntermediateExpirationDescription() string {
	oldestIntermediate := cs.IntermediateExpiringFirst()

	switch {
	case len(cs) == 0:
		return CertChainNotFound

	case oldestIntermediate.IssuedOn.IsZero():
		return CertNotPresentInChain

	default:
		return fmt.Sprintf(
			"%s (%s)",
			FormattedExpiration(oldestIntermediate, "", ""),
			FormattedLifetime(oldestIntermediate),
		)
	}
}

// FormattedExpiration formats the expiration date for the given certificate
// using an optional custom unit of measurement and an optional precision
// format string.
func FormattedExpiration(cert Certificate, uom string, precisionFmtString string) string {
	var leadInText string

	defaultUOM := "d" // days
	if uom == "" {
		uom = defaultUOM
	}

	daysRemaining := cert.DaysRemaining

	if daysRemaining < 0 {
		// If negative value, flip to positive.
		daysRemaining = float64(math.Abs(daysRemaining))

		// Since we're tracking time (using 'd' as default uom for days),
		// we'll use "ago" to communicate that the event has already occurred.
		uom += " ago"

		leadInText = "expired "
	}

	// Opt for one decimal place over two by default to reduce visual "noise".
	defaultPrecisionFmtString := "%.1f"

	if precisionFmtString == "" {
		precisionFmtString = defaultPrecisionFmtString
	}

	fmtString := "%s" + precisionFmtString + "%s"

	return fmt.Sprintf(fmtString, leadInText, daysRemaining, uom)
}

// FormattedLifetime formats the remaining (positive) lifetime for a given
// certificate.
func FormattedLifetime(cert Certificate) string {
	uom := "%"
	lifetime := cert.LifetimePercent

	if lifetime < 0 {
		lifetime = 0
	}

	return fmt.Sprintf("%d%s left", lifetime, uom)
}
