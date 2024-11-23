// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/cert-payload
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package shared

// Nagios plugin/service check state "labels". These values are used (where
// applicable) by the CertChainPayload `ServiceState` field.
// const (
// 	StateOKLabel        string = "OK"
// 	StateWARNINGLabel   string = "WARNING"
// 	StateCRITICALLabel  string = "CRITICAL"
// 	StateUNKNOWNLabel   string = "UNKNOWN"
// 	StateDEPENDENTLabel string = "DEPENDENT"
// )

// Validity period keywords intended as human readable output.
//
// Common historical certificate lifetimes:
//
//   - 5 year (1825 days, 60 months)
//   - 3 year (1185 days, 39 months)
//   - 2 year (825 days, 27 months)
//   - 1 year (398 days, 13 months)
//
// See also:
//
//   - https://www.sectigo.com/knowledge-base/detail/TLS-SSL-Certificate-Lifespan-History-2-3-and-5-year-validity/kA01N000000zFKp
//   - https://support.sectigo.com/Com_KnowledgeDetailPage?Id=kA03l000000o6cv
//   - https://www.digicert.com/faq/public-trust-and-certificates/how-long-are-tls-ssl-certificate-validity-periods
//   - https://docs.digicert.com/en/whats-new/change-log/older-changes/change-log--2023.html#certcentral--changes-to-multi-year-plan-coverage
//   - https://knowledge.digicert.com/quovadis/ssl-certificates/ssl-general-topics/maximum-validity-changes-for-tls-ssl-to-drop-to-825-days-in-q1-2018
//   - https://chromium.googlesource.com/chromium/src/+/666712ff6c7ba7aa5da380bc0a617b637c9232b3/net/docs/certificate_lifetimes.md
//   - https://www.entrust.com/blog/2017/03/maximum-certificate-lifetime-drops-to-825-days-in-2018
const (
	ValidityPeriod1Year   string = "1 year"
	ValidityPeriod90Days  string = "90 days"
	ValidityPeriod45Days  string = "45 days"
	ValidityPeriodUNKNOWN string = "UNKNOWN"
)
