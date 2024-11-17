# Changelog

## Overview

All notable changes to this project will be documented in this file.

The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Please [open an issue](https://github.com/atc0005/cert-payload/issues) for any
deviations that you spot; I'm still learning!.

## Types of changes

The following types of changes will be recorded in this file:

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

## [Unreleased]

- placeholder

## [v0.6.0] - 2024-11-17

### Added

- (GH-39) Add `WeakSignatureAlgorithm` cert issues field

## [v0.5.0] - 2024-11-16

### Added

- (GH-34) Add `Certifiates.SANsEntriesCount` field
- (GH-35) Add `Certifiates.SignatureAlgorithm` field

## [v0.4.0] - 2024-11-08

### Changed

- (GH-28) Replace `MultipleLeafCerts` with `DuplicateCerts`

## [v0.3.0] - 2024-11-06

### Changed

- (GH-23) Update `ValidityPeriod*` constants
- (GH-24) Clarify fields which may not be populated

## [v0.2.0] - 2024-11-04

### Added

- (GH-21) Add `CertificateChainIssues.MissingSANsEntries`

## [v0.1.0] - 2024-11-03

### Added

Initial package state

Add current code used in `atc0005/check-cert` prototype to be used when
generating an encoded certificate chain metadata payload for inclusion in
plugin output.

[Unreleased]: https://github.com/atc0005/cert-payload/compare/v0.6.0...HEAD
[v0.6.0]: https://github.com/atc0005/cert-payload/releases/tag/v0.6.0
[v0.5.0]: https://github.com/atc0005/cert-payload/releases/tag/v0.5.0
[v0.4.0]: https://github.com/atc0005/cert-payload/releases/tag/v0.4.0
[v0.3.0]: https://github.com/atc0005/cert-payload/releases/tag/v0.3.0
[v0.2.0]: https://github.com/atc0005/cert-payload/releases/tag/v0.2.0
[v0.1.0]: https://github.com/atc0005/cert-payload/releases/tag/v0.1.0
