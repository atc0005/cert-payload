# Format Versions History

## Overview

All notable changes to the certificate metadata payload formats provided by
this project will be documented in this file.

Please [open an issue](https://github.com/atc0005/cert-payload/issues) for any
entries that are unclear (or incomplete) in this document.

## Format changes

### `format2`

v0.9.0 is the second stable format release. New fields (see below) were added
in this format release.

| Change                                        | Pull Request                                               | Release                                                               |
| --------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| Add `owners` multi-value field                | [GH-131](https://github.com/atc0005/cert-payload/pull/131) | [v0.9.0](https://github.com/atc0005/cert-payload/releases/tag/v0.9.0) |
| Add `service_environment` single-value field  | [GH-132](https://github.com/atc0005/cert-payload/pull/132) | [v0.9.0](https://github.com/atc0005/cert-payload/releases/tag/v0.9.0) |
| Add `public_key_algorithm` single-value field | [GH-133](https://github.com/atc0005/cert-payload/pull/133) | [v0.9.0](https://github.com/atc0005/cert-payload/releases/tag/v0.9.0) |

### `format1`

v0.7.0 is the initial stable format release.

Behavioral changes since this release include:

| Change                                      | Pull Request                                             | Release                                                               |
| ------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| Update `ValidityPeriodDescription` behavior | [GH-94](https://github.com/atc0005/cert-payload/pull/94) | [v0.8.0](https://github.com/atc0005/cert-payload/releases/tag/v0.8.0) |
| Adjust misordered chain logic               | [GH-76](https://github.com/atc0005/cert-payload/pull/76) | [v0.7.1](https://github.com/atc0005/cert-payload/releases/tag/v0.7.1) |
