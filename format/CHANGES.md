# Format Versions History

## Overview

All notable changes to the certificate metadata payload formats provided by
this project will be documented in this file.

Please [open an issue](https://github.com/atc0005/cert-payload/issues) for any
entries that are unclear (or incomplete) in this document.

## Forward Format Compatibility

The `v0.10.0` release added automatic *forward* format compatibility (ffc)
between older stable format versions and newer stable format versions. Stable
format version `2` is the first to provide this FFC conversion support by
automatically converting format version `1`. If desired, the caller can opt
out of this automatic conversion by calling the format-specific `Decode`
function (e.g., `format2.Decode`) with the appropriate boolean value.

The unstable format version `0` is supported only when used as the input
payload format version when decoding to a destination of the same format
version `0`; automatic *forward* format compatibility (ffc) is NOT supported
in any direction for the unstable format `0`.

## Format changes

### `format2`

v0.9.0 is the follow-up stable format release.

New fields and behavior changes were included in this format release and by
later library updates:

| Change                                           | Pull Request                                               | Release                                                                 |
| ------------------------------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| Add Forward Format Compatibility (`FFC`) support | [GH-141](https://github.com/atc0005/cert-payload/pull/141) | [v0.10.0](https://github.com/atc0005/cert-payload/releases/tag/v0.10.0) |
| Add `owners` multi-value field                   | [GH-131](https://github.com/atc0005/cert-payload/pull/131) | [v0.9.0](https://github.com/atc0005/cert-payload/releases/tag/v0.9.0)   |
| Add `service_environment` single-value field     | [GH-132](https://github.com/atc0005/cert-payload/pull/132) | [v0.9.0](https://github.com/atc0005/cert-payload/releases/tag/v0.9.0)   |
| Add `public_key_algorithm` single-value field    | [GH-133](https://github.com/atc0005/cert-payload/pull/133) | [v0.9.0](https://github.com/atc0005/cert-payload/releases/tag/v0.9.0)   |

### `format1`

v0.7.0 is the initial stable format release.

Behavioral changes since this release include:

| Change                                           | Pull Request                                               | Release                                                                 |
| ------------------------------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| Add Forward Format Compatibility (`FFC`) support | [GH-141](https://github.com/atc0005/cert-payload/pull/141) | [v0.10.0](https://github.com/atc0005/cert-payload/releases/tag/v0.10.0) |
| Update `ValidityPeriodDescription` behavior      | [GH-94](https://github.com/atc0005/cert-payload/pull/94)   | [v0.8.0](https://github.com/atc0005/cert-payload/releases/tag/v0.8.0)   |
| Adjust misordered chain logic                    | [GH-76](https://github.com/atc0005/cert-payload/pull/76)   | [v0.7.1](https://github.com/atc0005/cert-payload/releases/tag/v0.7.1)   |
