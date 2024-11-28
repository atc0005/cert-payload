<!-- omit in toc -->
# Certificate metadata payload format versions

<!-- omit in toc -->
## Table of contents

- [Status](#status)
- [Overview](#overview)
- [Versions](#versions)
  - [Payload format versions](#payload-format-versions)
  - [Library versions](#library-versions)
- [Paper notes](#paper-notes)
  - [Context](#context)
  - [Content](#content)
- [References](#references)

## Status

These notes are being compiled on 2024-11-28 from recent work and some paper
notes that I'll be (mostly) including here 1:1. Those paper notes were jotted
down from memory from an "ah hah!" moment I had while driving a few days
prior.

Some of the ideas presented have been implemented towards a `v0.7.0` library
release, many of the better more ergonomic ideas are pending further planning
and research as I don't yet know how to implement them properly.

See <https://github.com/atc0005/cert-payload/issues/46> and linked GH issues
for further information and (likely) current status details. See also the main
project README and latest library releases as those are likely to be the most
current source of information.

## Overview

The purpose of this library is to offload/export/share the behavior needed to
create payloads and then later deconstruct them to native Go types for
analysis, reporting or "action" purposes.

Changes to behavior are expected, even after the initial batch of refactor
iterations as this library matures and client code stabilizes. To support
that, this library will need to expect to handle payloads generated using
earlier payload formats.

Due to the expected lag time between the payload generator updating its copy
of this library and the consumer updating its copy, there could be a brief
window of time when the two would not sync up and a payload version would be
offered for consumption that the receiving client code would not know how to
deal with. Semantic Versioning of this library would communicate expectations
of compatibility (e.g., a v1.0 and a v2.0 communicate breaking changes), but
it wouldn't ensure compatibility (on its own).

Not only do we need to consider this problem from a backwards compatible
perspective (e.g., the "old" payload as a legacy object that will fade away),
but also from sysadmins opting to intentionally stick with a specific format
of the payload for compatibility purposes; sysadmins may opt to keep a stable
earlier format of the payload because it is "good enough" instead of always
updating to the latest payload changes.

Frankly, that makes perfect sense to me (coming from a sysadmin background).

This approach allows payload generators (e.g., `check_cert` from the
`atc0005/check-cert` project) and consumers (e.g., a `cert-reports` tool from
a consuming project) to remain compatible.

So the question becomes, "How do we allow payload format compatibility between
payload generator and consumer without overly complicating the library design
*and* allowing this library to be updated frequently with very low risk of
breakage?".

My initial answer to that (which came to me while driving to a work site on a
Saturday morning) is versioning of payload formats and separate versioning for
the project as a whole.

## Versions

Versioning for this library is handled in two parts:

1. payload format versions
2. library version

### Payload format versions

Payload format versions are intended (once declared stable) to *remain* stable
for the life of this project. `v0` is intentionally *not* covered by this
goal. Once it meets an expected level of maturity it will become the new `v1`.
At that point `v1` is locked in.

In my initial design I was initially divided between thinking of the format
versions as an integer counter, increasing for every single change made to
them (whether compatible or not). I then decided that I'd use a semver
compatible approach, keeping a `v1` format "active" until I made a field or
type change that was incompatible with a generator or consumer of that format.

At present (2024-11-28) both `v0` and the stub/placeholder (for testing) `v1`
formats are actively changing, so I'm undecided on which approach to take:

1. if we go with an approach of freezing a format
   - we'd need to increment for every change to a format
1. if we keep a format "open" or "unlocked"
   1. continue to label the payload as an integer `v1` value
   1. we go with a full semver approach and end up with a `v1.0.1` and
      `v1.1.0` and so on
      - this which might complicate things
      - this library would need to perform semver compatibility evaluation on
        the major version for format version "switching"

That decision is still up in the air.

The end goal is to allow payload generator and payload consumer to specify a
particular format version that they wish to agree on and lock-in that format
for the life of this library. The sysadmin running each would decide when they
wish to move to a different format version.

### Library versions

The intent is to follow the usual Semantic Version practice of using a `v0`
version to indicate early development, a `v1` version to indicate the first
stable release series and a `v2` and subsequent major version releases to
indicate breaking changes.

The *library* version is intended to be entirely separate from the payload
format versions which (overall) would not break once declared stable. The
library version would cover API details and overall library behavior for
interacting with payloads.

## Paper notes

### Context

The following details are copied from my paper notes near verbatim. These
notes were recorded from memory a few days after the Saturday car ride when
(unfortunately) the details were a little fuzzier. I unfortunately didn't
think to record myself at the time the ideas were rapidly occurring to me.

> [!NOTE]
>
> This content was originally written on 2024-11-09 based on the (vague)
> memories from 2024-11-11.

### Content

As of the v0.20.1 release (of the atc0005/check-cert project), optional
support for adding a cert payload to plugin output was added. The payload
format is tracked extrenally in the cert-payload project and at present is
tightly coupled with the payload emitted by the check-cert project's
check_cert plugin.

When I modified a field in the cert-payload project I bumped the version to
v0.4.0 from v0.3.0 and am preparing the check-cert project to reflect that
change in the next release.

I haven't updated the cert-reports reporting tool to make use of the cert
payload yet, but if I had then updating the cert-payload dependency from
v0.3.0 to v0.4.0 would have broken the build.

I plan to move the contents of the payload.go file from the v0.20.1 release to
the cert-payload project, keeping the payload append behavior within the
check_cert project.

Note: I am considering adding compression support to the go-nagios package to
shrink the JSON "blob" or JSON payload size before it is encoded using
Ascii85; the cert-payload project would not be responsible for this.

> [!NOTE]
>
> This support was added in <https://github.com/atc0005/go-nagios/pull/309>.

I would like to extend the cert-payload project to handle receiving a slice of
`*x509.Certificate` values and a format/version number and taking care of
creating the JSON blob using the specified format or "scheme" version.

The plan would be to support decoding the JSON blob automatically using a
version field's value.

> [!NOTE]
>
> This behavior has not been implemented as I've been unable to decide on a
> way to make it work reliably. Instead, we pass a target value to the
> `Decode` function for the payload to be unmarshalled into. This is a
> workaround until I find a better way to handle this.

Each new cert-payload release would support all known formats (starting with
`v1`). `v0` would be the version used while migrating JSON blob creation
support from check-cert to cert-payload.

The plan is to have cert-payload provide all necessary support for explicitly
specifying the format version and creating the payload and then later decoding
that payload. The current thinking is that the client code (e.g., reporting
tool retrieving the payload from Nagios XI API) would provide the retrieved,
Ascii85 decoded (and maybe decompressed) payload and the cert-payload project
would unmarshal to the support format version type.

> [!NOTE]
>
> Encoded (and compressed) plugin output payload support was added in
> <https://github.com/atc0005/go-nagios/pull/309>.

The intent is to retain decoding and encoding support for all published
payload format versions so that:

- users of the check_cert plugin can lock-in the desired format version (e.g.,
  via CLI flag) to either support an older reporting tool's expected format
  (primary reason) or just because the format is "good enough"
- users of a reporting tool can work with any previously saved/archived
  payload transparently, though can expect an error to be raised if the
  incoming JSON blob has a version value greater than the maximum "known" by
  the version of cert-payload package being used by the reporting tool
  - the intent is to make cert-payload package updates as seamless as possible
    and to try very hard to keep from needing a library `v2` release
  - the format versions **MUST** remain stable once published
  - the library API for creating the JSON payloads and then later decoding the
    payloads **SHOULD** remain stable (using RFC terminology)

> [!IMPORTANT]
>
> As noted already, this behavior has not been implemented as I've been unable
> to determine a way to transparently decode earlier version payloads. This is
> a strong contender as a priority number one blocker before declaring this
> library as a stable `v1.0.0` release.

The cert-payload package will provide constants and functions that expose all
supported version numbers:

- minimum format version supported
- maximum format version supported
- list of versions

One idea I haven't thought through is providing a "user agent" or "generator"
value to indicate the tool which generated the payload, but this is probably
not for the client code such as check_cert, but for the cert-payload project
itself. The thinking is that if someone wants to fork the cert-payload project
and maintain it in the future this would be one way to further distinguish the
origin of the payload JSON "blob".

The payload type would be extended to provide sufficient metadata:

- version (maybe payload format version)
  - e.g., `v1`
- generator name
  - e.g., `cert-payload`
- generator version
  - e.g., `v0.15.6`
  - could be useful if a bug is later identified with the payloads generated
    by a specific release version of the cert-payload library
- generator repo
  - e.g., `https://github.com/atc0005/cert-payload` or
    `https://github.com/GITHUB_USERNAME_HERE/cert-payload`

Every field added increases the size of the monitoring plugin's output size,
so we'd need to carefully consider what metadata fields are added as they're
not likely to be used often by reporting tools consuming the payload (unless
as a debug message logged during report generation).

The repo directory structure would make use of the `internal` path to keep as
much of the API surface thin, the bulk of the functionality private.

A `formats` (or `format`) subdirectory would hold major versioned
subdirectories with the payload schema specific to that major version.

Examples:

- `formats/v1/payload.go`
- `formats/v1/README.md`
- `formats/v1/doc.go`

Presumably most notes in the `doc.go` file, thin details in the Markdown doc.

> [!NOTE]
>
> I still haven't gotten around to creating the `README.md` file for each
> format version or extending the `doc.go` file for each format version with
> any backstory on the overall design. That is a future TODO item as of this
> writing.

Continuing from the `formats` (or `format`) subdirectory notes:

Each format subdirectory should be self-contained only as needed, keeping most
of the non-format specific logic at a shared higher level to prevent code
duplication. As needed, code should be copied within a specific format version
subdirectory in order to allow newer formats to deviate in behavior while
keeping older formats stable/reliable.

The thought I had was "CoM" ("Copy on Modify") or "CoW" ("Copy on Write").
Each format version would provide a similar (or same) surface area, but
forwards the work to shared code until the need to copy it locally is reached
in order to retain compatibility.

Presumably tests would assert JSON payload equivalence for creation and
decoding to help catch any regressions.

As much as possible the goal would be to keep the encoding/decoding of JSON
payloads (aka, JSON "blobs") concentrated within the cert-payload project,
moving any logic to create them here. This would start with the check-cert
project, but would potentially involve absorbing behavior for the reporting
tool as well.

## References

- encoded payloads
  - <https://github.com/atc0005/go-nagios/issues/251>
  - <https://github.com/atc0005/go-nagios/issues/301>
- certificate metadata payloads
  - <https://github.com/atc0005/cert-payload/issues/46>
  - <https://github.com/atc0005/cert-payload/pull/47>
- certificate metadata payload generation support
  - <https://github.com/atc0005/check-cert/pull/1098>
