# Upstream capability and asset audit

Checked 2026-08-03. Upstream projects are references; HuntProxy extensions are
independent implementations unless an asset is explicitly recorded below.

## Reusable with attribution

PortSwigger's Param Miner repository is Apache-2.0. Its `resources/` wordlists
are therefore candidates for redistribution with the repository's copyright,
license, and NOTICE obligations preserved. The audited upstream commit was
`4c35086a963cb68a608e91d90aef135be0f572a3` (2026-06-29). Files observed:
`assetnote-params`, `boring_headers`, `fierce-subdomains`, `functions`,
`headers`, `params`, `wafparams`, and `words`. They have not yet been copied;
vendoring must pin the commit, preserve the license, and add a provenance file.

PortSwigger HTTP Request Smuggler and Turbo Intruder are Apache-2.0 at audited
commits `a25814d258c501b59b7f561d816f4d787c61ab70` and
`0923fefc39833518a69c788cd106d88f9a45ec93`. Their code may be studied or
adapted under Apache-2.0, but their Burp-specific runtime should not be copied
as the HuntProxy architecture.

The Caido community Autorize repository is MIT at audited commit
`30cef2b34b5cf3592e7cf977f4999ca1bc09edd8`. No source has been copied.

## Not cleared for reuse

The PortSwigger Upload Scanner repository had no top-level license file at
audited commit `aea3fe2a4c5123c474d80717ab4bc8e80b03e0fd`. Its source, embedded
binaries, and payload corpus must not be copied. UploadAnalyzer should use an
independently authored, non-destructive corpus. Crash, memory/disk exhaustion,
fork-bomb, and denial-of-service payloads are excluded.

Plugin names and descriptions in third-party catalogs do not grant rights to
their source or bundled data. Audit every additional source before copying it.

## Capability gaps that belong in HuntProxy

Request Smuggler needs exact HTTP/1 bytes (already present), split writes,
half-close, multi-response reads, connection reuse/state, and low-level HTTP/2
header/frame control. A semantic HTTP/2 library cannot cover malformed frame,
pseudo-header, CRLF-in-header, tunneling, or downgrade probes faithfully.

Racer needs synchronized connection groups and HTTP/2 single-packet release:
prepare streams without completing them, then release their final DATA bytes
in one TCP packet where possible. Ordinary concurrent requests are not a
single-packet attack and must not be labeled as one.
