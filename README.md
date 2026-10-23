# ZeroByte Protocol

The open specification of ZeroByte, an end-to-end encrypted relay between two
paired devices of one app. This repository defines the keys, the envelope
format and the HTTP and WebSocket endpoints, and ships the known-answer vectors
every implementation is tested against. Anyone may implement the protocol,
under any licence.

## Contents

| Path | What it is |
|---|---|
| [`relay-v1.md`](relay-v1.md) | Relay Protocol v1: keys, envelope, endpoints, watch, client behaviour, limits |
| [`spec/vectors.py`](spec/vectors.py) | Independent reference implementation. Python standard library only; checks itself against RFC 8439 and RFC 5869 before it writes anything. |
| [`spec/vectors.json`](spec/vectors.json) | Known-answer vectors: two credential sets, four envelopes, ten rejections, wire-format cases |

## The protocol in one page

Two devices pair once and agree a 32-byte link key and a 16-byte link id. The
relay never takes part in pairing and never receives either value.

From the link key, each device derives four values with HKDF-SHA256: a mailbox
id, an access token, and one encryption key per direction (primary to
companion, companion to primary). The relay only ever stores the SHA-256 of the
access token.

Every message is sealed with ChaCha20-Poly1305 into an envelope of
`version ‖ direction ‖ sequence ‖ nonce ‖ ciphertext ‖ tag`. The header and the
mailbox id are authenticated, so an envelope cannot be replayed, reordered or
moved to another mailbox without failing to open.

The relay files envelopes under `/v1/<app>/mailbox/<mailbox>/<direction>/<sequence>`.
The reader fetches, opens and prunes them. A WebSocket announces new sequence
numbers so clients do not poll. A mailbox without a write for 30 days erases
itself.

The details, including every status code and limit, are in
[`relay-v1.md`](relay-v1.md).

## Test vectors

Implementations copy `spec/vectors.json` byte for byte and test against it.
None of them regenerates it. The file changes only when the protocol does:

```sh
python3 spec/vectors.py > spec/vectors.json
```

A change to the wire format is a new protocol version (`relay-v2.md`), never an
edit of v1. The HKDF labels (`derived-relay-*-v1`) keep the name of the first
app that used the protocol. They are part of the wire format and stay as they
are.

## Implementations

| Repository | Platform | Licence |
|---|---|---|
| [zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay) | The relay: Node server and Cloudflare Worker | AGPL-3.0-only |
| [zerobyte-swift-sdk](https://github.com/szymonmichalik/zerobyte-swift-sdk) | iOS, iPadOS, macOS, watchOS, tvOS, visionOS | Apache-2.0 |
| [zerobyte-android-sdk](https://github.com/szymonmichalik/zerobyte-android-sdk) | Android and any JVM 11+ (Kotlin) | Apache-2.0 |
| [zerobyte-js-sdk](https://github.com/szymonmichalik/zerobyte-js-sdk) | Browsers, Node, Deno, Bun, Cloudflare Workers | Apache-2.0 |
| [zerobyte-dotnet-sdk](https://github.com/szymonmichalik/zerobyte-dotnet-sdk) | Windows and any .NET 10 platform | Apache-2.0 |

If you write another implementation, open an issue and I will list it here.

## Security

Report a vulnerability in the protocol by
[opening an issue](https://github.com/szymonmichalik/zerobyte-protocol/issues/new)
in this repository. See [SECURITY.md](SECURITY.md).

## Licence

The specification text is licensed under Creative Commons Attribution 4.0
(`CC-BY-4.0`, see [`LICENSE`](LICENSE)). `spec/vectors.py` and
`spec/vectors.json` are also available under Apache-2.0
([`LICENSE-APACHE`](LICENSE-APACHE)), so they can be copied into any
implementation.

An implementation may say that it implements the ZeroByte protocol. Please
don't present it as `zerobyte.cloud`.

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. relay.zerobyte.cloud runs the same code for Derived and isn't
open to other apps. To use ZeroByte in your app, run your own relay: see
[zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay).
