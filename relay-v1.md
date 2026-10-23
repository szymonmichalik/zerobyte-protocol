# ZeroByte Relay Protocol v1

Everything a client or a relay needs to interoperate. Byte orders are big-endian. Hex is
lowercase.

## 1. Keys

Two paired devices share a 32-byte **link key** `K` and a 16-byte **link id** `L` (a UUID's
16 bytes in RFC 4122 order). Every value is HKDF-SHA256 (RFC 5869) with salt `L`:

| Value | `info` (UTF-8) | Length | Use |
|---|---|---|---|
| Mailbox id | `derived-relay-mailbox-v1` | 16 | In URLs as 32 hex characters |
| Access token | `derived-relay-token-v1` | 32 | Bearer, base64url without padding (43 characters) |
| p2c key | `derived-relay-p2c-v1` | 32 | Seals primary → companion |
| c2p key | `derived-relay-c2p-v1` | 32 | Seals companion → primary |

The labels keep the name of the protocol's first application. They are part of the wire
format; changing one is a new protocol version. The relay stores only `SHA-256(access token)`,
as hex.

The **primary** is the device that holds the source of truth (usually the phone); the
**companion** mirrors it. Each direction has its own key and its own sequence, so neither side
can replay the other's envelopes back to it.

## 2. Envelope

```
version (1) = 0x01
direction (1)       0x01 p2c, 0x02 c2p
sequence (8)        UInt64, 1 … 2^64−1, strictly increasing per direction
nonce (12)          random
ciphertext (n)      ChaCha20-Poly1305 (RFC 8439)
tag (16)
```

The additional authenticated data is the 10-byte header followed by the 16-byte mailbox id, so
an envelope cannot be moved to another mailbox, direction or sequence. Overhead is 38 bytes;
plaintext is at most 1 MiB.

A receiver opens an envelope only if, in this order: it has at least 38 bytes; the version is 1
(`unsupported_version`); the direction byte is 1 or 2 (`malformed`); it is the direction the
receiver reads (`wrong_direction`); the sequence is greater than the last one it accepted
(`replayed`); and the tag verifies (`authentication_failed`). Every SDK uses these error codes.

## 3. Endpoints

All under `/v1/<app>/mailbox/<mailbox id>`, where `<app>` is a registered UUIDv7. Every request
carries `Authorization: Bearer <token>`. An unknown app and every unknown path answer the same
404. Errors are JSON: `{"error": "<code>", "status": n}`.

| Request | Does | Answers |
|---|---|---|
| `PUT …` with `{"tokenDigest": "<hex>"}` | Claim: the first bearer wins. The body must name the digest of the bearer presented. | 201 claimed, 204 already yours, 403 someone else's |
| `DELETE …` | Erase the mailbox, close watchers | 204 |
| `PUT …/<dir>/<seq>` | Store one envelope; its header must match the path | 201; 409 with `X-Relay-Last` if `seq` is not above the last; 507 full |
| `GET …/<dir>?after=&limit=` | Envelopes after a sequence, oldest first, at most 16 | 200, [wire body](#wire-body), `X-Relay-More: 0\|1` |
| `HEAD …/<dir>` | The last sequence ever stored | 200, `X-Relay-Last` (absent if none) |
| `DELETE …/<dir>?through=` | Drop everything up to a sequence | 204 |
| `GET …/<dir>/watch` | WebSocket, see below | 101 |

`<dir>` is `p2c` or `c2p`. `X-Relay-Last` survives pruning, so a writer that lost its state
continues from it. Cross-origin requests are allowed (`Access-Control-Allow-Origin: *`): the
token is never a cookie, so a page without it gets nothing.

### Wire body

```
count (UInt32)                     at most 64
repeat count: length (UInt32) ‖ envelope
```

### Watch

The WebSocket carries only decimal sequence numbers as text messages, one per envelope stored
after the socket opened. The client still fetches and opens; the relay learns nothing new.
Offer the subprotocol `zerobyte.v1`. A browser, which cannot set headers on a WebSocket, also
offers `zerobyte.bearer.<token>`; the relay accepts it as the bearer and never echoes it back.
Fetch once after the socket opens, and again on every reconnect.

## 4. Client behaviour

- Claim once per mailbox (idempotent). Both devices may claim; the second gets 204.
- To send: next sequence = 1 + the last you stored, or `HEAD` on a fresh start. On 409,
  continue from `X-Relay-Last` + 1 and seal again with a new nonce.
- To receive: fetch after your last accepted sequence until `X-Relay-More` is 0, open each
  envelope, then prune through the highest sequence you saw, including envelopes that failed
  to open: they never will.
- Persist the last accepted sequence. Erase the mailbox when the devices unpair.

## 5. Limits

| Limit | Value |
|---|---|
| Envelope | 38 B … 1 MiB + 38 B |
| Mailbox | 32 MiB, 64 envelopes per direction |
| One fetch | 16 envelopes |
| Idle mailbox | Erased 30 days after the last write or claim |

## 6. Test vectors

[`spec/vectors.json`](spec/vectors.json) holds two credential sets, four envelopes, ten
rejections and the wire format cases. It is produced by [`spec/vectors.py`](spec/vectors.py),
an independent reference that uses only the Python standard library and checks itself against
RFC 8439 and RFC 5869 before writing anything. Implementations copy the file; they never
regenerate it.

## 7. What the relay sees

The app id, the mailbox id, the SHA-256 of one token, envelope sizes, sequence numbers and
times, and the connecting IP address while a request lasts. Not the link key, not any
encryption key, not one byte of plaintext.
