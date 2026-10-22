# ZeroByte Relay Protocol v1

Everything a client or a relay needs to interoperate. Byte orders are big-endian. Hex is
lowercase.

## 1. Keys

Two paired devices share a 32-byte **link key** `K` and a 16-byte **link id** `L` (a UUID's
16 bytes in RFC 4122 order). Every value is HKDF-SHA256 (RFC 5869) with salt `L`:

| Value | `info` (UTF-8) | Length | Use |
|---|---|---|---|
| Mailbox id | `zerobyte-relay-mailbox-v1` | 16 | In URLs as 32 hex characters |
| Access token | `zerobyte-relay-token-v1` | 32 | Bearer, base64url without padding (43 characters) |
| p2c key | `zerobyte-relay-p2c-v1` | 32 | Seals primary → companion |
| c2p key | `zerobyte-relay-c2p-v1` | 32 | Seals companion → primary |

The labels are part of the wire
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

A receiver opens an envelope only if, in this order: it has at least 38 bytes (`malformed`);
the version is 1 (`unsupported_version`); the direction byte is 1 or 2 and the sequence is not
0 (`malformed`); it is the direction the receiver reads (`wrong_direction`); the sequence is
greater than the last one it accepted (`replayed`); and the tag verifies
(`authentication_failed`). A sender refuses a plaintext over 1 MiB, and a receiver an envelope
over 1 MiB + 38 bytes, with `too_large`. Every SDK uses these error codes.

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

- `after` defaults to 0. `limit` defaults to the fetch limit and is capped at it. An `after`
  that is neither 0 nor a sequence, a `limit` that is not a positive integer, and a `through`
  that is not a sequence answer 400.
- A claim whose body is not JSON naming the digest of the bearer presented answers 400.
- An envelope whose header does not match the path (version 1, the path's direction and
  sequence) answers 400; a body over the envelope limit answers 413.
- A request without a bearer answers 401, and so does every request but the claim when the
  mailbox is not claimed or the bearer is not the one that claimed it.
- A method a path does not take answers 405 with `Allow`. A watch or signal request without a
  WebSocket upgrade answers 426.
- `OPTIONS` on any known path answers 204 with `Access-Control-Allow-Methods: GET, HEAD, PUT,
  DELETE`, `Access-Control-Allow-Headers: Authorization, Content-Type, X-Relay-Notify` and
  `Access-Control-Max-Age: 86400`. Every response exposes `X-Relay-Last`, `X-Relay-More` and
  `Retry-After` to scripts.

The `error` codes:

| Status | `error` |
|---|---|
| 400 | `bad_request` |
| 401 | `unauthorized` |
| 402 | `payment_required` |
| 403 | `forbidden` |
| 404 | `not_found` |
| 405 | `method_not_allowed` |
| 409 | `sequence_conflict` |
| 413 | `envelope_too_large` |
| 426 | `upgrade_required` |
| 429 | `rate_limited` |
| 502 | `upstream_unavailable` |
| 507 | `mailbox_full` |

Clients act on the status; the code is for people reading logs.

### Wire body

```
count (UInt32)                     at most 64
repeat count: length (UInt32) ‖ envelope
```

### Watch

The WebSocket carries only decimal sequence numbers as text messages, one per envelope stored
after the socket opened. The client still fetches and opens; the relay learns nothing new.
Offer the subprotocol `zerobyte.v1`; the relay answers with it. A browser, which cannot set
headers on a WebSocket, also offers `zerobyte.bearer.<token>`; the relay accepts it as the
bearer and never echoes it back. Fetch once after the socket opens, and again on every
reconnect. A direction takes at most 8 watch sockets; another answers 429 with
`Retry-After: 60`. Erasing the mailbox closes every socket with 1000.

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
| Envelope | 38 B (empty plaintext) to 1 MiB + 38 B |
| Mailbox | 32 MiB, 64 envelopes per direction |
| One fetch | 16 envelopes |
| Watch sockets | 8 per direction |
| Idle mailbox | Erased 30 to 31 days after the last write or claim |

These are the defaults. A relay may give an app its own envelope count (16 … 4096), mailbox
size (1 … 256 MiB), largest plaintext (1 KiB … 1 MiB) and idle time (1 … 365 days). A client
learns the limits it hit from 413 and 507. A relay that bills apps may refuse a write with 402 when the
app's plan does not cover it; reading, pruning and erasing still work. SDKs report 402, 413 and
507 as `quota_exceeded`.

## 6. Test vectors

[`spec/vectors.json`](spec/vectors.json) holds two credential sets, four envelopes, eleven
rejections and the wire format cases, and under `signal` the signal keys, two frames and five
rejections of the signal extension (§8). It is produced by [`spec/vectors.py`](spec/vectors.py),
an independent reference that uses only the Python standard library and checks itself against
RFC 8439 and RFC 5869 before writing anything. Implementations copy the file; they never
regenerate it.

## 7. What the relay sees

The app id, the mailbox id, the SHA-256 of one token, envelope sizes, sequence numbers and
times, and the connecting IP address while a request lasts. Not the link key, not any
encryption key, not one byte of plaintext.

## 8. Extensions

Optional, enabled per app by the relay operator. A client must work without them. A path the
app has not enabled answers the same 404 as an unknown path. None of them changes a byte of
§1 or §2.

### Rate limits

Any request may answer `429 rate_limited` with `Retry-After: <seconds>`. Wait that long and
retry; nothing was stored.

### Push

| Request | Does | Answers |
|---|---|---|
| `PUT …/<dir>/push` with a registration | Wake this direction's reader | 204; 400 malformed |
| `DELETE …/<dir>/push` | Stop | 204 |
| `PUT …/<dir>/<seq>` with `X-Relay-Notify: alert\|silent` | Store, then wake the reader | As without; 400 for another value |

The registration is a JSON object, at most 2 KiB, with three generic members and the push
service's own:

```json
{"service": "<name>", "tag": "<1-64 of A-Z a-z 0-9 _ ->",
 "alert": "<optional, at most 160 Unicode characters>", "…": "<the service's fields>"}
```

`service` is 1-16 of `a-z 0-9 -`, starting with a letter. Each service is a separate module of
the relay that checks its fields and delivers. Two are defined here, `apns` (Apple Push
Notification service) and `fcm` (Firebase Cloud Messaging, for Android):

```json
{"service": "apns", "token": "<device token, lowercase hex, 32-100 bytes>",
 "environment": "production" | "development", "tag": "…", "alert": "…"}
{"service": "fcm", "token": "<registration token, 32-1024 of A-Z a-z 0-9 _ : ->",
 "tag": "…", "alert": "…"}
```

A relay with the module for the service answers 400 to fields it does not accept. A relay
without it keeps a registration whose other fields are at most 8 strings of at most 256
characters, and sends nothing for it. The reader registers on the direction it reads: the
companion on `p2c`, the primary on `c2p`.

The relay stores the registration sealed with AES-256-GCM under
`HKDF-SHA256(ikm = access token, salt = "zerobyte-push-v1", info = "<mailbox id>/<dir>", 32)`,
and opens it only while serving a request that presents the bearer. Its database therefore
holds no device token.

The push carries no mailbox id, sequence or content: only the tag. With `alert` it is a visible
notification and the registered `alert` text, and with `silent` a background push.

- APNs: the payload is `{"zerobyte": {"tag": "…"}}`. An alert has `mutable-content: 1`, so a
  notification service extension can fetch, open and replace it.
- FCM: every message is data-only, so the app always receives it and draws the notification
  itself. `data` holds `zerobyte_tag`, `zerobyte_notify` (`alert` or `silent`) and, for an
  alert, `zerobyte_alert`, the registered text or `New message`. Alerts are sent at high
  priority, silent pushes at normal.

The `tag` is chosen by the reader so that it can find the link; it should be random per link,
not a name. The relay sends nothing while the reader's watch socket has sent `ping` within the
last 45 seconds, and drops a registration that the service reports dead (APNs: 410,
`BadDeviceToken`, `DeviceTokenNotForTopic`; FCM: `UNREGISTERED`, `SENDER_ID_MISMATCH`).
Pushes are best-effort: the reader still fetches on launch.

### Watch keep-alive

A client may send the text `ping` on a watch or signal socket; the relay answers `pong`. Any
other frame on a watch socket closes it with 1003. Send `ping` every 30 seconds: it keeps NATs
open and tells the relay the reader is awake, which suppresses pushes.

### Signal

`GET …/signal/<primary|companion>`, upgraded like watch (same subprotocols, same bearer). A
rendezvous for a direct connection between the two devices:

- binary frames of at most 64 KiB are forwarded to the other side's socket as they are;
- the relay sends the text `peer 1` to both when both are connected, and `peer 0` to the one
  left when the other goes;
- a new socket for a side replaces the old one, which is closed with 4000;
- a text frame other than `ping` closes the socket with 1003, an oversized frame with 1009, and
  frames faster than the relay's rate limit with 1008.

The relay neither stores nor reads signal frames. Clients seal them with two more keys from
§1, which the relay does not have, so a frame can never pass for an envelope or the other way
round:

| Value | `info` (UTF-8) | Length | Use |
|---|---|---|---|
| p2c signal key | `zerobyte-signal-p2c-v1` | 32 | Seals primary → companion frames |
| c2p signal key | `zerobyte-signal-c2p-v1` | 32 | Seals companion → primary frames |

A frame has the envelope's layout and AAD (§2), with a counter in place of the sequence:
milliseconds since 1970, or the last counter sent + 1 when the clock has not moved past it. A
frame is at most 64 KiB, so its plaintext is at most 65,498 bytes. A receiver opens a frame as it
opens an envelope, under the signal key, and also refuses (`replayed`) a counter more than five
minutes (300,000 ms) from its own clock. It keeps the last counter it accepted for as long as
its socket is open. Frames that do not open are dropped.

### ICE

`GET …/ice` answers `{"iceServers": [{"urls": […], "username": "…", "credential": "…"}],
"ttl": 3600}`, in the shape of WebRTC's `RTCIceServer`, or 502 if the TURN provider is down. The
credentials expire after `ttl` seconds. A TURN server sees both devices' addresses and the
size and timing of what they exchange, never its content.

### What the extensions add to what the relay sees

When a signal frame passes and its size; the two devices' addresses while their sockets are
open; whether a reader is awake. The push registration only while serving a request that
presents the bearer. The push service (Apple for APNs, Google for FCM) sees the device token,
the time and the tag, and APNs also the topic.
