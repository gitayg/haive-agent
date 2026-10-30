# Live screen protocol (`GET /screen`)

Agent 3.13.0 adds a delta-encoded live screen next to the existing endpoints.
`/frame` (one full JPEG) and `/stream` (MJPEG) stay unchanged, so older hubs and
the built-in viewer page keep working.

## Request

`GET /screen?sid=<sid>&ack=<seq>&codec=<tiles|h264>&q=<quality>&w=<max_width>`

| param | meaning |
|---|---|
| `sid` | viewer session id, 1-64 chars `[A-Za-z0-9_-]`. Required; anything else is 400. |
| `ack` | the `seq` of the last response the viewer applied. `0` = none (forces a key frame). |
| `codec` | `tiles` (default) or `h264`. `h264` on a device without an encoder answers with `tiles` and says so in the header. |
| `q` | JPEG quality (tiles) or quality hint (h264), clamped to 20..=90. Default: the agent's configured quality. |
| `w` | maximum output width in pixels, clamped to 320..=3840. The frame is scaled down keeping aspect ratio, never up. |

The endpoint is privileged (same token rules as `/frame`).

## Session state

The agent keeps up to 8 sessions keyed by `sid`, evicting one idle for 60 s
(least recently used first when full). Each session holds the last frame it
sent (at output size), its `seq`, its codec, and, for h264, the encoder. The
encoder is recreated when the output size changes; a `q` change alone does not
recreate it (that would cost an IDR on every adaptive step), so for h264 `q`
takes effect at the next size change or new session. If the h264 encoder fails,
that response and the rest of the session are tiles, with `note` saying why.

The agent sends a **key frame** (every tile, or an IDR) when any of these holds:
- `ack` != the session's last `seq` (a response was lost or this is a new viewer);
- the output size changed (different `w`, monitor resolution change);
- the codec changed;
- for tiles: more than 60% of tiles changed (one full JPEG is cheaper).

## Long poll

When nothing changed since `ack`, the agent re-captures every ~70 ms for up to
1000 ms before answering with an empty update (`rects: []`, `unchanged: true`).
That keeps an idle desktop from spinning the relay. A pointer move ends the wait
early with the same empty update carrying the new `cursor` (the captured image
never contains the pointer, so a moving mouse over a still screen is otherwise
invisible for up to a second).

## Response

`200`, `Content-Type: application/x-itai-screen`. Body:

```
"ITS1"                      4 bytes magic
header_len                  u32 little-endian
header                      header_len bytes of UTF-8 JSON
payload                     the rest
```

Header JSON:

```json
{
  "seq": 42,
  "key": false,
  "codec": "tiles",
  "w": 1600, "h": 900,
  "rects": [{"x":0,"y":64,"w":128,"h":64,"off":0,"len":5123}],
  "unchanged": false,
  "cursor": {"x": 812, "y": 455},
  "desktop": "default",
  "enc_ms": 9,
  "wait_ms": 0,
  "note": null
}
```

- `seq`: increases by one per non-empty response in this session. An unchanged
  response repeats the current `seq`.
- `w`,`h`: output frame size. The viewer resizes its canvas to this on a key frame.
  For h264 both are even: an odd last column/row of the scaled frame is dropped.
- `rects` (tiles): each rect is a JPEG at `payload[off..off+len]`, to be drawn at
  `(x,y)` in output pixels. A key frame is one rect covering the frame, or the
  full set of tiles.
- `h264`: `rects` is empty; the payload is one Annex-B access unit (start codes,
  SPS+PPS before every IDR). `key: true` means it starts with an IDR.
- `cursor`: pointer position in output pixels, or `null` when unknown/off-screen.
  The viewer draws its own arrow at this point (the frame does not contain one).
- `desktop`: `default`, `winlogon` (UAC prompt / lock screen / Ctrl+Alt+Del screen),
  `screensaver`, or `null` off Windows.
- `enc_ms`: time the agent spent on this request — capturing, diffing, encoding,
  and any long-poll wait — so `round trip − enc_ms` is the network time the
  viewer's adaptive controller wants.
- `wait_ms`: the long-poll part of `enc_ms` (0 when the first capture already
  differed). `enc_ms − wait_ms` is the capture + encode cost.
- `note`: a human-readable reason when the agent fell back (e.g. "h264 encoder
  unavailable on this device — sending tiles").

Errors: `400` bad params, `500` capture failure with the reason as text (same
strings as `/frame`, including the no-display message).

## Tiles

The detection grid is 64x64 output pixels (edge tiles are smaller). Changed tiles
are merged into rectangles (horizontal runs, then runs with identical x-span on
consecutive rows) and each rectangle is JPEG-encoded at quality `q`.

## Cursor in `/frame`

`/frame` (the one-shot screenshot the MCP `screenshot` tool and the AI use) now
has a small arrow drawn at the pointer position when the agent can read it, so
the model can see where the mouse is. `/screen` never draws it into the image.

## Ctrl+Alt+Del (`POST /sas`)

Windows only. Asks Windows to generate the secure attention sequence through
`SendSAS`. Works only when the agent runs as a LocalSystem service. Answers
`204` on success, `409` with the reason when it can't (not a service, policy
disabled, not Windows).

## Adaptive quality

The viewer owns the control loop: it measures round-trip time and bytes per
response, subtracts `enc_ms`, and adjusts `q` and `w` on the next request. The
agent only honours the clamped values.

## Capabilities

The agent's hello `info` carries `"screen": {"proto": 1, "codecs": ["tiles", "h264"?], "sas": bool}`
so the hub can decide whether to use `/screen` at all and which codec to ask for.
