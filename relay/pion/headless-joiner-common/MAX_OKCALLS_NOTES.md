# MAX / OK-Calls transport — how the media layer MUST work

Reverse-engineered from the web client (web.max.ru, chunk `nodes/0.*.js`) and two-host
live testing (2026-09-10). This corrects the original peer-to-peer/DataChannel design in
`max_joiner.go`, which **cannot work** and is superseded.

## What MAX calls actually are
MAX video calls run on **OK (Odnoklassniki)'s "OK Calls" SFU**, not VK and not a mesh.
Signaling is JSON over the ws2 TEXT WebSocket at `videowebrtc.okcdn.ru/ws2`; media is a
**mediasoup-style SFU** reached with producer/consumer commands. Endpoint + TURN
(`155.212.x`) are all OK infrastructure.

## Why the current max_joiner.go media path is wrong
`max_joiner.go` does a symmetric **peer** offer/answer over `transmit-data` with
`p2pRelay:"true"` and opens an SCTP **DataChannel** ("dc" tunnel mode). Every layer of that
is the DIRECT/p2p path, which is disabled and unusable here:

- **`p2pRelay` is a capability flag that the client sets to FALSE** (`p2pRelay:()=>!1` in the
  web bundle) — it is NOT an SDP field. `transmit-data{sdp,p2pRelay:"true"}` is the p2p relay
  path; with the flag off, the server does not run it. Observed: ICE always goes
  checking→failed; TURN answers `CreatePermission 403 Forbidden IP` for peer addresses.
- **p2p is also wrong for the whitelist-bypass goal**: a peer path terminates at the other
  client's IP, which is not on a censored network's allowlist. We WANT everything to go to
  MAX/OK servers (the SFU + its TURN), which are whitelisted. The SFU model is both what
  OK-Calls requires and what we need.
- **OK's SFU is media-only.** The web client has no data producer/consumer (no `produceData`
  / `dataProducer` / `dataConsumer`; the `sctp`/`DataChannel` strings are only in the bundled
  webrtc-adapter shim). An SFU forwards RTP media tracks, not arbitrary SCTP DataChannels, so
  the DataChannel tunnel cannot traverse it.

## The correct design (what to build)
Mirror `telemost_joiner.go`'s **video mode**, not vk_joiner's dc mode:

1. **Tunnel data as a VP8 media track.** Reuse the existing whitelist-bypass machinery:
   `AddTunnelTracks` + `tunnel.NewVP8DataTunnel` to encode outbound tunnel bytes into a VP8
   stream; `pc.OnTrack` + `ReadTrackFunc` + `vp8tunnel.HandleFrame` to decode the inbound one.
   (This is exactly why the joiner constructor already takes `AddTracks`/`ReadTrackFn`.)
2. **Negotiate with the SFU via producer/consumer**, NOT `transmit-data{sdp}`. The web
   client's OK-Calls signaling API (bundle):
   - `allocateConsumer(desc, capabilities)` → `_send(ALLOCATE_CONSUMER, {capabilities, description: desc.sdp})`
     — set up receiving (consume the peer's producer). `capabilities` = RTP capabilities.
   - `acceptProducer(desc, ssrcs, sessionId)` → `_send(ACCEPT_PRODUCER, {description: desc.sdp, sessionId, ssrcs})`
     — set up sending (produce our VP8 track).
   - Related commands in the enum: RECOVER `recover`, ACCEPT_CALL `accept-call`,
     CHANGE_MEDIA_SETTINGS `change-media-settings`, ALLOCATE_CONSUMER `allocate-consumer`,
     ACCEPT_PRODUCER `accept-producer`, CHANGE_STREAM_PRIORITIES, SWITCH_TOPOLOGY `switch-topology`,
     REQUEST_REALLOC `request-realloc`, CUSTOM_DATA `custom-data`.
   - Server notifications: `connection`, `settings-update`, `registered-peer`, `topology-changed`,
     `producer-updated`, `consumer-answered`, `force-media-settings-change`, `participants-state-changed`.
   - `transmit-data` is only for the (disabled) p2p relay path — do not use it for media.
3. **capabilities bitmask.** `capabilities` (the `1877f`-style hex in the ws2 URL and
   internalParams) is `Flags.getFlags()`: a bitmask over an ordered flag list where each entry
   is a predicate. `p2pRelay` is one of those flags and is off. Recompute honestly from the
   flag set rather than hardcoding if behaviour depends on it.

## Building blocks already correct / reusable (keep)
- Control plane: `maxproto` (op6/op19/op46/op76/op166), verified live. Unaffected.
- roomd MAX room issuance (op76), enrol per-device creds, letmeout wiring — all provider-level,
  unaffected by the media redesign.
- ws2 connect + URL augmentation; adopting TURN/STUN from the `connection` notification
  (`handleConnection`) — correct and needed for the SFU path too.
- `change-media-settings` on connect — needed; for a data-as-video tunnel, video enabled.
- CA scoping (Russian Sub CA for api2 only; system roots for okcdn) — correct.
- Non-goal: the DataChannel ("dc") tunnel, `transmit-data` offer/answer, `p2pRelay` field,
  and the self/peer ICE-candidate exchange over transmit-data — all superseded.

## VERIFIED LIVE (2026-09-10) — the working handshake and the one remaining gap

The SFU signaling flow below is implemented in max_joiner.go and **confirmed working against
the live server** (no protocol errors, no TURN 403 any more):

1. ws2 connect → `change-media-settings` (isVideoEnabled true) + `update-media-modifiers`.
2. `connection` notification → adopt conversationParams TURN/STUN → build PC.
3. **Topology matters and is not forcible.** A 1:1 call runs in `DIRECT` (peer-to-peer; the
   server relays NO media and never produces, so no `producer-updated` ever arrives).
   `switch-topology {topology:"SERVER",force:true}` is rejected with `feature-is-disabled`.
   The conversation flips to `SERVER` **on its own once a THIRD participant joins** — verified:
   `<- topology-changed topology=SERVER`. Implication for letmeout: a MAX tunnel needs a third
   (filler) participant in the room, or the call must otherwise be a group call.
4. On `topology-changed → SERVER`, RE-SEND `allocate-consumer` (the one sent while still in
   DIRECT does not carry over). Then the SFU offers.
5. `allocate-consumer` payload: `{"capabilities": {...}}` — a STRUCTURED object (the hex
   bitmask is rejected with "Invalid message format"). Shape copied from the web bundle's
   capabilities getter: estimatedPerformanceIndex, audioMix, consumerUpdate,
   producer/consumer*DataChannelVersion, onDemandTracks, unifiedPlan, singleSession,
   videoTracksCount, red, simulcast*, etc. Accepted by the server as implemented.
6. `← producer-updated {description, sessionId}` = the SFU's SDP **offer**; we answer and send
   `accept-producer {description, sessionId, ssrcs}`. Both directions verified on the wire.

### The SFU's offer (captured live) — and the remaining gap
The SFU is **`a=ice-lite`** (it never sends connectivity checks; our side must drive ICE), its
candidates are plain host candidates on its own public IP (e.g. `155.212.206.87:43210` udp +
tcp, no ufrag attribute), and ONE offer carries BOTH directions across 5 bundled m-lines:

```
a=group:BUNDLE 0 1 2 3 4 / a=ice-lite
m=audio       mid:0  sendonly   SFU -> us (audio-mix)
m=application mid:1             SCTP datachannel (SFU's own producerCommand/notification etc.)
m=audio       mid:2  recvonly   us -> SFU
m=video       mid:3  recvonly   us -> SFU   <-- OUR VP8 TUNNEL TRACK BELONGS HERE
m=video       mid:4  sendonly   SFU -> us
```
(NB: the SFU *does* offer an SCTP m-line, so DataChannels are not categorically impossible —
but they are the SFU's own control channels, so the VP8 media tunnel remains the design.)

**Remaining gap:** our answer carries `ssrcs=[]` — the outbound VP8 track is added with
`AddTracks` *before* the offer arrives and is never bound to `mid:3`, so we advertise video and
supply none. The SFU then rejects the answer and re-offers with a fresh `sessionId` every ~14s,
which is why ICE never settles (each new offer resets the session). Fix: after
`SetRemoteDescription(offer)`, locate the transceiver whose mid is the video/recvonly one
(mid:3) and attach the tunnel track to it (`transceiver.Sender().ReplaceTrack(sampleTrack)` or
set its direction to sendonly), making sure the track's codec matches one of that m-line's
payload types (98-106), then answer. `extractSSRCs` should then return a real SSRC and the SFU
should accept, letting ICE complete against the ice-lite SFU.

## Next step
Build a `CONSUMER`/`PRODUCER` SFU media flow in `max_joiner.go` (video/VP8 tunnel), driven by
`allocate-consumer` / `accept-producer`, feeding Pion tracks. The cleanest reference is
`telemost_joiner.go`'s video-mode track handling + this OK-Calls producer/consumer signaling.
Validate two-host on the homelab (egress is fine; both public IPs differ; MAX hosts reachable).
