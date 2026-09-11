# OK-Calls SFU data-channel control protocol (`producerCommand` / `producerNotification`)

Port target: `max_sfu_dc.go` (codec + decoders), wired into `max_joiner.go`
(`MediaMode=="sfu"`). Source of truth: the de-minified web.max.ru call bundle
slice `tools/maxref/vendor/slice.pretty.js` (line cites `S:<line>`) and the
full minified `bundle.min.js` (byte-offset cites `B:@<offset>`), both in the
`letmeout` repo's `maxref` worktree. Captured evidence: browser oracle
transcript `/tmp/golden/D3.jsonl` (2026-09-11), `kind:"dc"` lines.

## 1. Why this exists

The SFU is on-demand (`onDemandTracks: true` in the `allocate-consumer`
capabilities). After `accept-producer` the consumer PeerConnection carries
exactly one remote track — the Opus `audio-mix` (`a=ssrc:... label:audio-mix`,
mid 0) — plus N pre-allocated **recvonly video consumer slots** whose SSRCs are
labelled `video-pat-N` and whose msid is `pat-N video-pat-N` ("pat" =
participant-agnostic track, `IC.PARTICIPANT_AGNOSTIC_TRACK_PREFIX`, S:4076).
No peer video flows until the consumer asks for a specific participant's
stream over the `producerCommand` SCTP data channel; the SFU then answers on
`producerNotification` with which slot now carries it.

## 2. The four data channels

`ServerTransport._openConnection` (S:6666-6760) creates, on the single SFU
PeerConnection, in this order, all with `{ ordered: true }`
(`_createDataChannel`, S:6648-6665):

| label | dir | role | S: |
|---|---|---|---|
| `producerNotification` | SFU -> client | binary notifications, `binaryType="arraybuffer"`, fed to `participantIdRegistry.handleMessage` then `Signaling._handleMessage` | 6685-6689, 9116-9123 |
| `producerCommand` | client -> SFU (+ replies) | binary commands; `useCommandDataChannel(true)` is called **before** it is created so `_isDataChannelCommand` routes eligible commands here | 6690-6694, 9124-9142 |
| `producerScreenShare` | SFU -> client | fast screen-share receiver (not ported) | 6695-6698 |
| `consumerScreenShare` | client -> SFU | fast screen-share sender (not ported) | 6747-6753 |

(`asr` and `animoji` channels are conditional on `Q.asrDataChannel` /
`Q.vmoji`; the capture had neither.)

Which ws2 commands go over `producerCommand` (`_isDataChannelCommand`,
S:9484-9494): `update-display-layout`, `report-perf-stat`,
`report-sharing-stat`, `request-asr`, `enable-video-suspend`,
`enable-video-suspend-suggest`, `report-network-stat`, `change-simulcast` —
and only while `producerCommandDataChannelEnabled`. Everything else stays JSON
over the WebSocket. A queued command object is `{sequence, name, route:
"producer"|"websocket", params, needResponse, ...}` (S:9467-9481).

**Sequence numbers are shared**: `_sendRaw` takes `c = this.sequence++`
(S:9467) for both routes. In the capture the data-channel request carried
`sequence=4` after ws2 `allocate-consumer`=1, `change-media-settings`=2,
`accept-producer`=3. The Go port draws from the same `h.seq` (`nextSeq()`).

Queueing: commands pushed while the channel is not open sit in
`datachannelCommandsQueue` and are flushed in `setProducerCommandDataChannel`
/ `_handleCommandsQueue` (S:9141, 9805-9829). Responses are matched by
`sequence` via `responseHandlers`; `_resetProducerConnection` (S:9146-9160)
rejects every pending `route:"producer"` command when the PC is rebuilt.

## 3. msgpack dialect

The bundle ships its own small msgpack (`B:@290576-296560`). Writer `_S()`
(S:2118-2181) is a big-endian growable buffer; reader `yS()`/`C_()`
(S:2182-2236). Typed codecs used by this protocol:

| codec | B:@ | encoding |
|---|---|---|
| `F_` int | 293194 | **signed family only**: 0..127 positive fixint; -1..-31 negative fixint; else `d0` int8 / `d1` int16 / `d2` int32 / `d3` int64 by *signed* range. So 320 is `d1 01 40` (a canonical encoder would write `cd 01 40`). `F_.dec` also accepts `cc..cf` unsigned and treats `c0` nil as 0. |
| `N_` nil | 292970 | `c0` |
| `P_` bool | 293057 | `c2`/`c3`; dec treats `c0` as false |
| `z_` str | 294264 | fixstr (<32 bytes) else `d9`/`da`/`db` (`w_`, B:@291792); UTF-8 via `G_` |
| `R_` bin | 294230 | `c4`/`c5`/`c6` + bytes |
| `V_` array | 294830 = `U_(M_)` | header `E_` (B:@292252): fixarray <16 else `dc`/`dd`; elements generic |
| `H_` map | `W_(M_,M_)` | header `O_` (B:@292443): fixmap <16 else `de`/`df` |
| `M_` any | 292905 | encoder picks by JS type (`q_`, B:@295681: integer>=0 -> `I_` unsigned, <0 -> `F_`, ArrayBuffer -> `R_`); decoder dispatches on tag (`J_`, B:@296036) |
| `Y_(bytes)` | 296527 | `M_.dec(C_(bytes))`: one generic value from a byte view |

This is why `max_sfu_dc.go` hand-rolls the codec instead of using the repo's
`github.com/vmihailenco/msgpack/v5` (used by `maxproto`): the unit tests must
reproduce the browser's bytes exactly, and `F_`'s signed-tag choice is not
what a canonical encoder produces.

## 4. `producerCommand` — client -> SFU command frames

Serializer class `FS` (S:2249-2378), constants S:2237-2248:

```
command types  bS=0 UPDATE_DISPLAY_LAYOUT   xS=1 REPORT_PERF_STAT   SS=2 REPORT_SHARING_STAT
               CS=3 REQUEST_ASR             wS=4 REPORT_NETWORK_STAT TS=5 ENABLE_VIDEO_SUSPEND
               ES=6 ENABLE_VIDEO_SUSPEND_SUGGEST                     DS=7 CHANGE_SIMULCAST
version        jS=0            response ok code  MS=0
layout kinds   OS=0 normal     kS=1 stopStream   AS=2 keyFrameRequested
fit            NS=0 "cv" cover PS=1 "cn" contain
```

Every command starts with the same three `F_` ints — there is **no separate
binary header**; the "prefix" bytes are msgpack fixints:

```
F_(commandType)  F_(version=0)  F_(sequence)  <command-specific body>
```

### 4.1 UPDATE_DISPLAY_LAYOUT (`serializeUpdateDisplayLayout`, S:2258-2264)

```
F_(0) F_(0) F_(seq) N_(nil) V_([ R_(layout_1), R_(layout_2), ... ]) N_(nil)
```

`params` is the JS object `{ "<streamDesc>": {width,height,fit,priority?} |
{stopStream:true} | {keyFrameRequested:true}, ... }`; each key/value becomes
one nested msgpack blob (`writeLayout`, S:2265-2291) carried as a **bin**:

```
layout := streamDesc  F_(kind)  [ body ]
streamDesc := F_(compactId)         if participantIdRegistry.getCompactId(key) is known   (writeStreamDesc, S:2292-2300)
            | z_("<streamDesc>")     otherwise
kind=1 (stopStream) / kind=2 (keyFrame): nothing follows
kind=0: (priority===undefined ? N_ : F_(priority))
        (width&&height ? F_(round(w)) F_(round(h)) : N_ N_)
        (fit "cv" -> F_(0) | "cn" -> F_(1) | else N_)
```

Stream description string (`mS`, S:2079-2085; parsed by `hS`, S:2086-2113):
`<participantId>[:s<MEDIA>][:m<streamName>]` where `participantId` is the
composite `Z.composeParticipantId` (S:270-292): `"u"|"g"` + numeric id, plus
`":d<deviceIdx>"` when non-zero. `MEDIA` is one of `dS` (S:2066-2075):
`CAMERA SCREEN STREAM MOVIE ANIMOJI SHARED_URL`. So a peer camera is
`u1125900244908947:sCAMERA`; a participant-level key has no `:s` part.

What the app puts in: `_getRequestLayouts` (B:@646593) builds
`{uid, mediaType, width, height, fit: cover ? "cv" : "cn", priority?}` per
visible tile, throttled by `requestDisplayLayoutThrottleMs` (750 ms, S:1263)
and diffed against the last sent layouts (`_getDiff`); `Call.updateDisplayLayout`
(B:@727283) maps them to `mS(...)` keys, evicts over `videoTracksCount`
(default 30, S:1262) with `{stopStream:true}`, and sends only in SERVER
topology. The **same command over the WebSocket** would instead be JSON
`{command:"update-display-layout", sequence, layouts:{"<desc>": "sz=320x240:fit=cv"}}`
(`_serializeJson` + `_convertDisplayLayout` + `uS`, S:9912-9926, 2052-2065) —
not used while the data channel is enabled.

### 4.2 Other commands (listed, not ported)

`REPORT_PERF_STAT`: `F_(1) F_(0) F_(seq) F_(framesDecoded) F_(framesReceived)` (S:2301-2311).
`REPORT_SHARING_STAT`: `F_(2) F_(0) F_(seq) F_(minDelay) F_(maxDelay) F_(avgDelay) F_(largeDelayDuration)`.
`REQUEST_ASR`: `F_(3) F_(0) F_(seq) P_(request)`.
`REPORT_NETWORK_STAT`: `F_(4) F_(0) F_(seq) F_(timestamp) F_(sendBitrate)`.
`ENABLE_VIDEO_SUSPEND[_SUGGEST]`: `F_(5|6) F_(0) F_(seq) P_(enabled)`.
`CHANGE_SIMULCAST`: `F_(7) F_(0) F_(seq) F_(mediaSource) F_(nStreams) { z_(rid) F_(w) F_(h) F_(fps) F_(bitrate/1000) }*`.

## 5. `producerCommand` — SFU -> client responses

`FS.deserializeCommandResponse` (S:2379-2417):

```
F_(commandType) F_(version)  -- must be 0, else "Unsupported version"
F_(errorCode)                -- must be MS=0, else "Error code: N received..." and the frame is dropped
type 0: F_(sequence) V_([ R_(entry)... ])  entry := M_(key: int compactId | str desc) F_(errorCode)
        -> {type:"response", response:"update-display-layout", sequence, errorCodeByParticipantId}
type 1: F_(sequence) F_(estimatedPerformanceIndex)
```

The response resolves the pending command by `sequence` like any ws2 response
(`_handleCommandResponse`, S:9773-9803). `_sendUpdateDisplayLayout`
(B:@730130) turns non-empty `errorCodeByParticipantId` into
"Could not allocate one or more participants".

## 6. `producerNotification` — SFU -> client

Every frame is `uint8 type` followed by **one generic msgpack value** (`Y_`),
handled by the participant-id registry `VC.handleMessage` (S:4168-4262):

| type | body | meaning | JS notification |
|---|---|---|---|
| 1 | map `{ "<streamDesc>": compactId }` | **registry**: the SFU assigns small ints to stream descriptions; both sides may use the int instead of the string afterwards (`getStreamDescription`/`getCompactId`, S:4162-4167) | none (returns null) |
| 2 | array `[compactId...]` | audio activity | `audio-activity {activeParticipants}` |
| 3 | int compactId | speaker changed | `speaker-changed {speaker}` |
| 4 | array `[compactId...]` | stalled participants | `stalled-activity {stalledParticipants}` |
| 5 | array `[maxBitrate, maxDimension, mediaType(0=CAMERA,1=SCREEN,nil)]` | | `video-quality-update` |
| 6 | map `{ compactId: percent }` | network status, value/100 | `network-status {statuses}` |
| 7 | map `{ slotIndex: [compactId|nil, rtpTimestamp|nil, sequenceNumber, fastScreenShare, suspend|nil] }` | **slot assignment**: consumer slot `pat-<slotIndex>` now carries that stream (nil compactId = released) | `participant-sources-update {participantUpdateInfos:[{participantStreamDescription, streamId:"pat-N", rtpTimestamp, sequenceNumber, fastScreenShare, suspend}]}` (S:4272-4308) |
| 8 | array of `[compactId, gain, pause, offset, mute, liveStatus, startTimeMs]` | | `movie-update-notification` |
| 9 | int | | `video-suspend-suggest {bandwidth}` |

What the app does with type 7 (`_onParticipantSourcesUpdate` ->
`_waitForStreamIfNeeded`, B:@735868): resolves the stream description, drops
it if `sequenceNumber` is older than the last `_stopStreaming` sequence for
that stream ("outdated PAT response"), optionally waits until the track's RTP
timestamp reaches `rtpTimestamp` (`getStreamWaitingTimeMs`) when a slot is
being switched between participants, then looks the `MediaStream` up **by
`streamId` (`pat-N`)** in `_streamByStreamId` — i.e. the msid the track
arrived with in `ontrack` — and fires `onRemoteStream(participant, stream)`.

Correlation with SDP/OnTrack: `_updateSSRCMap` (S:6784-6789) keeps
`ssrc -> label` from `a=ssrc:<n> label:(audio|video)-(<id>|mix|pat-N|ta-N)`.
In pion, `TrackRemote.StreamID()` is the msid stream id (`pat-N`) and the SSRC
matches the offer's `a=ssrc ... label:video-pat-N` lines; `parseSFUSlotMap`
builds `pat-N -> {mid, ssrcs}` from the offer so both are logged together.

## 7. The captured frames, decoded

All from `/tmp/golden/D3.jsonl`, `who:"oracle-D"`, `pc:1`; `t` is ms.

`t=71388 producerNotification rx (21 B)`: `01 81 b1 75..34 00`
- `01` type 1 registry; `81` fixmap(1); `b1` fixstr(17) `u1125900244960634` (the browser's own participant, no media type); `00` compact id 0.

`t=71389 producerNotification rx (4 B)`: `06 81 00 3c`
- type 6 network-status; fixmap(1); key `00` compact 0 (self); `3c` = 60 -> 0.60.

`t=74983 producerNotification rx (2 B)`: `04 90`
- type 4 stalled-activity; `90` empty array.

`t=76385 producerNotification rx (4 B)`: `06 81 00 46` — network-status self = 70/100.

`t=82138 ws rx participant-joined participantId=1125900244908947` (JSON).

`t=82257 producerCommand tx (43 B)`:
```
00            F_ commandType 0 = UPDATE_DISPLAY_LAYOUT
00            F_ version 0
04            F_ sequence 4        (ws2 counter: 1 allocate-consumer, 2 change-media-settings, 3 accept-producer)
c0            N_ nil
91            V_ fixarray(1)                       -- one layout entry
c4 23         R_ bin8, 35 bytes:
   b9 "u1125900244908947:sCAMERA"   z_ fixstr(25): stream description (string form — the
                                    registry had no compact id for the peer yet)
   00                                F_ kind 0 = normal layout
   c0                                N_ priority undefined
   d1 01 40                          F_ width 320   (signed int16 tag)
   d1 00 f0                          F_ height 240
   00                                F_ fit 0 = "cv" (cover)
c0            N_ trailing nil
```
So the guessed "4-byte header" is really `F_(0) F_(0) F_(seq) N_`; there is no
command-id/sequence header outside msgpack.

`t=82462 producerCommand rx (5 B)`: `00 00 00 04 90`
- `00` commandType 0; `00` version 0; `00` errorCode 0 (ok); `04` sequence 4; `90` empty array -> no per-stream errors: request accepted.

`t=83579 ws rx registered-peer participantId=1125900244908947` (JSON).

`t=83710 producerNotification rx (29 B)`: `01 81 b9 "u1125900244908947:sCAMERA" 01`
- registry: the peer's CAMERA stream is compact id 1.

`t=83710 producerNotification rx (9 B)`: `07 81 00 95 01 c0 04 c0 c0`
- type 7 sources-update; fixmap(1); key `00` -> slot `pat-0`; `95` fixarray(5):
  `01` compactId 1 (= u1125900244908947:sCAMERA), `c0` rtpTimestamp nil (switch now),
  `04` sequenceNumber 4 (answers our seq-4 request), `c0` fastScreenShare -> false,
  `c0` suspend -> undefined.
- Meaning: the peer's camera is now on consumer slot `pat-0`, i.e. the offer's
  `m=video ... a=mid:5 / a=msid:pat-0 video-pat-0 / a=ssrc:3611711214|3611711215 label:video-pat-0`
  (offer at `t=65582`; mid 3 `pat-256` is the browser's own producer slot, no ssrc lines).

`t=87457 producerNotification rx (4 B)`: `06 81 00 46` — network-status again.

Round-trip unit tests for every one of these frames: `max_sfu_dc_test.go`.

## 8. Go port summary (`max_joiner.go`, SFU mode)

- `initPCSFU` creates the four channels with `DataChannelInit{Ordered:true}`,
  keeps their handles in `sfuDCs`, resets the per-session registry/slot state,
  and attaches handlers (`attachSFUDataChannel`).
- Peers are learned from the `connection` notification's
  `conversation.participants[].id`, `participant-joined` and `registered-peer`
  (self excluded) into `sfuPeers` (call-scoped). When `producerCommand` opens
  (and on each new peer while it is open) one `UPDATE_DISPLAY_LAYOUT` per peer
  is sent for `u<id>:sCAMERA` at `SFUVideoWidth x SFUVideoHeight`
  (default 320x240, fit `cv`), using the registry compact id if the SFU already
  announced one. A PeerConnection rebuild (new `producer-updated` sessionId)
  resets `sfuRequested`, so requests are re-issued on the new channel.
- `producerNotification` frames are decoded and logged; type 7 records
  `pat-N -> stream` in `sfuSlotAssign` and logs the slot's mid/SSRCs from the
  offer (`sfuSlots`, filled in `handleProducerUpdated` after
  `SetRemoteDescription`). `OnTrack` logs `ssrc/streamId/mid/slot/carries` so a
  video track can be matched to the peer it belongs to.
- All frames are also written to the JSONL transcript as `kind:"dc"` lines in
  the browser oracle's shape (`trDC`), for diffing.

## 9. Not determined / not ported

- Meaning of the per-stream `errorCode` values in the UPDATE_DISPLAY_LAYOUT
  response (`HT(t)` -> `VT` reasons, B:@730130) — not traced; we only log them.
- Notification types 2, 3, 5, 8, 9 and the perf-stat response were decoded from
  the bundle only; none appeared in the capture.
- `stopStream` on participant leave, `keyFrameRequested`, priorities, the
  screen-share channels, `REPORT_*`/`CHANGE_SIMULCAST` senders and the
  `rtpTimestamp` wait-before-switch logic are not wired (encoders/decoders for
  the layout kinds exist and are tested).
- Whether the SFU honours a request sent before it has announced the peer in a
  type-1 registry message: the capture shows the browser sending the string
  form first and the SFU accepting it (response err=0 then a type-7
  assignment), so yes for the string form.
