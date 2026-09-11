# Gemini prompt — extract MAX / OK-Calls SFU joining reference from the web-client JS

## Files (in this directory)
- `webref_max_web_call.beautified.js` (~57k lines, readable) — the web.max.ru chunk that contains the
  ENTIRE call/WebRTC/OK-Calls-SDK logic. **Analyze this one.**
- `webref_max_web_call.min.js` — the original minified source (same content), if you want the raw bytes.
- `max_joiner.go` (same directory) — OUR Go/pion re-implementation that we are trying to fix. Compare against it.

Both JS files are one minified/beautified vendor bundle; identifiers are single letters (`e`,`t`,`n`,`r`,`s`…).
Function boundaries are obfuscated — read by following data flow around the anchor lines below, not by name.

## Context — what this is and the exact bug we're chasing
`max_joiner.go` joins a MAX (OK-Calls) group call as a WebRTC endpoint to tunnel data. Signalling is JSON
over a TEXT WebSocket ("ws2", `videowebrtc.okcdn.ru/ws2`). The media server is a **mediasoup-style SFU** that
is **`a=ice-lite`** (so our client is the ICE **controlling** agent). The flow that works in the browser but
FAILS in our pion client:

1. ws2 `connection` notification → TURN/STUN creds + topology.
2. We send `allocate-consumer` (a structured `capabilities` object).
3. At 3+ participants topology flips to `SERVER`; the SFU sends **`producer-updated`** = an SDP **offer**
   (5 m-lines for us: mid0 audio recv, mid1 SCTP, mid2 audio send, mid3 video send = our data track, mid4
   video recv; the browser negotiates ~35 m-lines with many pre-allocated recvonly consumer slots).
4. We answer and send **`accept-producer`** `{description:<raw SDP string>, sessionId, ssrcs:[int,…]}`.
5. We (controlling) run ICE against the SFU's inline host candidate (`155.212.x:43210` UDP, `:7684` TCP-passive).

**The failure (proven by a packet capture, browser vs our pion, same SFU, same homelab network):**
- Our pion sends STUN Binding Requests to the SFU with the correct-looking USERNAME (`srvUfrag:ourUfrag`),
  ICE-CONTROLLING, PRIORITY, MESSAGE-INTEGRITY, FINGERPRINT — and gets **ZERO responses and ZERO errors**.
- The real browser client sends nearly the same request (plus `USE-CANDIDATE` and `GOOG-NETWORK-INFO`) and
  gets answered (44 responses) → media flows.
- 0 responses + 0 errors from an ice-lite server = it is **silently dropping our packets for bad
  MESSAGE-INTEGRITY / wrong credentials**. The SFU **re-offers `producer-updated` ~4× with a NEW ice-ufrag +
  ice-pwd each time**. Our leading hypothesis: across those re-offers our client pairs the WRONG ufrag with
  the WRONG pwd (a ufrag from one generation, a pwd from another), so integrity fails on every packet. The
  browser handles the same 3–4 re-offers cleanly and stays in sync.

## What to produce
A precise, language-agnostic **reference spec of the joining/ICE logic**, written so we can port it to
`max_joiner.go`. Ground EVERY claim in a JS line number from `webref_max_web_call.beautified.js`. Cover:

1. **The producer-updated → accept-producer cycle.** How the client turns the SFU's offer into its answer:
   which RTCPeerConnection calls, in what order (setRemoteDescription/createAnswer/setLocalDescription), how
   it builds the `accept-producer` payload (the exact `ssrcs` it puts, how `sessionId` is chosen), and any
   SDP munging it does to the answer before sending (setup role, rtcp-mux, extmaps, ssrc-group, msid, mid
   handling, the BUNDLE group).

2. **★ ICE credential handling across re-offers (the bug).** When a NEW `producer-updated` arrives with a new
   `a=ice-ufrag`/`a=ice-pwd`: does the client do a full `setRemoteDescription(offer)` + new answer (ICE
   restart), or patch in place? How does it guarantee the outgoing STUN USERNAME and MESSAGE-INTEGRITY use
   the **matching** ufrag+pwd from the **same** offer generation? Look around: `setRemoteDescription`
   (l.12932, 13467, 14029, 14118), `createAnswer` (l.13402, 13494), `usernameFragment` (l.13626, 13757,
   13973), `ice-ufrag`/`ice-pwd`/`ice-lite` builder (l.13757–13764), `iceRestart` / `iceRestartWaitTime`
   (~l.20154). Explain exactly what keeps the browser's credentials consistent that our port likely breaks.

3. **ICE role + nomination.** Confirm the client forces itself CONTROLLING for the ice-lite SFU (how/where),
   and whether it uses **aggressive nomination** (USE-CANDIDATE on the first check) vs regular. Does it set
   any Pion-equivalent flags (e.g. an ice-lite-aware transport policy)? Note `forceRelayPolicy` (l.20058)
   and `iceTransportPolicy` usage.

4. **allocate-consumer capabilities** (l.21498, 24895–24905) — the exact object, and whether the count of
   consumer slots the SFU offers (5 vs ~35 m-lines) depends on it. Does answering fewer m-lines than offered,
   or a specific capability, cause the SFU to re-offer/reject? 

5. **The ws2 command/notification vocabulary** actually used for the SFU media path (anchors: command enum
   ~l.21191, notification enum ~l.21725, call handling ~l.25805): `allocate-consumer`, `accept-producer`,
   `producer-updated`, `consumer-answered`, `switch-topology`, `topology-changed`, `change-media-settings`,
   etc. — the precise JSON field shapes.

Deliver: (a) a step-by-step sequence with JS line cites; (b) the exact answer-SDP transform rules; (c) a
focused root-cause verdict on the ufrag/pwd-across-re-offers question with the JS evidence; (d) a short list
of concrete changes to `max_joiner.go` if you can infer them. If a detail isn't determinable from the JS,
say so rather than guessing.
