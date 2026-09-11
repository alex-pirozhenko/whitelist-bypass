# Gemini prompt #2 — why does the SFU keep re-offering (reject our accept-producer)?

## Files (same dir)
- `webref_max_web_call.beautified.js` (~57k lines, readable) — the web.max.ru call/WebRTC/OK-Calls-SDK bundle. **Analyze this.**
- `max_joiner.go` — OUR Go/pion re-implementation. Compare against it.
- `webref_GEMINI_PROMPT.md` — the first prompt (context on the overall join flow).

Identifiers are single letters; follow data flow, not names. Anchors from prompt #1 still apply:
ServerTransport class `Qw` (24056–24458); `_openConnection` (24076–24110); `_onProducerUpdated`
(24390–24394); `_acceptProducer` (24309–24332); `_processOffer` (24274–24308); `_updateSSRCMap`
(24129–24135); allocate-consumer (24893–24921, videoTracksCount default 30 at 20427); command enum
~21191; notification enum ~21725.

## What we already fixed and PROVED on the wire (do not re-litigate these)
Since prompt #1 we applied and packet-verified all of:
1. `accept-producer.ssrcs` now echoes the SFU OFFER's labeled ssrcs (a=ssrc:<id> label:...), not our answer's.
2. Remote offer candidates are kept (not stripped); local answer candidates kept; setup:active.
3. The RTCPeerConnection is torn down + rebuilt on every sessionId change (clean ICE creds per generation).
4. Aggressive nomination: our ICE binding requests now carry USE-CANDIDATE on EVERY check (verified
   `use-candidate=true` on the wire), matching the browser.

## The exact remaining failure (packet + signaling captures, browser works / we don't, same network)
- We join (op166), topology flips SERVER, we send `allocate-consumer`, SFU sends `producer-updated`
  (an SDP offer, 5 m-lines for us: mid0 audio recv, mid1 SCTP, mid2 audio send, mid3 video send = our
  data track, mid4 video recv). The real browser negotiates ~35 m-lines.
- We answer, send `accept-producer {description:<raw SDP>, sessionId, ssrcs:[the offer's labeled ssrcs]}`.
- The SFU replies `{"response":"accept-producer"}` (a bare receipt, no error) — but then, ~20s later,
  **re-offers `producer-updated` with a NEW sessionId and NEW ice-ufrag/ice-pwd**, and repeats this every
  ~20s indefinitely. i.e. it is REJECTING our accept-producer and never arming its ICE responder.
- Consequently our ICE binding requests to the SFU host candidate (e.g. 155.212.206.84:43210 udp /
  :7684 tcp-passive) get **ZERO responses** — the SFU never set up ICE for a session it rejected. The
  requests themselves are well-formed: USERNAME=`<sfuUfrag>:<ourUfrag>` (matching generation),
  ICE-CONTROLLING, PRIORITY, USE-CANDIDATE, MESSAGE-INTEGRITY (keyed with the offer's ice-pwd),
  FINGERPRINT. The SFU host is reachable (its TCP :7684 accepts connections; the STUN servers answer us).
- The real browser client's FIRST accept-producer sticks: no re-offer loop, ICE completes, media flows.

## THE question: what makes accept-producer actually succeed (stop the re-offer loop + arm ICE)?
Ground EVERY claim in a JS line number from `webref_max_web_call.beautified.js`. Answer precisely:

1. **`ssrcs` semantics.** In `_acceptProducer` / `_updateSSRCMap`, what EXACTLY goes in the `ssrcs`
   field — the offer's producer ssrcs, our own answer ssrcs, RTX ssrcs too, a subset by label, or a
   different shape (array vs map/object)? How many entries, and keyed/ordered how? Show the code that
   builds the accept-producer payload verbatim.

2. **Must every offered m-line be answered?** The SFU offers us 5 m-lines but the browser answers ~35.
   Does answering FEWER m-lines than offered (or leaving pre-allocated recvonly consumer slots
   unanswered / not rejected with a=inactive+port 0) cause the SFU to reject and re-offer? What does the
   browser put for consumer m-lines it isn't actively using?

3. **Extra commands that arm the transport/ICE.** Between `producer-updated` and ICE succeeding, does the
   client send any OTHER ws2 command that arms the media transport or ICE — e.g. `consumer-answered`,
   `resume-consumer`, `connect-transport`, `connect-webrtc-transport`, `restart-ice`,
   `change-media-settings`, `producer-*`? List the exact sequence of commands the client sends from
   `producer-updated` receipt through media flowing, with the JSON field shapes.

4. **DTLS / transport-connect coupling.** Is ICE gated on a DTLS role or an explicit transport-connect
   step? Does the SFU wait for something in the answer (a specific setup:, a fingerprint match, a
   dtlsParameters/iceParameters object sent SEPARATELY from the SDP over ws2) before it arms ICE?

5. **What is the precise server-side trigger that STOPS the re-offer / periodic producer-updated?** If
   you can see a timeout or a "producer not accepted" path, name it.

Deliver: (a) the exact accept-producer payload builder with line cites; (b) the full command sequence
producer-updated → media; (c) a focused verdict on WHY a minimal 5-m-line answer with offer-ssrcs would
be rejected and re-offered; (d) concrete changes to max_joiner.go. If undeterminable from the JS, say so.
