# MAX web client (web.max.ru) video-call signaling: ws2 protocol reference

Source: `maxweb_calls.js`, ~1.24MB, single line, minified. All citations below are
**byte offsets into that file** (there are no newlines to use as line numbers — I
verified the file is one physical line, 1,243,267 characters). Every offset was
located with a Python substring/regex scan of the raw file and the surrounding
text was extracted and re-wrapped for readability; mangled identifiers (`sS`,
`aC`, `Q`, `Z`, `FC`, `AT`, `CT`, `uC`, `lC`, `jT`, `zT`, `TT`, ...) are kept as-is
and explained in prose. Where something was searched for and **not found**, that
is stated explicitly rather than guessed.

Class-name legend I inferred from usage patterns (minified names, not in source):
- `sS` = outbound command-name enum (symbol → wire string)
- `aC` = inbound notification-name enum (wire string → symbol)
- `uC` = topology enum: `DIRECT` / `SERVER`
- `lC` = per-transport connection-state enum: `IDLE/OPENED/CONNECTING/RECONNECTING/CONNECTED/CLOSED/FAILED`
- `jT` = call direction enum: `INCOMING/OUTGOING/JOINING`
- `zT` = per-participant session state: `CALLED/ACCEPTED/REJECTED/HUNGUP`
- `rC` = ws2 connection-type enum: `START/ACCEPT/JOIN/RETRY` (becomes the `tgt` query param)
- `iC` = internal signaling-event-bus enum: `NOTIFICATION/FAILED/RECONNECT`
- `Q` = global mutable SDK config object (`Q._params`, with getters/setters)
- `Z` = utility/codec/participant-id namespace (`Z.patchLocalSDP`, `Z.composeParticipantId`, ...)
- `FC` = the **DirectTransport** class (the 1:1 / DIRECT-topology RTCPeerConnection wrapper) — **this is the class that matters most for §3**
- `AT` = the signaling-socket class (owns `_send`/`_sendRaw`, the command queues, `_handleMessage`)
- `CT` = the low-level WebSocket/WebTransport wrapper (owns `_buildUrl`, reconnection, `lastStamp`)
- the "TransportManager" class (unnamed by me) that owns `_directTransport`/`_serverTransport`, `allocate()`, `open()`, `_onTopologyChanged()` — offsets ~573000-585000

---

## 1. Command / notification name tables

### 1a. Outbound commands — `sS` enum

Found once, whole, at offset **447375-448700** (function `sS=function(e){return e.RECOVER=...}(sS||{})`):

```
sS.RECOVER=`recover`,e.ACCEPT_CALL=`accept-call`,e.ADD_PARTICIPANT=`add-participant`,
e.REMOVE_PARTICIPANT=`remove-participant`,e.HANGUP=`hangup`,e.TRANSMIT_DATA=`transmit-data`,
e.ACCEPT_PRODUCER=`accept-producer`,e.ALLOCATE_CONSUMER=`allocate-consumer`,
e.CHANGE_MEDIA_SETTINGS=`change-media-settings`,e.CHANGE_PARTICIPANT_STATE=`change-participant-state`,
e.CHANGE_STREAM_PRIORITIES=`change-streams-priorities`,e.UPDATE_DISPLAY_LAYOUT=`update-display-layout`,
e.REPORT_PERF_STAT=`report-perf-stat`,e.REPORT_SHARING_STAT=`report-sharing-stat`,
e.REPORT_NETWORK_STAT=`report-network-stat`,e.RECORD_START=`record-start`,e.RECORD_STOP=`record-stop`,
e.RECORD_PUBLISH=`record-publish`,e.RECORD_SET_CONF=`record-set-conf`,e.RECORD_GET_STATUS=`record-get-status`,
e.SWITCH_MICRO=`switch-micro`,e.SWITCH_TOPOLOGY=`switch-topology`,e.REQUEST_REALLOC=`request-realloc`,
e.CHAT_MESSAGE=`chat-message`,e.CHAT_HISTORY=`chat-history`,e.CUSTOM_DATA=`custom-data`,
e.GRANT_ROLES=`grant-roles`,e.MUTE_PARTICIPANT=`mute-participant`,
e.ENABLE_FEATURE_FOR_ROLES=`enable-feature-for-roles`,e.PIN_PARTICIPANT=`pin-participant`,
e.UPDATE_MEDIA_MODIFIERS=`update-media-modifiers`,e.CHANGE_OPTIONS=`change-options`,
e.GET_WAITING_HALL=`get-waiting-hall`,e.GET_PARTICIPANT_LIST_CHUNK=`get-participant-list-chunk`,
e.GET_PARTICIPANTS=`get-participants`,e.PROMOTE_PARTICIPANT=`promote-participant`,
e.REQUEST_TEST_MODE=`request-test-mode`,e.ADD_MOVIE=`add-movie`,e.UPDATE_MOVIE=`update-movie`,
e.REMOVE_MOVIE=`remove-movie`,e.START_URL_SHARING=`start-url-sharing`,e.STOP_URL_SHARING=`stop-url-sharing`,
e.GET_ROOMS=`get-rooms`,e.UPDATE_ROOMS=`update-rooms`,e.ACTIVATE_ROOMS=`activate-rooms`,
e.REMOVE_ROOMS=`remove-rooms`,e.SWITCH_ROOM=`switch-room`,e.FEEDBACK=`feedback`,
e.ASR_START=`asr-start`,e.ASR_STOP=`asr-stop`,e.REQUEST_ASR=`request-asr`,
e.REQUEST_PROMOTION=`request-promotion`,e.ACCEPT_PROMOTION=`accept-promotion`,
e.GET_HAND_QUEUE=`get-hand-queue`,e.ENABLE_VIDEO_SUSPEND=`enable-video-suspend`,
e.ENABLE_VIDEO_SUSPEND_SUGGEST=`enable-video-suspend-suggest`,e.HOLD=`hold`,
e.PUT_HANDS_DOWN=`put-hands-down`,e.CHANGE_SIMULCAST=`change-simulcast`
```

| Symbol | Wire string | Symbol | Wire string |
|---|---|---|---|
| RECOVER | `recover` | GET_PARTICIPANTS | `get-participants` |
| ACCEPT_CALL | `accept-call` | PROMOTE_PARTICIPANT | `promote-participant` |
| ADD_PARTICIPANT | `add-participant` | REQUEST_TEST_MODE | `request-test-mode` |
| REMOVE_PARTICIPANT | `remove-participant` | ADD_MOVIE | `add-movie` |
| HANGUP | `hangup` | UPDATE_MOVIE | `update-movie` |
| TRANSMIT_DATA | `transmit-data` | REMOVE_MOVIE | `remove-movie` |
| ACCEPT_PRODUCER | `accept-producer` | START_URL_SHARING | `start-url-sharing` |
| ALLOCATE_CONSUMER | `allocate-consumer` | STOP_URL_SHARING | `stop-url-sharing` |
| CHANGE_MEDIA_SETTINGS | `change-media-settings` | GET_ROOMS | `get-rooms` |
| CHANGE_PARTICIPANT_STATE | `change-participant-state` | UPDATE_ROOMS | `update-rooms` |
| CHANGE_STREAM_PRIORITIES | `change-streams-priorities` **(note: plural "streams")** | ACTIVATE_ROOMS | `activate-rooms` |
| UPDATE_DISPLAY_LAYOUT | `update-display-layout` | REMOVE_ROOMS | `remove-rooms` |
| REPORT_PERF_STAT | `report-perf-stat` | SWITCH_ROOM | `switch-room` |
| REPORT_SHARING_STAT | `report-sharing-stat` | FEEDBACK | `feedback` |
| REPORT_NETWORK_STAT | `report-network-stat` | ASR_START | `asr-start` |
| RECORD_START | `record-start` | ASR_STOP | `asr-stop` |
| RECORD_STOP | `record-stop` | REQUEST_ASR | `request-asr` |
| RECORD_PUBLISH | `record-publish` | REQUEST_PROMOTION | `request-promotion` |
| RECORD_SET_CONF | `record-set-conf` | ACCEPT_PROMOTION | `accept-promotion` |
| RECORD_GET_STATUS | `record-get-status` | GET_HAND_QUEUE | `get-hand-queue` |
| SWITCH_MICRO | `switch-micro` | ENABLE_VIDEO_SUSPEND | `enable-video-suspend` |
| SWITCH_TOPOLOGY | `switch-topology` | ENABLE_VIDEO_SUSPEND_SUGGEST | `enable-video-suspend-suggest` |
| REQUEST_REALLOC | `request-realloc` | HOLD | `hold` |
| CHAT_MESSAGE | `chat-message` | PUT_HANDS_DOWN | `put-hands-down` |
| CHAT_HISTORY | `chat-history` | CHANGE_SIMULCAST | `change-simulcast` |
| CUSTOM_DATA | `custom-data` | GRANT_ROLES | `grant-roles` |
| MUTE_PARTICIPANT | `mute-participant` | ENABLE_FEATURE_FOR_ROLES | `enable-feature-for-roles` |
| PIN_PARTICIPANT | `pin-participant` | UPDATE_MEDIA_MODIFIERS | `update-media-modifiers` |
| CHANGE_OPTIONS | `change-options` | GET_WAITING_HALL | `get-waiting-hall` |
| GET_PARTICIPANT_LIST_CHUNK | `get-participant-list-chunk` | | |

The user-supplied anchor list said `change-stream-priorities` (singular) — the
actual wire string is **`change-streams-priorities`** (plural "streams"); a
literal-string grep for the singular form returns zero hits (verified).

`RECOVER` (`recover`) is **defined but I could not find any call site that sends
it** — see §3h/§6, this is important.

### 1b. Inbound notifications — `aC` enum

Found once, whole, at offset **463020-465100** (`aC=function(e){return e.TRANSMITTED_DATA=...}(aC||{})`), and the dispatcher switch (`_onSignalingNotification`) at offset **749980-751250**:

```
e.TRANSMITTED_DATA=`transmitted-data`,e.ACCEPTED_CALL=`accepted-call`,e.HUNGUP=`hungup`,
e.PARTICIPANT_ADDED=`participant-added`,e.PARTICIPANT_JOINED=`participant-joined`,
e.CLOSED_CONVERSATION=`closed-conversation`,e.MEDIA_SETTINGS_CHANGED=`media-settings-changed`,
e.PARTICIPANT_STATE_CHANGED=`participant-state-changed`,
e.PARTICIPANTS_STATE_CHANGED=`participants-state-changed`,e.RATE_CALL_DATA=`rate-call-data`,
e.FEATURE_SET_CHANGED=`feature-set-changed`,e.TOPOLOGY_CHANGED=`topology-changed`,
e.PRODUCER_UPDATED=`producer-updated`,e.CONSUMER_ANSWERED=`consumer-answered`,
e.MULTIPARTY_CHAT_CREATED=`multiparty-chat-created`,
e.FORCE_MEDIA_SETTINGS_CHANGE=`force-media-settings-change`,e.SETTINGS_UPDATE=`settings-update`,
e.VIDEO_QUALITY_UPDATE=`video-quality-update`,e.REGISTERED_PEER=`registered-peer`,
e.SWITCH_MICRO=`switch-micro`,e.RECORD_STARTED=`record-started`,e.RECORD_STOPPED=`record-stopped`,
e.REALLOC_CON=`realloc-con`,e.AUDIO_ACTIVITY=`audio-activity`,e.SPEAKER_CHANGED=`speaker-changed`,
e.SESSION_STATE=`session-state`,e.STALLED_ACTIVITY=`stalled-activity`,e.CHAT_MESSAGE=`chat-message`,
e.CUSTOM_DATA=`custom-data`,e.ROLES_CHANGED=`roles-changed`,e.MUTE_PARTICIPANT=`mute-participant`,
e.PIN_PARTICIPANT=`pin-participant`,e.OPTIONS_CHANGED=`options-changed`,
e.NETWORK_STATUS=`network-status`,e.PARTICIPANT_SOURCES_UPDATE=`participant-sources-update`,
e.PROMOTE_PARTICIPANT=`promote-participant`,e.CHAT_ROOM_UPDATED=`chat-room-updated`,
e.PROMOTION_APPROVED=`promotion-approved`,e.JOIN_LINK_CHANGED=`join-link-changed`,
e.FEEDBACK=`feedback`,e.MOVIE_UPDATE_NOTIFICATION=`movie-update-notification`,
e.MOVIE_SHARE_STARTED=`movie-share-started`,e.MOVIE_SHARE_STOPPED=`movie-share-stopped`,
e.URL_SHARING_INFO_UPDATED=`url-sharing-info-updated`,e.ROOM_UPDATED=`room-updated`,
e.ROOMS_UPDATED=`rooms-updated`,e.ROOM_PARTICIPANTS_UPDATED=`room-participants-updated`,
e.FEATURES_PER_ROLE_CHANGED=`features-per-role-changed`,
e.PARTICIPANT_ANIMOJI_CHANGED=`participant-animoji-changed`,e.ASR_STARTED=`asr-started`,
e.ASR_STOPPED=`asr-stopped`,
e.DECORATIVE_PARTICIPANT_ID_CHANGED=`decorative-participant-id-changed`,
e.VIDEO_SUSPEND_SUGGEST=`video-suspend-suggest`,e.HOLD=`hold`
```

Note: on the wire, `e.TRANSMIT_DATA`'s **reply/echo notification is `transmitted-data`** — the client's own outbound `transmit-data` command shows up to *both* peers as a `transmitted-data` notification (the server relays it and reflects a copy back with `notification:"transmitted-data"`). Also: there is **no separate `connection` entry in the `aC` enum** — `"connection"` is a bare literal string compared directly (see §2), not a named enum member.

| Wire string | Handled by (top-level `_onSignalingNotification` switch, offset ~749980) |
|---|---|
| `accepted-call` | `_onAcceptedCall(e)` |
| `hungup` | `_onHungup(e)` |
| `participant-added` | `_onAddedParticipant(e)` |
| `participant-joined` | `_onJoinedParticipant(e)` |
| `closed-conversation` | `_onClosedConversation(e)` |
| `media-settings-changed` | `_onMediaSettingsChanged(e)` |
| `participant-state-changed` | `_onParticipantStateChanged(e)` |
| `session-state` | `_onSessionState(e)` |
| `participants-state-changed` | `_onParticipantsStateChanged(e)` |
| `rate-call-data` | `_onNeedRate()` |
| `feature-set-changed` | `_onFeatureSetChanged(e)` |
| `multiparty-chat-created` | `_onMultipartyChatCreated(e)` |
| `force-media-settings-change` | `_onForceMediaSettingsChange(e)` |
| `settings-update` | `_onSettingsUpdate(e)` |
| `video-quality-update` | `_onVideoQualityUpdate(e)` |
| `registered-peer` | `_onPeerRegistered(e)` |
| `switch-micro` | `_onMicSwitched(e)` |
| `chat-message` | `_onChatMessage(e)` |
| `custom-data` | `_onCustomData(e)` |
| `record-started` | `_onRecordInfo(e.recordInfo,e.roomId)` |
| `record-stopped` | `_onStopRecordInfo(e,e.roomId)` |
| `roles-changed` | `_onRolesChanged(e.participantId,e.roles||[])` |
| `mute-participant` | `_onMuteParticipant(e)` |
| `pin-participant` | `_onPinParticipant(e.participantId,e.unpin,e.markers,e.roomId)` |
| `options-changed` | `_onOptionsChanged(e.options||[])` |
| `participant-sources-update` | `_onParticipantSourcesUpdate(e)` |
| `promote-participant` | `_onParticipantPromoted(e)` |
| `chat-room-updated` | `_onChatRoomUpdated(e.eventType,e.totalCount,e.firstParticipants,e.addedParticipantIds,e.removedParticipantIds)` |
| `join-link-changed` | `_onJoinLinkChanged(e)` |
| `feedback` | `_onFeedback(e)` |
| `movie-update-notification` | `_onSharedMovieUpdate(e)` |
| `movie-share-started` | `_onSharedMovieInfoStarted(e)` |
| `movie-share-stopped` | `_onSharedMovieInfoStopped(e)` |
| `url-sharing-info-updated` | `_onUrlSharingInfoUpdated(e)` |
| `rooms-updated` | `_onRoomsUpdated(e)` |
| `room-updated` | `_onRoomUpdated(e)` |
| `room-participants-updated` | `_onRoomParticipantsUpdated(e)` |
| `features-per-role-changed` | `_onFeaturesPerRoleChanged(e)` |
| `participant-animoji-changed` | `_onParticipantAnimojiChanged(e)` |
| `asr-started` | `_onAsrStart(e)` |
| `asr-stopped` | `_onAsrStop(e)` |
| `promotion-approved` | `_onPromotionApproved(e)` |
| `decorative-participant-id-changed` | `_onDecorativeParticipantIdChanged(e)` |
| `video-suspend-suggest` | `_onVideoSuspendSuggest(e)` |
| `hold` | `_onParticipantHold(e)` |
| `topology-changed` | `_onSignalingTopologyChanged(e)` (a lightweight no-op-ish sync: `this._conversation.topology=e.topology` if changed — the *real* topology handling lives one layer down, in the TransportManager's own `_onTopologyChanged`, see §3a/§4) |

Two other, **separate**, smaller `_onSignalingNotification` switches exist lower in the stack and only look at the notifications relevant to them:

- **DirectTransport** (`FC`, offset ~476985): `transmitted-data` → `_handleTransmittedData(e)`; `settings-update` → `this._directStatReporter.updateSettings(e.settings)`; `custom-data` → if `e.data.sdk` present, `_directStatReporter.reportRemote(e.data?.sdk)`.
- **ServerTransport** (offset ~566274): `producer-updated` → `_onProducerUpdated(e)`; `realloc-con` → `_reconnect()`; `audio-activity` → `_signalActiveParticipants(e.activeParticipants)`; `speaker-changed` → `_signalSpeakerChanged(e.speaker)`; `stalled-activity` → `_signalStalledParticipants(e.stalledParticipants)`; `network-status` → `_signalNetworkStatus(e.statuses)`.

**`consumer-answered` is defined in the enum but I found zero references to `aC.CONSUMER_ANSWERED` (or the bare identifier `CONSUMER_ANSWERED`) anywhere outside the enum definition itself.** See §4 and §6 — the client instead receives the producer's SDP offer (both the *initial* one and every renegotiation) via `producer-updated`, and `_onProducerUpdated` always calls `_acceptProducer`. I could not find any code path that reacts to a distinct "consumer answered" server message; either it's genuinely dead code in this client, or it's consumed by a mechanism I didn't locate (e.g. matched purely as the `response` to `ALLOCATE_CONSUMER`, which is handled generically by `_handleCommandResponse` and never inspected for `notification===aC.CONSUMER_ANSWERED"`).

---

## 2. Connection bring-up sequence

### 2a. What happens before the WebSocket even opens

Three REST-driven entry points build the "conversation params" object (`endpoint`,
`wt_endpoint`, `token`, `stun_server`, `turn_server`, `is_concurrent`, `p2p_forbidden`,
`device_idx`, ...) and choose a `rC` connection type, offset ~700900-705000:

- **Starting an outgoing call**: `this._api.startConversation(...)` → `_connectSignaling(rC.START, p)` (offset 701230/701260ish).
- **Joining an existing/group conversation**: `this._api.joinConversation(...)` (or `joinConversationByLink`, or a "fast join" callback) → `_connectSignaling(rC.JOIN, l)` (offset 703457).
- **Receiving an incoming call (push)**: `_prepareConversation(...)` resolves `endpoint`/`token` (via `_decodeExternalConversationParams` or `_getConversationParams`) → `_connectSignaling(rC.ACCEPT, l)` (offset 704810).
- **Reconnecting** an already-live call uses `rC.RETRY` (found via the enum and via `_buildUrl`'s `recoverTs` gate, see below); I did not extract the exact call site but the enum member exists and `_buildUrl` special-cases it.

iceServers are populated from the REST response, not from ws2, offset **698150-698300**:
```
async _getConversationParams(e){let t=await this._api.getConversationParams(e);...
let{turn_server:n,stun_server:r}=t;return Q.iceServers=iE(r,n), Q.wssBase=t.endpoint, ...}
_setConversationParams({turn_server:e,stun_server:t,endpoint:n,wt_endpoint:r,token:i,client_type:a}){
  Q.iceServers=iE(t,e), Q.wssBase=n, Q.wssToken=i, r&&(Q.wtsBase=r), ...}
```
`iE(stun,turn)` (offset **636083**):
```
function iE(e,t){let n=[],r=rE(e),i=rE(t);if(r&&n.push(r),i){
  let e=[...i.urls];e.push(`${e[e.length-1]}?transport=tcp`),n.push({...i,urls:e})}return n}
```
i.e. `iceServers` = `[stunServerEntry?, turnServerEntry-with-an-extra-?transport=tcp-URL-appended?]`.
`forceRelayPolicy` also comes back from the server as **`p2p_forbidden`** on the
conversation object and overrides the SDK default, offset **707825-707900**:
```
e.p2p_forbidden&&(Q.forceRelayPolicy=e.p2p_forbidden)
```
(There is also a public SDK setter `zO(e){Q.forceRelayPolicy=e}`, offset 812976, that the host app can call directly.)

### 2b. Building the ws2 URL — `_buildUrl`, offset **604000-604900**

```
_buildUrl(e,t){let n=new URL(e),r=n.searchParams;
  return r.set(`platform`,Q.platform),
    r.set(`appVersion`,String(Q.appVersion)),
    r.set(`version`,String(Q.protocolVersion)),
    r.set(`device`,Q.device),
    r.set(`capabilities`,fT.getFlags()),
    r.set(`clientType`,Q.clientType),
    this.connectionType&&r.set(`tgt`,this.connectionType),
    this.connectionType===rC.RETRY&&this.lastStamp&&r.set(`recoverTs`,String(this.lastStamp)),
    Q.useParticipantListChunk&&(r.set(`partIdx`,String(Q.participantListChunkInitIndex)),
      Q.participantListChunkInitCount!==null&&r.set(`partCount`,String(Q.participantListChunkInitCount))),
    t&&(r.set(`compression`,`deflate-raw`), r.set(`ua`,navigator.userAgent)),
    this.peerId!==null&&r.set(`peerId`,String(this.peerId)),
    n.toString()}
```

`_connectWebSocket()` calls `this._buildUrl(this.endpoint, false)` — i.e. **for the
plain `ws2` WebSocket, `t=false`**, so `compression` and `ua` are **not** appended
(those two params are WebTransport-only in this code path). `_connectWebTransport()`
calls `_buildUrl(this.wtEndpoint, true)`.

So a WebSocket `ws2` URL query string looks like:
`?platform=<Q.platform>&appVersion=<Q.appVersion>&version=<Q.protocolVersion>&device=<Q.device>&capabilities=<fT.getFlags()>&clientType=<Q.clientType>&tgt=<start|accept|join|retry>[&recoverTs=<lastStamp>][&partIdx=…&partCount=…][&peerId=<peerId>]`

`fT.getFlags()` is a capability/feature-flag string builder — I located its call
sites (offsets 605447, 679253, 798944, 801159) but did not fully trace its
internals; treat its exact output as **not fully verified**, only its role
(one query param, computed once per URL build) is confirmed.

`rC` enum (offset ~371050): `START`,`ACCEPT`,`JOIN`,`RETRY` — these are exactly the
`tgt` values.

### 2c. First bytes on the wire

`_onMessage` (offset **619440**) special-cases a **bare text frame `"ping"`**
(not JSON) as a keepalive from the server and replies with a bare text frame
`"pong"` — see §6. Every other frame is `JSON.parse`d and dispatched by `.type`.

`_handleMessage(e)` (offset **619528-620500**):
```
switch(e.type){
 case`notification`:
   this._attachNotificationCallError(e),
   e.notification===`connection`
     ? ( this.connected=!0, this.transport.resetReconnectCount(), this.transport.setEndpoint(e.endpoint),
         e.peerId&&this.peerId!==e.peerId.id&&(this.peerId=e.peerId.id, this.transport.setPeerId(e.peerId.id)),
         this._stopWaitConnectionMessage(),
         this.conversationResolve
           ? this.conversationResolve(e)
           : ( this._logTransportStat(sC.RESTART), this._triggerEvent(iC.RECONNECT,e),
               e.conversation.topology && this._triggerEvent(iC.NOTIFICATION,{type:`notification`,notification:aC.TOPOLOGY_CHANGED,topology:e.conversation.topology}),
               this._resolvePendingRecordCommands(e) ),
         this.lastStamp && this._handleCachedMessages(),
         e.recoverMessages?.forEach(e=>{ e.notification===aC.ACCEPTED_CALL && e.peerId.id===this.peerId && e.peerId.type===`WEB_TRANSPORT` || this._handleMessage(e) }),
         this._handleCommandsQueue(this.websocketCommandsQueue) )
     : (!this.connected||!this.listenersReady) ? this.incomingCache.push(e) : this._triggerEvent(iC.NOTIFICATION,e);
   break;
 case`response`: this._handleCommandResponse(!0,e); break;
 case`error`: this._handleErrorMessage(e); break;
 default: /* log unknown_message */
}
e.stamp && (this.lastStamp=e.stamp, this.transport.setLastStamp(e.stamp))
```

So the **very first server→client message is `{type:"notification", notification:"connection", endpoint, peerId?, conversation:{...,topology}, recoverMessages?}`**. `"connection"` is compared as a **bare string literal**, not via the `aC` enum (confirmed: `aC` has no `CONNECTION` member). On first connect this resolves the pending `connect()` promise (`conversationResolve`); on a reconnect (`this.conversationResolve` already null) it instead fires an internal `RECONNECT` event, synthesizes a `TOPOLOGY_CHANGED` notification from `e.conversation.topology` if present, replays `e.recoverMessages` (skipping a duplicate self-originated `accepted-call` for the `WEB_TRANSPORT` peer type), and finally flushes anything that was queued on `websocketCommandsQueue` while the socket was down.

After the "connection" notification, for an **outgoing call started with `rC.START`** no explicit call-answer command is needed (the callee side does the accepting); for the **callee**, once `aC.ACCEPTED_CALL`/participant flow has established the transport, the local user's UI action triggers `signaling.acceptCall(mediaSettings)` → wire command `accept-call` (offset 612494: `async acceptCall(e){return this._send(sS.ACCEPT_CALL,{mediaSettings:e})}`), which flips the local call-state machine `PROCESSING`→`ACTIVE` (offset 687974, see §5).

Then, once participants are allocated and the transport topology is known (see §3/§4), media begins.

---

## 3. The DIRECT (1:1) topology path

Class `FC` (`class e extends SC{...}`, offset **472050-484950**) — I'm calling it
**DirectTransport**. One instance per direct (1:1) peer connection.

### 3a. Master/offerer determination

**Constructor** (offset **472050-473650**): `constructor(e,t,n,r,i,...)` where the
2nd positional arg `t` is stored as `this._isMaster=t`. If `_isMaster` is true, the
constructor **immediately and synchronously** (before `open()` is ever called):
```
this._mediaSource.addTrackToPeerConnection(this._pc,!1,!0), this._applySettings(),
this._createOffer(!1).catch(e=>{ this._state===lC.IDLE ? this._failedOnCreate=e : this.close(e) })
```
(offset ~473450). The non-master does nothing at construction time; it waits for
an incoming offer (see 3e).

**Where `isMaster` comes from — two distinct code paths:**

1. **Normal 1:1 call start** (offset **717600-717700**, method that wires up the
   participant-transport allocation right after the transport is created):
   ```
   let e = this._conversation.direction===jT.OUTGOING && !this._conversation.concurrent, t=this._participants;
   for (let n of Object.values(t))
     (n.state===zT.ACCEPTED||n.state===zT.CALLED) && this._allocateParticipantTransport(n.id,e)
   ```
   **i.e. `isMaster = (call direction is OUTGOING) && (not a "concurrent" multi-device call)`.
   The party that placed the call is the master/offerer; the callee is the non-master/answerer.**
   This is a purely **local** decision, made from the local `conversation.direction`
   field — it requires no round-trip to the server.

2. **Mid-call participant add** (offset **718550-718600**, inside `_onAddParticipant`):
   ```
   this._allocateParticipantTransport(r.id,!0)
   ```
   whoever executes the local "add participant" action is unconditionally the master
   toward that newly-added participant.

3. **Server-driven override on a topology switch to DIRECT** (offset **578400-579190**,
   method `_onTopologyChanged` on the TransportManager, triggered by the `topology-changed`
   notification, see §1b):
   ```
   let t=e.offerTo||[], n=e.offerToTypes||[], r=e.offerToDeviceIdxs||[],
       i = t.length&&n.length ? Z.composeParticipantId(t[0],n[0],r[0]) : null;
   ...
   let a=this._allocated[0];
   if(this._directTransport) this._directTransport.allowRestart();
   else { let e = i===a; this._directTransport=this._createDirectTransport(a,e) }
   ```
   Here the server's `topology-changed` payload can carry `offerTo`/`offerToTypes`/
   `offerToDeviceIdxs` arrays identifying which participant should be offered to;
   the client composes that into a participant id and compares it against the
   (single) allocated remote participant — if they match, **this client becomes
   master** for the new DirectTransport. This path only fires when a topology
   *change* notification arrives (e.g. falling back from SERVER to DIRECT, or a
   group call collapsing to 1:1); it is **not** how the initial master flag for a
   fresh 1:1 call is set (that's path 1 above — `_onTopologyChanged` only acts
   `if(e.topology!==this._topology)`).

`isMaster` is memoized once decided, offset **694524** (`_allocateParticipantTransport`):
```
_allocateParticipantTransport(e,t){this._transport&&(this._transport.getTopology()===uC.DIRECT&&
  (t=this._directTransportIsMaster??=t), this._transport.allocate(e,t))}
```
— confirming there is exactly one master flag per direct call, fixed the first time it's computed.

**Recovery/self-healing is also master-only** (see 3h): only the master ever
initiates an ICE restart or requests a topology fallback to SERVER on connection
failure. The non-master purely reacts to whatever the master (re-)sends.

### 3b. `sendSdp(participantId, sdp, extra)` — exact wire payload

Definition, offset **612370-612420**:
```
async sendSdp(e,t,n){
  let r=Object.assign({sdp:t},n);
  return this._send(sS.TRANSMIT_DATA, {participantId:e, data:r}, !0, TT)
}
```
`extra` (`n`) is built by the caller. The only call site that constructs it is
`_onSignalingStateChange` on DirectTransport, offset **479500-479700**:
```
_onSignalingStateChange(){
  ...
  let e={animojiVersion: Q.vmojiOptions.protocolVersion||1};
  switch(this._pc?.signalingState){
    case`have-local-offer`:
      let t=this._pc.localDescription;
      t ? this._signaling.sendSdp(this._participantId,t,e).catch(this.close.bind(this))
        : this.close(Error());
      break;
    case`have-remote-offer`:
      this._createAnswer().then(t=>this._signaling.sendSdp(this._participantId,t,e)).catch(this.close.bind(this));
      break;
  }
}
```
So **`extra` = `{animojiVersion: Q.vmojiOptions.protocolVersion || 1}`** and that
is the **only** extra field ever sent — it is a small integer (the "vmoji"/animoji
protocol version, default `1`), sent with *every* SDP (offer and answer alike),
not specific to master or non-master.

Full wire body of a `transmit-data` command carrying SDP (after `_send`'s own
enrichment, see below) is:
```
{
  "participantId": "<numeric id>",
  "participantType": "<type>",       // added by _send, see below
  "deviceIdx": <int>,                // added by _send only if present
  "data": { "sdp": <RTCSessionDescriptionInit {type, sdp}>, "animojiVersion": <int> }
}
```
wrapped in the outer envelope `{sequence, name:"transmit-data", params:{...above...}}`
(see §6 for the outer envelope).

The **3rd argument to `_send`** is `needResponse` (default `true` in `_send`'s own
signature, but `sendSdp` passes it explicitly as `!0`/true). The **4th argument**
is a **retry count**, not a data-channel selector: `sendSdp` passes `TT`, and
`TT=10` (offset **607674**, in the same statement as `wT=\`open\`,TT=10,...`).
This means: **an SDP `transmit-data` send will silently retry itself up to 10
times** if the underlying send is rejected (socket not open yet, timeout, etc.),
per the retry loop in `_sendRaw` (see §6). SDP is therefore the most
retried/robust of all outbound messages in this client.

### 3c. `sendCandidate(participantId, candidate)` — exact wire payload

Definition, offset **612180-612230**:
```
async sendCandidate(e,t){
  return this._send(sS.TRANSMIT_DATA, {participantId:e, data:{candidate:t}}, !1)
}
```
Only 3 arguments are passed: `needResponse=false`, and the 4th (retry count)
is **omitted → defaults to 0 (no retry)**. So candidate sends are fire-and-forget,
no ack expected, no auto-retry — unlike SDP sends.

`t` (the candidate value) is whatever `RTCPeerConnection.onicecandidate` handed
over — either a full `RTCIceCandidateInit`-shaped object (`{candidate, sdpMid,
sdpMLineIndex, ...}` — WebRTC's native shape, unmodified/un-enriched by this
code) or the literal `{candidate:""}` sentinel for end-of-candidates (see 3d).

**`participantType` and `deviceIdx` ARE present on the wire**, but they are
injected generically by `_send` itself for *every* command that carries a
`participantId`, not by `sendCandidate`/`sendSdp` individually. `_send`,
offset **617163-617220**:
```
async _send(e,t={},n=!0,r=0){
  if(t.participantId){
    let e=Z.decomposeParticipantId(t.participantId), n=Z.decomposeId(e.compositeUserId);
    t=Object.assign({},t,{participantId:n.id, participantType:n.type}),
    e.deviceIdx && (t.deviceIdx=e.deviceIdx)
  }
  return this._sendRaw(e,t,n,r)
}
```
i.e. every internal "participantId" is actually a **composite id** encoding
`{userId, type, deviceIdx}` (built by `Z.composeParticipantId`/`Z.composeUserId`,
offsets not fully traced — see caveat below); `_send` decomposes it right before
transmission and flattens it into three separate wire fields: `participantId`
(bare user id), `participantType`, and (only if truthy) `deviceIdx`. So:
**`sendCandidate`'s and `sendSdp`'s wire payloads both end up with
`{participantId, participantType, deviceIdx?, data:{...}}`** at the top level of
`params` — there is no separate `label` field anywhere in this code (no match
for a `label` field on transmit-data payloads was found).

I did **not** fully trace `Z.composeParticipantId`/`Z.decomposeParticipantId`/
`Z.decomposeId` to their literal bit-layout (they're defined via a pattern my
searches for `name(args){` literal text didn't match, likely due to different
minified parameter names per call site); treat the *existence and placement* of
`participantType`/`deviceIdx` on the wire as confirmed, but not their exact
string/number encoding.

### 3d. The empty end-of-candidates marker — `forwardEmptyIceCandidate`

`_handleIceCandidate` (the `RTCPeerConnection.onicecandidate` handler), offset
**482020-482100**:
```
async _handleIceCandidate(e){
  this._signaling.ready && (
    e.candidate
      ? ( this._debug.debug(`Local ice candidate`,...), await this._signaling.sendCandidate(this._participantId,e.candidate) )
      : ( Q.forwardEmptyIceCandidate &&
          ( this._debug.debug(`ICE gathering complete, forwarding empty candidate`,...),
            await this._signaling.sendCandidate(this._participantId,{candidate:``}) ) )
  )
}
```
So: **every non-null `onicecandidate` event is forwarded immediately** via
`sendCandidate`. When the browser signals end-of-gathering (`event.candidate ===
null`), the client sends the empty-string sentinel `sendCandidate(participantId,
{candidate:""})` **only if the global config flag `Q.forwardEmptyIceCandidate` is
true**. That flag **defaults to `false`** in the SDK's own parameter defaults
(offset **434061-435975**, the big `Y(Q,'_params',{...forceRelayPolicy:!1,...
forwardEmptyIceCandidate:!1})` default object) — so **web.max.ru must explicitly
opt in** to this behavior at SDK-init time for the empty marker to ever be sent
at all. I could not find where web.max.ru's own init call sets this (that call
site is presumably outside this bundle, in the app's own bootstrap code) — but
given the task's premise that the server does trickle candidates back in
production, it's a safe inference that this flag is turned on. **A Go
reimplementation must therefore always send `{candidate:""}` after local ICE
gathering completes, on both master and non-master, exactly like the real
client does** — this is symmetric in the client code; there is nothing here
that differentiates master vs. non-master for sending the marker.

The gate is `this._signaling.ready`, which is the *signaling socket's* `ready`
getter (offset **608560**, class `AT extends oS`):
```
get ready(){return !this.disposed && this.transport.readyState!==null}
```
`transport.readyState!==null` just means a `WebSocket`/transport object has been
constructed (i.e. `.connect()` was called) — it does **not** require the socket
to be `OPEN` yet. Practically this means `onicecandidate`/offer-creation can fire
and get **queued** (see §6) even before the "connection" notification has been
received; the queue is flushed once `websocketCommandsQueue` processing is
triggered (on socket open when already `OPEN`, and again explicitly when the
"connection" notification arrives, offset ~620280: `this._handleCommandsQueue(this.websocketCommandsQueue)`).
Because sends are FIFO-queued in `_sendRaw`/`_handleCommandsQueue` (push + shift,
never reordered), the offer (queued the instant `have-local-offer` fires) is
always queued and therefore sent **before** any of its own trickled candidates
generated afterward, on both roles.

### 3e. How incoming `transmit-data` is processed

The server relays the client's own `transmit-data` back out as a
**`transmitted-data`** notification (see §1b) to the DirectTransport class. Handler,
offset **479192-479692** (`_handleTransmittedData`):
```
_handleTransmittedData(e){
  let t=e.data, n=Z.getPeerIdString(e.peerId);
  Z.composeMessageId(e)===this._participantId && (
    t.candidate && t.candidate.candidate
      ? this._addIceCandidate(n,t.candidate).catch(this.close.bind(this))
      : t.sdp && ( this._remoteAnimojiVersion=t.animojiVersion||1,
                   this._setRemoteDescription(n,t.sdp).catch(this.close.bind(this)) )
  )
}
```
Key points:
- Messages are filtered by `Z.composeMessageId(e)===this._participantId` — i.e.
  each DirectTransport instance only reacts to `transmitted-data` addressed to
  the participant id it owns (protects against cross-talk in multi-transport
  scenarios).
- **Candidate vs SDP is distinguished purely by shape**: `t.candidate &&
  t.candidate.candidate` (a non-empty inner `.candidate` string) routes to ICE;
  otherwise, if `t.sdp` is present, it routes to SDP. **There is no `sdp.type`
  inspection anywhere in this dispatch** — the client does not need to know
  offer-vs-answer here because `setRemoteDescription` (below) accepts whatever
  `RTCSessionDescriptionInit` the browser's own WebRTC stack was given (the
  `type` field travels inside `t.sdp.type` as produced by `createOffer`/
  `createAnswer`, unmodified).
- **The client's own empty-candidate sentinel is effectively a no-op on
  receipt**: if `t.candidate = {candidate:""}`, the check `t.candidate.candidate`
  is falsy (empty string), so **neither branch fires** — this message is
  silently swallowed by the receiving DirectTransport. That sentinel is meant
  for the **server** (to signal "I'm done gathering, so you may relay/trickle
  your own now"), not to signal anything to the browser peer.
- `_remoteAnimojiVersion` is cached from `t.animojiVersion||1` right before
  setting the remote description.

**Remote-description / candidate ordering**, offset **480000-480870**
(`_setRemoteDescription`, `_setRemoteCandidates`, `_addIceCandidate`):
```
async _addIceCandidate(e,t){
  if(this._isOpen && (!this._remotePeerId||this._remotePeerId===e) && this._pc && this._pc.remoteDescription){
    await this._pc.addIceCandidate(new RTCIceCandidate(t))
  } else {
    // Cache remote ice candidate
    this._remoteCandidates[e]=this._remoteCandidates[e]||[], this._remoteCandidates[e].push(t)
  }
}
async _setRemoteCandidates(e){
  let t=this._remoteCandidates[e]; if(!t) return;
  this._remoteCandidates[e]=[];
  for(let n of t) try{ await this._addIceCandidate(e,n) }catch{}
}
async _setRemoteDescription(t,n){
  if(this._isOpen && (!this._remotePeerId||this._remotePeerId===t) && this._pc){
    if(this._lastRemoteSDP?.sdp===n.sdp) return;   // de-dup identical SDP
    this._lastRemoteSDP=n;
    n = e._patchRemoteDescription(n);              // codec-preference rewrite only, see below
    this._calcFingerprint(n.sdp);
    await this._pc.setRemoteDescription(n);
    await this._setRemoteCandidates(t);             // flush any candidates cached before the SDP arrived
    this._processAnimojiProtocolVersion(this._remoteAnimojiVersion);
  } else {
    this._remoteSDP[t]=n   // cache SDP if not yet open
  }
}
```
So: **any ICE candidate that arrives before `remoteDescription` is set (or
before the transport is `_isOpen`) is cached per-peer-id and replayed, in
arrival order, immediately after `setRemoteDescription` succeeds.** This is the
standard "cache candidates until SRD" pattern, applied uniformly to both roles.

**SDP is patched only for codec preference, never for ICE credentials or
candidate lines.** Two static methods, offset **487550-487650**:
```
static _patchLocalDescription(e){
  let t=!!mx.baseChromeVersion();
  return e.sdp=Z.patchLocalSDP(e.sdp, Q.preferH264&&mx.canPreferH264(), mx.isBrokenH264Decoder(), Q.preferVP9, t&&Q.audioNack), e
}
static _patchRemoteDescription(e){
  return e.sdp=Z.patchRemoteSDP(e.sdp, !1, !1, Q.preferVP9, mx.isBrokenVP9Encoder(), mx.isBrokenVP9Decoder()), e
}
```
`patchLocalSDP`/`patchRemoteSDP` take booleans that gate H264/VP9 preference and
audio NACK — **there is no ice-ufrag/ice-pwd rewriting, no candidate-line
stripping/filtering, and no offer/answer content inspection beyond codecs
anywhere in this client's SDP handling.** The ice-ufrag/pwd rewriting and
server-originated candidate trickling described in the task prompt must
therefore be entirely a **server-side** behavior of the OK Calls SFU acting as
an ICE-terminating relay in front of the "DIRECT" 1:1 media path — it is
invisible to (and not special-cased by) this client bundle. This strongly
suggests that, from the browser's `RTCPeerConnection` point of view, the
"remote peer" in a DIRECT call is actually the media-server's edge process
(which is why the server can rewrite ice-ufrag/pwd identically for both sides
and why it, not the other browser, is the one trickling candidates back).

`_createOffer`/`_createAnswer` (offset **485921-486700**) both:
`pc.createOffer()`/`pc.createAnswer()` → `_patchLocalDescription` → `calcFingerprint`
→ `pc.setLocalDescription(...)` → return the description (which then flows into
`sendSdp` from the `onsignalingstatechange` handler, per 3b).

### 3f. ICE config

`_createPeerConnection`, offset **476850-476960**:
```
_createPeerConnection(){
  let e=new RTCPeerConnection({
    iceServers: Q.iceServers,
    iceTransportPolicy: Q.forceRelayPolicy ? `relay` : `all`
  });
  return e.onicecandidate=this._handleIceCandidate.bind(this),
    e.ontrack=this._onAddTrack.bind(this),
    e.oniceconnectionstatechange=this._onIceConnectionStateChange.bind(this),
    e.onconnectionstatechange=this._onConnectionStateChange.bind(this),
    e.onsignalingstatechange=this._onSignalingStateChange.bind(this),
    ...
}
```
Confirmed exactly as the task anticipated: `iceTransportPolicy` is `"relay"` iff
`Q.forceRelayPolicy` is true, else `"all"`. `Q.iceServers`/`Q.forceRelayPolicy`
are populated as described in §2a (REST response fields `stun_server`/
`turn_server`/`p2p_forbidden`, defaulting to `[]`/`false` if absent, and
`forceRelayPolicy` can also be flipped by a public SDK setter).

### 3g. Signaling-state / renegotiation / glare handling

The **only** two `signalingState` cases handled are `have-local-offer` (send the
already-set local offer) and `have-remote-offer` (create+send an answer) — see
3b. **No other signalingState (`stable`, `have-local-pranswer`,
`have-remote-pranswer`, `closed`) triggers any action in
`_onSignalingStateChange`, and I found no explicit glare-handling logic**
(no rollback, no polite/impolite-peer pattern, no `perfect negotiation`-style
guard). The only reason glare is structurally avoided is the one-directional
master/non-master split from 3a: only the master ever calls `_createOffer`
(both for the initial offer, offset 473500, and for ICE restarts, offset
485830 — `_startIceRestart` only calls `_createOffer(!0)` if `this._isMaster`,
otherwise it just logs "Waiting for ice restart..." and starts a timeout).
Because the non-master never independently initiates an offer, two offers can
never cross in this implementation.

`_setRemoteDescription` includes an idempotency guard
(`this._lastRemoteSDP?.sdp===n.sdp) return;`) that no-ops on being handed the
same SDP twice (e.g. a duplicated/retried `transmit-data`), rather than trying
to detect/resolve a genuine glare condition.

### 3h. Reconnect / `recover`

**I found no call site anywhere in the bundle that sends `sS.RECOVER`
(`"recover"`).** A grep for `sS.RECOVER`, the bare identifier `RECOVER` outside
its enum definition, and the literal string `"recover"` all come back empty
(aside from the one enum-definition occurrence at offset 447375). **Reconnection
is instead handled entirely via the ws2 URL query string and a server-pushed
replay, not via an application-level "recover" command:**

1. On reconnect, `CT._buildUrl` (§2b) sets `tgt=retry` (from `rC.RETRY`) and, if
   `this.lastStamp` is non-zero, appends `recoverTs=<lastStamp>` — `lastStamp` is
   the `stamp` field off the **most recently received** message of any kind
   (`_handleMessage`'s trailing `e.stamp && (this.lastStamp=e.stamp, ...)`, offset
   ~620480).
2. The server's response to a retry connection is again a `{type:"notification",
   notification:"connection", ...}` message, this time additionally carrying
   `e.recoverMessages` — an array of notifications the client missed while
   disconnected, offset **620280-620320**:
   ```
   e.recoverMessages?.forEach(e=>{
     e.notification===aC.ACCEPTED_CALL && e.peerId.id===this.peerId && e.peerId.type===`WEB_TRANSPORT`
       || this._handleMessage(e)
   })
   ```
   (skips replaying a self-originated `accepted-call` for the client's own
   `WEB_TRANSPORT` peer-id/type, to avoid double-processing its own echo).
3. `this.transport.setLastStamp(e.stamp)` / `this.lastStamp` reset to `0` on an
   explicit `.close()` (offset ~603340, `CT.close`: `this.lastStamp=0`).

So: **"recover" as a wire command name is dead code in this client; the actual
recovery mechanism is `recoverTs` in the reconnect URL + `recoverMessages` in
the reconnect "connection" notification.** A Go client aiming for exact parity
should implement reconnect this way (URL param + replay), not by sending a
`recover` command over an existing socket.

Separately, **DirectTransport-level self-healing on ICE failure is master-only**
(offset 484800-484900, `_startReconnection`/`_requestTopologySwitch`):
```
_startReconnection(){
  this._reconnectionTimeout || this._iceRestartTimeout || (
    this._reconnectionTimeout = setTimeout(() => {
      this._reconnectionTimeout=null;
      this._neverConnected ? this._requestTopologySwitch() : this._startIceRestart()
    }, Q.transportConnectionWaitTime) )
}
_requestTopologySwitch(){
  this._isMaster && this._signaling.ready && this._signaling.switchTopology(uC.SERVER).catch(...)
}
_startIceRestart(){
  this._isMaster
    ? this._createOffer(!0).catch(this.close.bind(this))
    : /* non-master just logs "Waiting for ice restart..." */ ;
  this._iceRestartTimeout = setTimeout(() => { this._requestTopologySwitch() }, Q.iceRestartWaitTime)
}
```
i.e. on ICE `failed`/`disconnected`, after `Q.transportConnectionWaitTime` (default
`5000`ms, offset 434100ish) of no connection ever having been established, or
after `Q.iceRestartWaitTime` (default `20000`ms) of a restart not succeeding, **only
the master** sends `switch-topology` with `{topology:"SERVER", force:false}`
(via `switchTopology(e,t=!1){return this._send(sS.SWITCH_TOPOLOGY,{topology:e,force:t})}`,
offset 614672) to fall back from DIRECT to the SFU. The non-master takes no
independent recovery action of its own; it only reacts to whatever the master
does (a fresh offer on ICE-restart, or a `topology-changed` notification if the
master's `switch-topology` request succeeds).

---

## 4. The SERVER (SFU) topology path

Class offset ~540000-570000, I'm calling it **ServerTransport**.

### 4a. Capabilities object — every field, offset **593990-594860**

```
function t(){
  return {
    estimatedPerformanceIndex: iT.getEstimatedPerformanceIndex(),
    audioMix: true,
    consumerUpdate: true,
    producerNotificationDataChannelVersion: 8,
    producerCommandDataChannelVersion: 3,
    consumerScreenDataChannelVersion: 1,
    producerScreenDataChannelVersion: 1,
    asrDataChannelVersion: +!!Q.asrDataChannel,               // 0 or 1
    animojiDataChannelVersion: Q.vmoji ? Q.vmojiOptions.protocolVersion : 1,
    animojiBackendRender: !Q.vmojiOptions.renderingOptions.useFullClientRendering,
    onDemandTracks: true,
    unifiedPlan: true,
    singleSession: true,
    videoTracksCount: Q.videoTracksCount,                      // default 30
    red: true,
    audioShare: Q.audioShare,                                  // default false
    fastScreenShare: Q.fastScreenShare,                         // default false
    videoSuspend: Q.videoSuspend,                               // default false
    simulcast: Q.simulcast,                                     // default false
    simulcastNativeOrder: true,
    consumerFastScreenShare: Q.consumerFastScreenShare,         // default false
    consumerFastScreenShareQualityOnDemand: Q.consumerFastScreenShareQualityOnDemand, // default false
    transparentAudio: Q.transparentAudio                        // default false
  }
}
```
exposed as `uT.get()` (`uT=lT`, offset 595043). This is used in two places:
`hold(e){...capabilities: e ? undefined : uT.get() ...}` (i.e. capabilities are
sent when going *off* hold, omitted when going *onto* hold), and in
`_allocateConsumer()`.

### 4b. `allocate-consumer`

Sender, offset **612780-612830**:
```
async allocateConsumer(e,t){
  let n={capabilities:t};
  e && (n.description=e.sdp);
  return this._send(sS.ALLOCATE_CONSUMER,n)
}
```
Call site, offset **562190-562280** (`_allocateConsumer`, ServerTransport):
```
_allocateConsumer(){
  if(!this._signaling.ready) return;
  let e=uT.get();
  ...
  this._signaling.allocateConsumer(null,e).catch(...)
}
```
i.e. the client always calls it as `allocateConsumer(null, capabilities)` — the
first arg (a description whose `.sdp` would be forwarded) is **always `null`**
at this call site, so on the wire `allocate-consumer`'s `params` is simply
`{capabilities: {...the object in 4a...}}` (no `description` field sent by this
client in practice, even though the sender function supports one).

**The promise from `allocateConsumer(...)` is only `.catch()`-handled, never
`.then()`-handled** — the client does not synchronously consume a producer
offer from the direct response to `allocate-consumer`. Instead:

### 4c. `producer-updated` → `accept-producer`

`_onProducerUpdated`, offset **566173-566280**:
```
async _onProducerUpdated(e){
  this._producerSessionId && this._producerSessionId!==e.sessionId && this._reconnect(),
  Q.breakVideoPayloadTypes && ( this._signaling.requestTestMode(`breakVideoPayloadTypes`,null).catch(...) ),
  this._producerSessionId = e.sessionId,
  await this._acceptProducer(e.description, e.sessionId)
}
```
So the `producer-updated` notification's payload includes at least
**`{sessionId, description}`** (`description` being the producer/SFU's SDP
offer string). If `sessionId` changes from a previously-known one, the client
force-reconnects first (treats it as a fresh producer session).

`_acceptProducer(e,t)` (offset ~562700-563520) queues a second incoming offer if
one is already being processed (`_producerOfferIsProcessing` / `_producerNextOffer`
/ `_producerNextSessionId` — a simple 1-deep renegotiation queue, processed
recursively once the in-flight one finishes), then:
```
_processOffer(e,t){
  await pc.setRemoteDescription(e);                      // e = {type:'offer', sdp: patchRemoteSDP(...)}
  await this._simulcast.configureFromRemoteOffer(pc);
  await this._handleTracks();
  n = await pc.createAnswer();
  n.sdp = Z.patchLocalSDP(n.sdp, false, mx.isBrokenH264Decoder(), false);
  await pc.setLocalDescription(n);
  n.sdp = this._simulcast.finalizeAnswer(n.sdp);
  this._updateSSRCMap(e);
  await this._signaling.acceptProducer(n, Object.keys(this._ssrcMap), t);
}
```
`acceptProducer` sender, offset **612830-612870**:
```
async acceptProducer(e,t,n){
  let r={description:e.sdp, sessionId:n};
  t.length && (r.ssrcs=t);
  return this._send(sS.ACCEPT_PRODUCER,r)
}
```
So `accept-producer`'s wire `params` = `{description:<answer sdp string>,
sessionId:<the producer-updated's sessionId>, ssrcs?:<Object.keys(this._ssrcMap)>}`
— `ssrcs` is an **array of the local ssrc-map's keys** (the answer-side's own
ssrc bookkeeping, refreshed via `_updateSSRCMap(e)` right before sending; I did
not trace `_updateSSRCMap`'s internals byte-for-byte, but its output type here
is simply `Object.keys(...)`, i.e. an array of string keys), included only if
non-empty.

### 4d. Other ServerTransport notifications and `switch-topology`

Already listed under §1b's ServerTransport sub-switch: `realloc-con` →
`_reconnect()`, `audio-activity`/`speaker-changed`/`stalled-activity`/
`network-status` → local state signaling only (no outbound reply).

`switch-topology` (client→server) is sent from `switchTopology(e,t=!1){...
{topology:e, force:t}}` (offset 614672) — observed call site is the DIRECT-side
failure-recovery path in §3h (`topology: "SERVER"`, force:false`). I found no
symmetric client-initiated call requesting a switch *from* SERVER back to
DIRECT — the `_onTopologyChanged` handler (§3a) reacts to a server-pushed
`topology-changed` in either direction, but only the DIRECT→SERVER direction is
ever *requested* by this client in the code I found.

`CONSUMER_ANSWERED` (`consumer-answered`): as noted in §1b, unreferenced. My
best-supported explanation, given 4b/4c above, is that the initial producer
offer and every subsequent renegotiation both arrive uniformly via
`producer-updated`, so a separate "consumer answered" acknowledgment notification
was either superseded by that design or is consumed by a mechanism outside what
I could trace (e.g., purely as the generic `response` to `allocate-consumer`,
which — if it ever carries a `notification`-shaped body — would never hit this
notification-name switch at all, since `response` messages are routed by
`_handleCommandResponse`, not `_onSignalingNotification`).

---

## 5. State machine (compact)

Three layers, each independently tracked:

**A. ws2 socket layer (`CT`, offset ~603000-609000)** — implicit via
`transport.readyState`/`connectionType`/`reconnectCount`; drives `_buildUrl`'s
`tgt`/`recoverTs` and the "connection" notification flow. No named enum; states
are really just "not connected / connecting / open / retrying".

**B. Signaling-session layer (`AT`, `this.connected`/`this.listenersReady`)** —
`connected` flips true on the first "connection" notification (§2c) and stays
true until `dispose()`/`_terminate()` (offset ~623900, clears all queues/handlers
and rejects everything in flight).

**C. Per-transport connection state — `lC` enum** (offset ~464990, `lC=function(e){
return e.IDLE=`IDLE`,e.OPENED=`OPENED`,e.CONNECTING=`CONNECTING`,
e.RECONNECTING=`RECONNECTING`,e.CONNECTED=`CONNECTED`,e.CLOSED=`CLOSED`,
e.FAILED=`FAILED`,e}(lC||{})`) — used by both DirectTransport and ServerTransport:
`IDLE → OPENED` (on `.open()`) `→ CONNECTING` (peer-connection `connecting` /
`checking`) `→ CONNECTED` (`onconnectionstatechange==='connected'`, or the
`iceConnectionState` fallback for `connected`/`completed`) `→ RECONNECTING`
(on `failed`/`disconnected`, unless on hold or reconnection is prevented)
`→ CONNECTED` again, or eventually `→ CLOSED` (graceful) / `→ FAILED` (error).
DirectTransport additionally special-cases: master `_startIceRestart` on
`RECONNECTING` timeout, then `_requestTopologySwitch` (only master, §3h) if
that also times out.

**D. Top-level call/conversation state** — a small, non-enumerated set of
string literals I found being assigned to `this._state` on the outermost call
object (offsets scattered 681900-726300): **`IDLE` → `PROCESSING` → `ACTIVE`**,
with a side-state **`HELD`** (via `_holdLocally`, offset 726300: saves
`_previousState` then sets `HELD`, restorable) and a terminal **`CLOSE`** (offset
696300/697530, set together with `this._participantState=zT.HUNGUP` on hangup/
decline/remote-close). Concretely:
- `onJoin(...)` → `_state="PROCESSING"` (offset 681979) → on success,
  `_state="ACTIVE"` (offset 684608, guarded by a `t` success flag).
- Accepting an incoming call → `_state="PROCESSING"` (offset 687566) →
  `await signaling.acceptCall(mediaSettings)` (wire `accept-call`) →
  `_state="ACTIVE"`, `_participantState=zT.ACCEPTED` (offset 687974).
- Declining → `_state="PROCESSING"` (offset 691551) then presumably `CLOSE`
  (not re-extracted, but symmetric with hangup).
- Hangup / remote hangup / closed-conversation → `_state="CLOSE"`,
  `_participantState=zT.HUNGUP` (offsets 696301, 697532).
- Hold/unhold → `_state="HELD"` ⇄ restored previous state (offset 726300-726330).

Per-participant state — **`zT` enum** (offset ~631755): `CALLED`, `ACCEPTED`,
`REJECTED`, `HUNGUP`. Call **direction** — **`jT` enum** (offset ~630812):
`INCOMING`, `OUTGOING`, `JOINING`.

---

## 6. Anything surprising

1. **Ping/pong keepalive is a bare text frame, not JSON.** `_onMessage`, offset
   **619420-619450**:
   ```
   _onMessage(e){
     if(e.data===`ping`){
       this._statPings?.mark(...); this._markTransportStat(sC.FAILED_PINGS);
       $.onSignalingMessage(e.data);
       this.transport.readyState===WebSocket.OPEN && this.transport.send(`pong`).catch(...);
       return
     }
     try{ let t=JSON.parse(e.data); ... }catch...
   }
   ```
   Note the (probably-misleading) stat name `FAILED_PINGS` is marked on
   **every** ping received, not just failures — likely just a counter/duration
   marker misnamed from a template, not an actual failure signal; treat this as
   observed-but-possibly-mislabeled telemetry, not a functional flag.

2. **Every outbound command gets an auto-incrementing `sequence` number and a
   FIFO send queue**, offset **608560-608900** / **617600-618900**:
   - `sequence` starts at `1` (`Y(this,'sequence',1)`), incremented per `_send`
     call (`c=this.sequence++`).
   - Two queues: `websocketCommandsQueue` and `datachannelCommandsQueue`
     (`route:"producer"` vs `route:"websocket"`), chosen by `_isDataChannelCommand(e)`
     (offset 617620): only `UPDATE_DISPLAY_LAYOUT, REPORT_PERF_STAT,
     REPORT_SHARING_STAT, REQUEST_ASR, ENABLE_VIDEO_SUSPEND,
     ENABLE_VIDEO_SUSPEND_SUGGEST, REPORT_NETWORK_STAT, CHANGE_SIMULCAST` are
     ever routed over the WebRTC data channel (`producerCommandDataChannel`),
     and only when `producerCommandDataChannelEnabled` — **everything else,
     including all of `transmit-data`/`allocate-consumer`/`accept-producer`,
     always goes over the ws2 WebSocket.**
   - Each queued command object is `{sequence, name, route, statMarkName,
     params, responseTimer, needResponse, resolve, reject}`.
   - `_handleCommandsQueue` (offset 626149) `shift()`s them off in order and
     sends; if `needResponse`, arms a response timer (`_startResponseTimer`,
     `WAIT_RESPONSE_DELAY` — offset 608560, `static get WAIT_RESPONSE_DELAY(){
     return Q.waitResponseDelay}`, default `Q.waitResponseDelay=1e4` i.e.
     **10000ms**) and records it in `this.responseHandlers[sequence]`;
     otherwise it resolves the local promise immediately without waiting for
     any server ack at all.
   - **Retry-on-reject is a separate, per-call mechanism** built into
     `_sendRaw`'s Promise wrapper (offset 617800ish):
     ```
     let s=(t,n=!1)=>{ !r || n ? o(t) : (r--, i(u)) }
     ```
     i.e. if the 4th `_send` argument `r` (retry budget) is falsy, or the
     rejection carries a forced flag, reject for real; otherwise decrement `r`
     and literally resubmit the same message object `u` through the router
     again. **Only `sendSdp` (`r=TT=10`) and `changeMediaSettings` (`r=TT=10`)
     use this** among the commands I sampled; `sendCandidate`, `hangup`,
     `acceptCall`, etc. pass no 4th arg (default `r=0`, no retry).
   - `_handleCommandResponse(t,n)` (offset 623900ish): if the response's
     `sequence` isn't in `responseHandlers` at all, it's treated as **stale/
     unmatched**, and — interestingly — if it happens to carry a `.participants`
     array, the client **synthesizes `PARTICIPANT_ADDED` notifications** out of
     it (offset 623910-624040: `if(n.participants) for(e of n.participants)
     this._triggerEvent(iC.NOTIFICATION,{...n, notification:aC.PARTICIPANT_ADDED,
     type:"notification", participant:e})`) rather than dropping it — a
     graceful-degradation path for a response arriving after its handler was
     already cleaned up (e.g. after a timeout already fired). If the socket is
     still open when a timeout is hit, it hard-rejects "Response timeout";
     if the socket is **not** open, it instead **re-arms the same timer**
     (waits for the reconnect rather than failing), offset 624440ish.

3. **A dedicated glare-avoidance-via-queue exists on the SFU producer path**
   but not on the DIRECT path: `_acceptProducer`'s `_producerOfferIsProcessing`
   flag defers/queues a second incoming producer offer while the first is still
   being processed (§4c) — a renegotiation race guard that has no counterpart
   in DirectTransport (which relies purely on the master/non-master split to
   avoid ever generating two offers).

4. **`RECOVER` (wire `"recover"`) and `CONSUMER_ANSWERED` (wire
   `"consumer-answered"`) are both defined enum members with zero live call
   sites / zero live dispatch handlers found anywhere in this 1.24MB bundle.**
   Both are flagged above (§3h, §4d/§1b) with the best-supported alternative
   explanation for how their apparent purpose is actually achieved
   (`recoverTs` URL param + `recoverMessages` replay; `producer-updated` used
   uniformly for both the first offer and renegotiations).

5. **Recording commands get special "resolve on reconnect" treatment**:
   `_resolvePendingRecordCommands(e)` (offset ~608700, called only from inside
   the "connection" notification handler when reconnecting) walks any
   still-pending `RECORD_START`/`RECORD_STOP` response handlers and resolves or
   rejects them **based on the freshly-received conversation's `recordInfo`
   state**, rather than waiting for the original response that was lost with
   the old socket — but only if `Q.waitForRecordResponse` is enabled (default
   `false`).

6. **`_send`'s participantId enrichment is unconditional and generic** — *any*
   command whose `params` object has a truthy `participantId` gets it silently
   decomposed and re-expanded into `{participantId, participantType,
   deviceIdx?}` right before going on the wire (§3c). This applies identically
   to `transmit-data` (sdp/candidate), `remove-participant`, `pin-participant`,
   etc. — it's a single shared code path, not something special-cased per
   command.

## Open items / not found in this bundle (explicitly flagged, not guessed)

- Exact bit-layout of `Z.composeParticipantId`/`decomposeParticipantId`/
  `decomposeId`/`composeUserId`/`composeMessageId`/`getPeerIdString` — their
  call sites and effects are confirmed (§3c/§3e), but their literal
  implementations were not matched by my searches (likely due to differing
  minified parameter names at each definition site) and were not re-attempted
  further given time budget.
- `fT.getFlags()` (the `capabilities` **ws2 URL query parameter**, distinct
  from the SFU `capabilities` object in §4a) — call sites found (§2b) but
  internals not traced.
- Where web.max.ru's own bootstrap sets `Q.forwardEmptyIceCandidate` (and any
  other `Q._params` overrides) — that call is presumably in application code
  outside this particular bundle/file.
- The exact literal value/encoding of `Q.platform`, `Q.appVersion`,
  `Q.protocolVersion`, `Q.device`, `Q.clientType` as actually configured by
  web.max.ru (only the SDK's own generic defaults were found: `platform:"WEB"`,
  `clientType:"PORTAL"`, `device:"browser"`, offset 434070ish — these may be
  overridden by the host app before `connect()` is ever called).
- No explicit code was found that inspects or rewrites `a=ice-ufrag`/`a=ice-pwd`
  lines in any SDP, on either the DIRECT or SERVER path — consistent with that
  rewriting being purely server-side (§3e).
