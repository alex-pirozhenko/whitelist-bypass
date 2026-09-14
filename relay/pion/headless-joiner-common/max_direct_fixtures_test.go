package joiner

// Fallback embedded fixtures copied verbatim from .direct-spec/caps/ (secrets redacted).
const (
	fixtureAnswerSDP = "v=0\r\n" +
		"o=- 3540960990225823726 2 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=group:BUNDLE 0 1\r\n" +
		"a=extmap-allow-mixed\r\n" +
		"a=msid-semantic: WMS e1933346-3ba4-4281-8b1f-8958ebdf6fc9\r\n" +
		"m=audio 9 UDP/TLS/RTP/SAVPF 63 111\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=rtpmap:63 red/48000/2\r\n" +
		"a=rtcp-fb:63 rrtr\r\n" +
		"a=fmtp:63 111/111\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=rtcp-fb:111 rrtr\r\n" +
		"a=rtcp-fb:111 nack\r\n" +
		"a=rtcp-fb:111 nack pli\r\n" +
		"a=rtcp-fb:111 transport-cc\r\n" +
		"a=fmtp:111 minptime=10;useinbandfec=1\r\n" +
		"a=sendrecv\r\n" +
		"a=rtcp:9 IN IP4 0.0.0.0\r\n" +
		"a=ice-ufrag:qUHcEQEVpn6UloG\r\n" +
		"a=ice-pwd:PrIJwXsfD1cCd1evfmAwHEYOq\r\n" +
		"a=ice-options:trickle\r\n" +
		"a=fingerprint:sha-256 A3:72:A7:B3:FB:40:DF:31:5B:4F:8B:7C:C9:B1:4D:C9:BF:98:64:AC:1E:60:21:3B:09:D5:5F:65:8B:76:CC:33\r\n" +
		"a=setup:passive\r\n" +
		"a=mid:0\r\n" +
		"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n" +
		"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" +
		"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" +
		"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
		"a=msid:e1933346-3ba4-4281-8b1f-8958ebdf6fc9 42da4f23-f8b1-435d-b584-724e19f711eb\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtcp-rsize\r\n" +
		"a=rtcp-xr:rcvr-rtt=all\r\n" +
		"a=ssrc:832415449 cname:1cnoAYK5zbNKuYQl\r\n" +
		"a=candidate:468136283 1 udp 658217562 155.212.192.213 43210 typ host generation 0\r\n" +
		"a=candidate:109246529 1 tcp 281532720 155.212.192.213 7684 typ host tcptype passive generation 0\r\n" +
		"m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103 104 107 108 109 114 115 116 117 39 40 45 46 118 119 120\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=rtpmap:96 VP8/90000\r\n" +
		"a=rtcp-fb:96 rrtr\r\n" +
		"a=rtcp-fb:96 goog-remb\r\n" +
		"a=rtcp-fb:96 transport-cc\r\n" +
		"a=rtcp-fb:96 ccm fir\r\n" +
		"a=rtcp-fb:96 nack\r\n" +
		"a=rtcp-fb:96 nack pli\r\n" +
		"a=rtpmap:97 rtx/90000\r\n" +
		"a=rtcp-fb:97 rrtr\r\n" +
		"a=fmtp:97 apt=96\r\n" +
		"a=rtpmap:102 H264/90000\r\n" +
		"a=rtcp-fb:102 rrtr\r\n" +
		"a=rtcp-fb:102 goog-remb\r\n" +
		"a=rtcp-fb:102 transport-cc\r\n" +
		"a=rtcp-fb:102 ccm fir\r\n" +
		"a=rtcp-fb:102 nack\r\n" +
		"a=rtcp-fb:102 nack pli\r\n" +
		"a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:103 rtx/90000\r\n" +
		"a=rtcp-fb:103 rrtr\r\n" +
		"a=fmtp:103 apt=102\r\n" +
		"a=rtpmap:104 H264/90000\r\n" +
		"a=rtcp-fb:104 rrtr\r\n" +
		"a=rtcp-fb:104 goog-remb\r\n" +
		"a=rtcp-fb:104 transport-cc\r\n" +
		"a=rtcp-fb:104 ccm fir\r\n" +
		"a=rtcp-fb:104 nack\r\n" +
		"a=rtcp-fb:104 nack pli\r\n" +
		"a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:107 rtx/90000\r\n" +
		"a=rtcp-fb:107 rrtr\r\n" +
		"a=fmtp:107 apt=104\r\n" +
		"a=rtpmap:108 H264/90000\r\n" +
		"a=rtcp-fb:108 rrtr\r\n" +
		"a=rtcp-fb:108 goog-remb\r\n" +
		"a=rtcp-fb:108 transport-cc\r\n" +
		"a=rtcp-fb:108 ccm fir\r\n" +
		"a=rtcp-fb:108 nack\r\n" +
		"a=rtcp-fb:108 nack pli\r\n" +
		"a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:109 rtx/90000\r\n" +
		"a=rtcp-fb:109 rrtr\r\n" +
		"a=fmtp:109 apt=108\r\n" +
		"a=rtpmap:114 H264/90000\r\n" +
		"a=rtcp-fb:114 rrtr\r\n" +
		"a=rtcp-fb:114 goog-remb\r\n" +
		"a=rtcp-fb:114 transport-cc\r\n" +
		"a=rtcp-fb:114 ccm fir\r\n" +
		"a=rtcp-fb:114 nack\r\n" +
		"a=rtcp-fb:114 nack pli\r\n" +
		"a=fmtp:114 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:115 rtx/90000\r\n" +
		"a=rtcp-fb:115 rrtr\r\n" +
		"a=fmtp:115 apt=114\r\n" +
		"a=rtpmap:116 H264/90000\r\n" +
		"a=rtcp-fb:116 rrtr\r\n" +
		"a=rtcp-fb:116 goog-remb\r\n" +
		"a=rtcp-fb:116 transport-cc\r\n" +
		"a=rtcp-fb:116 ccm fir\r\n" +
		"a=rtcp-fb:116 nack\r\n" +
		"a=rtcp-fb:116 nack pli\r\n" +
		"a=fmtp:116 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:117 rtx/90000\r\n" +
		"a=rtcp-fb:117 rrtr\r\n" +
		"a=fmtp:117 apt=116\r\n" +
		"a=rtpmap:39 H264/90000\r\n" +
		"a=rtcp-fb:39 rrtr\r\n" +
		"a=rtcp-fb:39 goog-remb\r\n" +
		"a=rtcp-fb:39 transport-cc\r\n" +
		"a=rtcp-fb:39 ccm fir\r\n" +
		"a=rtcp-fb:39 nack\r\n" +
		"a=rtcp-fb:39 nack pli\r\n" +
		"a=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:40 rtx/90000\r\n" +
		"a=rtcp-fb:40 rrtr\r\n" +
		"a=fmtp:40 apt=39\r\n" +
		"a=rtpmap:45 AV1/90000\r\n" +
		"a=rtcp-fb:45 rrtr\r\n" +
		"a=rtcp-fb:45 goog-remb\r\n" +
		"a=rtcp-fb:45 transport-cc\r\n" +
		"a=rtcp-fb:45 ccm fir\r\n" +
		"a=rtcp-fb:45 nack\r\n" +
		"a=rtcp-fb:45 nack pli\r\n" +
		"a=fmtp:45 level-idx=5;profile=0;tier=0\r\n" +
		"a=rtpmap:46 rtx/90000\r\n" +
		"a=rtcp-fb:46 rrtr\r\n" +
		"a=fmtp:46 apt=45\r\n" +
		"a=rtpmap:118 red/90000\r\n" +
		"a=rtcp-fb:118 rrtr\r\n" +
		"a=rtpmap:119 rtx/90000\r\n" +
		"a=rtcp-fb:119 rrtr\r\n" +
		"a=fmtp:119 apt=118\r\n" +
		"a=rtpmap:120 ulpfec/90000\r\n" +
		"a=rtcp-fb:120 rrtr\r\n" +
		"a=sendrecv\r\n" +
		"a=rtcp:9 IN IP4 0.0.0.0\r\n" +
		"a=ice-ufrag:qUHcEQEVpn6UloG\r\n" +
		"a=ice-pwd:PrIJwXsfD1cCd1evfmAwHEYOq\r\n" +
		"a=ice-options:trickle\r\n" +
		"a=fingerprint:sha-256 A3:72:A7:B3:FB:40:DF:31:5B:4F:8B:7C:C9:B1:4D:C9:BF:98:64:AC:1E:60:21:3B:09:D5:5F:65:8B:76:CC:33\r\n" +
		"a=setup:passive\r\n" +
		"a=mid:1\r\n" +
		"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n" +
		"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" +
		"a=extmap:13 urn:3gpp:video-orientation\r\n" +
		"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" +
		"a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n" +
		"a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n" +
		"a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n" +
		"a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n" +
		"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
		"a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n" +
		"a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n" +
		"a=msid:e1933346-3ba4-4281-8b1f-8958ebdf6fc9 0c1188ad-5db7-44e9-9f90-54528727fb54\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtcp-rsize\r\n" +
		"a=rtcp-xr:rcvr-rtt=all\r\n" +
		"a=ssrc-group:FID 1284737994 630181327\r\n" +
		"a=ssrc:1284737994 cname:1cnoAYK5zbNKuYQl\r\n" +
		"a=ssrc:630181327 cname:1cnoAYK5zbNKuYQl\r\n" +
		"a=candidate:468136283 1 udp 658217562 155.212.192.213 43210 typ host generation 0\r\n" +
		"a=candidate:109246529 1 tcp 281532720 155.212.192.213 7684 typ host tcptype passive generation 0\r\n"

	fixtureOfferSDP = "v=0\r\n" +
		"o=- 1242738193250137522 2 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=group:BUNDLE 0 1\r\n" +
		"a=extmap-allow-mixed\r\n" +
		"a=msid-semantic: WMS 16cdacd5-9ffe-47f1-8061-9c3951819135\r\n" +
		"m=audio 9 UDP/TLS/RTP/SAVPF 63 111\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=rtpmap:63 red/48000/2\r\n" +
		"a=rtcp-fb:63 rrtr\r\n" +
		"a=fmtp:63 111/111\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=rtcp-fb:111 rrtr\r\n" +
		"a=rtcp-fb:111 nack\r\n" +
		"a=rtcp-fb:111 nack pli\r\n" +
		"a=rtcp-fb:111 transport-cc\r\n" +
		"a=fmtp:111 minptime=10;useinbandfec=1\r\n" +
		"a=sendrecv\r\n" +
		"a=rtcp:9 IN IP4 0.0.0.0\r\n" +
		"a=ice-ufrag:qUHcEQEVpn6UloG\r\n" +
		"a=ice-pwd:PrIJwXsfD1cCd1evfmAwHEYOq\r\n" +
		"a=ice-options:trickle\r\n" +
		"a=fingerprint:sha-256 A3:72:A7:B3:FB:40:DF:31:5B:4F:8B:7C:C9:B1:4D:C9:BF:98:64:AC:1E:60:21:3B:09:D5:5F:65:8B:76:CC:33\r\n" +
		"a=setup:passive\r\n" +
		"a=mid:0\r\n" +
		"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n" +
		"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" +
		"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" +
		"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
		"a=msid:16cdacd5-9ffe-47f1-8061-9c3951819135 cf1f42d5-5358-436f-be53-173cf2769d25\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtcp-rsize\r\n" +
		"a=rtcp-xr:rcvr-rtt=all\r\n" +
		"a=ssrc:3447994390 cname:vrkjejePxdFoceYS\r\n" +
		"a=ssrc:3447994390 msid:16cdacd5-9ffe-47f1-8061-9c3951819135 cf1f42d5-5358-436f-be53-173cf2769d25\r\n" +
		"m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103 104 107 108 109 114 115 116 117 39 40 45 46 118 119 120\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=rtpmap:96 VP8/90000\r\n" +
		"a=rtcp-fb:96 rrtr\r\n" +
		"a=rtcp-fb:96 goog-remb\r\n" +
		"a=rtcp-fb:96 transport-cc\r\n" +
		"a=rtcp-fb:96 ccm fir\r\n" +
		"a=rtcp-fb:96 nack\r\n" +
		"a=rtcp-fb:96 nack pli\r\n" +
		"a=rtpmap:97 rtx/90000\r\n" +
		"a=rtcp-fb:97 rrtr\r\n" +
		"a=fmtp:97 apt=96\r\n" +
		"a=rtpmap:102 H264/90000\r\n" +
		"a=rtcp-fb:102 rrtr\r\n" +
		"a=rtcp-fb:102 goog-remb\r\n" +
		"a=rtcp-fb:102 transport-cc\r\n" +
		"a=rtcp-fb:102 ccm fir\r\n" +
		"a=rtcp-fb:102 nack\r\n" +
		"a=rtcp-fb:102 nack pli\r\n" +
		"a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:103 rtx/90000\r\n" +
		"a=rtcp-fb:103 rrtr\r\n" +
		"a=fmtp:103 apt=102\r\n" +
		"a=rtpmap:104 H264/90000\r\n" +
		"a=rtcp-fb:104 rrtr\r\n" +
		"a=rtcp-fb:104 goog-remb\r\n" +
		"a=rtcp-fb:104 transport-cc\r\n" +
		"a=rtcp-fb:104 ccm fir\r\n" +
		"a=rtcp-fb:104 nack\r\n" +
		"a=rtcp-fb:104 nack pli\r\n" +
		"a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:107 rtx/90000\r\n" +
		"a=rtcp-fb:107 rrtr\r\n" +
		"a=fmtp:107 apt=104\r\n" +
		"a=rtpmap:108 H264/90000\r\n" +
		"a=rtcp-fb:108 rrtr\r\n" +
		"a=rtcp-fb:108 goog-remb\r\n" +
		"a=rtcp-fb:108 transport-cc\r\n" +
		"a=rtcp-fb:108 ccm fir\r\n" +
		"a=rtcp-fb:108 nack\r\n" +
		"a=rtcp-fb:108 nack pli\r\n" +
		"a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:109 rtx/90000\r\n" +
		"a=rtcp-fb:109 rrtr\r\n" +
		"a=fmtp:109 apt=108\r\n" +
		"a=rtpmap:114 H264/90000\r\n" +
		"a=rtcp-fb:114 rrtr\r\n" +
		"a=rtcp-fb:114 goog-remb\r\n" +
		"a=rtcp-fb:114 transport-cc\r\n" +
		"a=rtcp-fb:114 ccm fir\r\n" +
		"a=rtcp-fb:114 nack\r\n" +
		"a=rtcp-fb:114 nack pli\r\n" +
		"a=fmtp:114 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:115 rtx/90000\r\n" +
		"a=rtcp-fb:115 rrtr\r\n" +
		"a=fmtp:115 apt=114\r\n" +
		"a=rtpmap:116 H264/90000\r\n" +
		"a=rtcp-fb:116 rrtr\r\n" +
		"a=rtcp-fb:116 goog-remb\r\n" +
		"a=rtcp-fb:116 transport-cc\r\n" +
		"a=rtcp-fb:116 ccm fir\r\n" +
		"a=rtcp-fb:116 nack\r\n" +
		"a=rtcp-fb:116 nack pli\r\n" +
		"a=fmtp:116 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:117 rtx/90000\r\n" +
		"a=rtcp-fb:117 rrtr\r\n" +
		"a=fmtp:117 apt=116\r\n" +
		"a=rtpmap:39 H264/90000\r\n" +
		"a=rtcp-fb:39 rrtr\r\n" +
		"a=rtcp-fb:39 goog-remb\r\n" +
		"a=rtcp-fb:39 transport-cc\r\n" +
		"a=rtcp-fb:39 ccm fir\r\n" +
		"a=rtcp-fb:39 nack\r\n" +
		"a=rtcp-fb:39 nack pli\r\n" +
		"a=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d001f;sps-pps-idr-in-keyframe=1\r\n" +
		"a=rtpmap:40 rtx/90000\r\n" +
		"a=rtcp-fb:40 rrtr\r\n" +
		"a=fmtp:40 apt=39\r\n" +
		"a=rtpmap:45 AV1/90000\r\n" +
		"a=rtcp-fb:45 rrtr\r\n" +
		"a=rtcp-fb:45 goog-remb\r\n" +
		"a=rtcp-fb:45 transport-cc\r\n" +
		"a=rtcp-fb:45 ccm fir\r\n" +
		"a=rtcp-fb:45 nack\r\n" +
		"a=rtcp-fb:45 nack pli\r\n" +
		"a=fmtp:45 level-idx=5;profile=0;tier=0\r\n" +
		"a=rtpmap:46 rtx/90000\r\n" +
		"a=rtcp-fb:46 rrtr\r\n" +
		"a=fmtp:46 apt=45\r\n" +
		"a=rtpmap:118 red/90000\r\n" +
		"a=rtcp-fb:118 rrtr\r\n" +
		"a=rtpmap:119 rtx/90000\r\n" +
		"a=rtcp-fb:119 rrtr\r\n" +
		"a=fmtp:119 apt=118\r\n" +
		"a=rtpmap:120 ulpfec/90000\r\n" +
		"a=rtcp-fb:120 rrtr\r\n" +
		"a=sendrecv\r\n" +
		"a=rtcp:9 IN IP4 0.0.0.0\r\n" +
		"a=ice-ufrag:qUHcEQEVpn6UloG\r\n" +
		"a=ice-pwd:PrIJwXsfD1cCd1evfmAwHEYOq\r\n" +
		"a=ice-options:trickle\r\n" +
		"a=fingerprint:sha-256 A3:72:A7:B3:FB:40:DF:31:5B:4F:8B:7C:C9:B1:4D:C9:BF:98:64:AC:1E:60:21:3B:09:D5:5F:65:8B:76:CC:33\r\n" +
		"a=setup:passive\r\n" +
		"a=mid:1\r\n" +
		"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n" +
		"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" +
		"a=extmap:13 urn:3gpp:video-orientation\r\n" +
		"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" +
		"a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n" +
		"a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n" +
		"a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n" +
		"a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n" +
		"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
		"a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n" +
		"a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n" +
		"a=msid:16cdacd5-9ffe-47f1-8061-9c3951819135 6f159d42-d64a-4311-ad01-8bda4f07a393\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtcp-rsize\r\n" +
		"a=rtcp-xr:rcvr-rtt=all\r\n" +
		"a=ssrc-group:FID 255391952 1587831529\r\n" +
		"a=ssrc:255391952 cname:vrkjejePxdFoceYS\r\n" +
		"a=ssrc:255391952 msid:16cdacd5-9ffe-47f1-8061-9c3951819135 6f159d42-d64a-4311-ad01-8bda4f07a393\r\n" +
		"a=ssrc:1587831529 cname:vrkjejePxdFoceYS\r\n" +
		"a=ssrc:1587831529 msid:16cdacd5-9ffe-47f1-8061-9c3951819135 6f159d42-d64a-4311-ad01-8bda4f07a393\r\n"
)
