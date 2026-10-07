// voice.go -- WebRTC SFU + embedded TURN + IRCd bridge for the
// "^channel" voice rooms.
//
// Architecture:
//
//   obbyworld client               obbyircd                  hosted-backend (this file)
//   ─────────────────                ────────                  ──────────────
//   TAGMSG ^vc @+obsidianirc/rtc=…   →                         (received via bridge)
//                                    ↓ voice.c module
//                                    ──── unix WS bridge ────► VoiceBridge
//                                                              ├─ VoiceRooms (SFU)
//                                                              └─ TURN server
//   ◄──── TAGMSG :server.name @+obsidianirc/rtc=… (back through the same bridge)
//
// All heavy lifting (TURN credentials, SDP munging, RTP forwarding)
// lives here.  The IRCd module is just a thin TAGMSG <-> JSON bridge.

package main

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/turn/v3"
	"github.com/pion/webrtc/v4"
)

/* =====================================================================
 * Config
 * ===================================================================== */

type VoiceConfig struct {
	// Public hostname / IP that clients reach the TURN server through.
	// Defaults to the request's Host header derived value at runtime;
	// can be forced via VOICE_PUBLIC_IP for deployments behind NAT.
	PublicIP string
	// UDP port for TURN.  3478 is the IANA-assigned TURN port.
	TurnPort int
	// HMAC secret used to derive time-limited TURN credentials per
	// authenticated user.  Required.
	TurnAuthSecret string
	// Unix-socket path for the IRCd <-> backend bridge.  Defaults to
	// /tmp/obbyirc-voice.sock; obbyircd's voice module reads the
	// same env var (VOICE_BRIDGE_SOCKET) to find us.
	BridgeSocket string
	// Hard cap on participants per voice room.  Above this, joins
	// fail with a "room_full" error.
	MaxRoomSize int
	// ICE/TURN realm for the embedded TURN server.
	Realm string
	// When true, skip starting the embedded TURN listener.  The SFU
	// still runs; clients are expected to receive TURN credentials
	// from an external source (e.g. the IRCd's voice::turn rewrite).
	DisableEmbeddedTurn bool
	// Ephemeral UDP port range pion gathers ICE candidates on.  Must
	// be published in the container's port spec for clients to reach
	// the SFU directly.
	WebRTCPortMin uint16
	WebRTCPortMax uint16
}

func loadVoiceConfig() VoiceConfig {
	cfg := VoiceConfig{
		PublicIP:       os.Getenv("VOICE_PUBLIC_IP"),
		BridgeSocket:   os.Getenv("VOICE_BRIDGE_SOCKET"),
		TurnAuthSecret: os.Getenv("VOICE_TURN_SECRET"),
		Realm:          os.Getenv("VOICE_TURN_REALM"),
		MaxRoomSize:    25,
	}
	if cfg.BridgeSocket == "" {
		cfg.BridgeSocket = "/tmp/obbyirc-voice.sock"
	}
	if cfg.Realm == "" {
		cfg.Realm = "obsidianirc"
	}
	cfg.TurnPort = 3478
	if v := os.Getenv("VOICE_TURN_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			cfg.TurnPort = p
		}
	}
	if v := os.Getenv("VOICE_MAX_ROOM"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			cfg.MaxRoomSize = p
		}
	}
	if b, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("VOICE_TURN_DISABLE_EMBEDDED"))); err == nil {
		cfg.DisableEmbeddedTurn = b
	}
	if v := os.Getenv("VOICE_WEBRTC_PORT_MIN"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			cfg.WebRTCPortMin = uint16(p)
		}
	}
	if v := os.Getenv("VOICE_WEBRTC_PORT_MAX"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			cfg.WebRTCPortMax = uint16(p)
		}
	}
	return cfg
}

/* =====================================================================
 * TURN credentials
 * ===================================================================== */

// TURN REST credentials per the long-lived-credentials draft:
// https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00
//
// username = "<expiry-unix>:<account>"
// password = base64(HMAC-SHA1(secret, username))
//
// The TURN server uses the same secret to validate the password,
// rejecting anything past the expiry.
type TurnCreds struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	URLs     []string `json:"urls"`
	TTL      int64    `json:"ttl"`
}

func mintTurnCreds(cfg VoiceConfig, account string, ttl time.Duration) TurnCreds {
	expiry := time.Now().Add(ttl).Unix()
	username := fmt.Sprintf("%d:%s", expiry, account)
	mac := hmac.New(sha1.New, []byte(cfg.TurnAuthSecret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	host := cfg.PublicIP
	if host == "" {
		host = "127.0.0.1"
	}
	urls := []string{
		fmt.Sprintf("turn:%s:%d?transport=udp", host, cfg.TurnPort),
		fmt.Sprintf("turn:%s:%d?transport=tcp", host, cfg.TurnPort),
	}
	return TurnCreds{
		Username: username,
		Password: password,
		URLs:     urls,
		TTL:      int64(ttl.Seconds()),
	}
}

// turnAuthHandler is pion/turn's RelayAuthHandler signature.  We
// recompute the expected HMAC for the supplied username; if the
// embedded expiry is past or the HMAC doesn't match, return false.
func turnAuthHandler(cfg VoiceConfig) turn.AuthHandler {
	return func(username, _realm string, _addr net.Addr) ([]byte, bool) {
		// username = "<expiry>:<account>"
		colon := strings.IndexByte(username, ':')
		if colon < 0 {
			return nil, false
		}
		expStr := username[:colon]
		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil || time.Now().Unix() > exp {
			return nil, false
		}
		mac := hmac.New(sha1.New, []byte(cfg.TurnAuthSecret))
		mac.Write([]byte(username))
		password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		// pion/turn expects the *long-term-credential key* which is
		// MD5(username:realm:password) per RFC 5389.  turn.GenerateAuthKey
		// computes that for us.
		return turn.GenerateAuthKey(username, cfg.Realm, password), true
	}
}

/* =====================================================================
 * TURN server lifecycle
 * ===================================================================== */

func startTurnServer(cfg VoiceConfig) (*turn.Server, error) {
	if cfg.TurnAuthSecret == "" {
		return nil, errors.New(
			"VOICE_TURN_SECRET must be set to enable TURN")
	}
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.TurnPort)
	publicIP := cfg.PublicIP
	if publicIP == "" {
		publicIP = "127.0.0.1"
	}
	relayGen := &turn.RelayAddressGeneratorStatic{
		RelayAddress: net.ParseIP(publicIP),
		Address:      "0.0.0.0",
	}

	srvCfg := turn.ServerConfig{
		Realm:       cfg.Realm,
		AuthHandler: turnAuthHandler(cfg),
	}

	// UDP listener -- only useful if the host's firewall actually
	// permits UDP on TurnPort.  We attempt to bind and skip silently
	// if it fails, so a TCP-only deployment still starts.
	udpConn, udpErr := net.ListenPacket("udp4", addr)
	if udpErr == nil {
		srvCfg.PacketConnConfigs = append(srvCfg.PacketConnConfigs,
			turn.PacketConnConfig{
				PacketConn:            udpConn,
				RelayAddressGenerator: relayGen,
			})
		log.Printf("voice: TURN UDP listening on %s", addr)
	} else {
		log.Printf("voice: TURN UDP %s: %v (continuing TCP-only)", addr, udpErr)
	}

	// TCP listener -- needed in firewall-restricted environments where
	// only TCP ports are open inbound.
	tcpLn, tcpErr := net.Listen("tcp4", addr)
	if tcpErr == nil {
		srvCfg.ListenerConfigs = append(srvCfg.ListenerConfigs,
			turn.ListenerConfig{
				Listener:              tcpLn,
				RelayAddressGenerator: relayGen,
			})
		log.Printf("voice: TURN TCP listening on %s", addr)
	} else {
		log.Printf("voice: TURN TCP %s: %v", addr, tcpErr)
	}

	if udpErr != nil && tcpErr != nil {
		return nil, fmt.Errorf("turn: neither UDP nor TCP could bind %s", addr)
	}

	srv, err := turn.NewServer(srvCfg)
	if err != nil {
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if tcpLn != nil {
			_ = tcpLn.Close()
		}
		return nil, fmt.Errorf("turn: new server: %w", err)
	}
	log.Printf("voice: TURN server up (public %s, realm %q)", publicIP, cfg.Realm)
	return srv, nil
}

/* =====================================================================
 * SFU: rooms + peers
 * ===================================================================== */

// signalEnvelope is the JSON shape carried inside the
// +obsidianirc/rtc message tag in both directions.
type signalEnvelope struct {
	Type string `json:"type"`

	// "join" / "leave"
	Channel string `json:"channel,omitempty"`

	// "offer" / "answer"
	SDP string `json:"sdp,omitempty"`

	// "ice"
	Candidate     string  `json:"cand,omitempty"`
	SDPMid        string  `json:"mid,omitempty"`
	SDPMLineIndex *uint16 `json:"mlineidx,omitempty"`

	// state broadcast: "mic" / "video" / "speaking" / "silent" /
	// "deaf" / "screen" / "hand". The envelope Type stays "presence"
	// when relayed so the recipient dispatches it through applyPresence;
	// the original semantic ("mic" / "hand" / ...) is carried on Kind.
	State string `json:"state,omitempty"`
	Kind  string `json:"kind,omitempty"`

	// Transient emoji reaction visible to everyone in the room.
	Emoji string `json:"emoji,omitempty"`

	// presence (server->everyone)
	Members []string `json:"members,omitempty"`
	Member  string   `json:"member,omitempty"`

	// turn credentials (server->one) -- sent in response to "join"
	TURN *TurnCreds `json:"turn,omitempty"`

	// human-readable error
	Error string `json:"error,omitempty"`

	// SDP chunking. CLIENT_TAG_SIZE_LIMIT in obbyircd is 8191 bytes
	// post-escape; a video offer/answer routinely exceeds that. The
	// client splits SDP into N pieces sharing an "id" and a sequential
	// "seq" with "total"; voice_bridge.go reassembles before dispatch.
	ChunkID string `json:"id,omitempty"`
	Seq     *int   `json:"seq,omitempty"`
	Total   *int   `json:"total,omitempty"`

	// Track-to-nick attribution hint. Pion's emitted SDP doesn't
	// always include a=msid for added-mid-session tracks (Firefox in
	// particular falls back to a browser-generated {uuid} stream id),
	// so the client can't always resolve which member a remote
	// audio/video/screen track belongs to. We ship an explicit map
	// alongside the server-pushed "offer".
	Tracks []TrackHint `json:"tracks,omitempty"`

	// Stream-channel ($-prefix) role bookkeeping.
	//
	// Mode is "voice" for ^-channels (everyone publishes) or "stream"
	// for $-channels (only streamers publish; viewers chat-only).
	// Sent on the "joined" reply so the client can configure its UI
	// before any media flows.
	Mode string `json:"mode,omitempty"`
	// Role: "streamer" | "viewer". Sent in `joined` for the joiner's
	// own role and in `role` envelopes for peers whose role changed.
	Role string `json:"role,omitempty"`
	// Snapshot of streamer nicks in the room, in join order. Sent in
	// `joined` so the client knows who is publishing right now.
	Streamers []string `json:"streamers,omitempty"`
	// Promote target nick (envelope Type "promote") -- streamer-only,
	// caps the room at 4 concurrent streamers. "demote" mirrors it.
	Target string `json:"target,omitempty"`
}

// TrackHint tells the receiving client which member + kind a given
// fanned-out track belongs to. trackID matches the value pion sets on
// the wire (which the browser may or may not honor as track.id);
// `mid` is the m-line identifier and is preserved across browsers,
// which makes it the most reliable resolver for attachInboundTrack.
type TrackHint struct {
	TrackID string `json:"track_id"`
	Mid     string `json:"mid,omitempty"`
	Member  string `json:"member"`
	Kind    string `json:"kind"`
}

type voiceRoom struct {
	name  string
	peers map[string]*voicePeer // keyed by nick
	mu    sync.RWMutex
	// "voice" for ^-channels, "stream" for $-channels. Set on creation
	// from the channel-name prefix and never changes for the room's
	// lifetime.
	mode string
	// In-process participants (see voice_local.go). Bot ghosts and any
	// future server-side audio consumer slot in here and bypass WebRTC.
	localPeers map[string]*voiceLocalPeer
}

// streamMaxStreamers caps how many co-streamers a $-channel can have at
// once. The host counts as one; promotions beyond this fail.
const streamMaxStreamers = 4

func roomModeFor(channel string) string {
	if strings.HasPrefix(channel, "$") {
		return "stream"
	}
	return "voice"
}

func (r *voiceRoom) snapshotMembers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.peers))
	for nick := range r.peers {
		out = append(out, nick)
	}
	return out
}

type voicePeer struct {
	nick string
	room *voiceRoom
	mgr  *voiceManager
	pc   *webrtc.PeerConnection
	mu   sync.Mutex
	// Set whenever a server-side track change couldn't be propagated
	// because the PC's signaling state wasn't stable. handleClientAnswer
	// drains it on next stable transition.
	pendingRenegotiate bool
	// One *TrackLocalStaticRTP per published track keyed by localID
	// ("<nick>-<kind>-<remoteTrackID>"). Two video tracks (camera +
	// screen share) from the same publisher each get their own slot.
	publishedTracks map[string]*webrtc.TrackLocalStaticRTP
	// Senders we've added to this peer's PC, keyed by the publisher's
	// localID; used to remove on leave / cleanup.
	subSenders map[string]*webrtc.RTPSender
	// "streamer" | "viewer". In "voice" rooms every peer is a streamer.
	// In "stream" rooms the first joiner is streamer, subsequent peers
	// are viewers until promoted by an existing streamer.
	role string
	// Server-side join time, used for deterministic auto-promotion when
	// every streamer leaves a $-channel.
	joinedAt time.Time
}

type voiceManager struct {
	cfg   VoiceConfig
	api   *webrtc.API
	mu    sync.RWMutex
	rooms map[string]*voiceRoom
	// Outgoing message channel back to the IRCd bridge.  All
	// signalEnvelopes that need to land at a client funnel through
	// here so the bridge can serialize -> JSON-tag -> TAGMSG.
	outbound func(target, payload string) error
	// Nicks that are expected to attach as local (in-process) participants
	// for a given channel. Populated by RegisterLocal; consulted by
	// handleJoin to skip PC creation when the IRC join arrives.
	localMu       sync.RWMutex
	localExpected map[string]map[string]bool
}

func newVoiceManager(cfg VoiceConfig) *voiceManager {
	return &voiceManager{
		cfg:   cfg,
		api:   newWebrtcAPI(cfg),
		rooms: map[string]*voiceRoom{},
	}
}

// Server-side PeerConnection only needs STUN; TURN relay is for the
// *client* side and is delivered via the "joined" envelope's `turn`
// field (mintTurnCreds).  Including TURN here without credentials
// causes pion to reject NewPeerConnection.
func (m *voiceManager) peerConnectionConfig() webrtc.Configuration {
	return webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	}
}

// newWebrtcAPI constructs a *webrtc.API with NAT1To1 + ephemeral-port
// settings so server-side PeerConnections advertise reachable host
// candidates when running behind container NAT.  Without these, the
// SFU only emits container-internal IPs and Google-STUN-derived srflx
// candidates pointing at unmapped ephemeral ports, and ICE never
// converges from outside the host.
func newWebrtcAPI(cfg VoiceConfig) *webrtc.API {
	se := webrtc.SettingEngine{}
	if cfg.PublicIP != "" {
		se.SetNAT1To1IPs([]string{cfg.PublicIP}, webrtc.ICECandidateTypeHost)
	}
	if cfg.WebRTCPortMin > 0 && cfg.WebRTCPortMax >= cfg.WebRTCPortMin {
		if err := se.SetEphemeralUDPPortRange(cfg.WebRTCPortMin, cfg.WebRTCPortMax); err != nil {
			log.Printf("voice: SetEphemeralUDPPortRange(%d,%d): %v",
				cfg.WebRTCPortMin, cfg.WebRTCPortMax, err)
		}
	}
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		log.Printf("voice: RegisterDefaultCodecs: %v", err)
	}
	return webrtc.NewAPI(webrtc.WithSettingEngine(se), webrtc.WithMediaEngine(m))
}

func (m *voiceManager) getOrCreateRoom(name string) *voiceRoom {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rooms[name]; ok {
		return r
	}
	r := &voiceRoom{
		name:  name,
		peers: map[string]*voicePeer{},
		mode:  roomModeFor(name),
	}
	m.rooms[name] = r
	return r
}

// streamersUnsafe returns the room's current streamers in join order.
// Caller holds room.mu.
func (r *voiceRoom) streamersUnsafe() []*voicePeer {
	out := make([]*voicePeer, 0, len(r.peers))
	for _, p := range r.peers {
		if p.role == "streamer" {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].joinedAt.Before(out[j].joinedAt)
	})
	return out
}

func streamerNicks(peers []*voicePeer) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.nick)
	}
	return out
}

func (m *voiceManager) reapEmpty(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rooms[name]; ok && len(r.peers) == 0 && len(r.localPeers) == 0 {
		delete(m.rooms, name)
	}
}

// handleJoin allocates a peer, opens a PeerConnection on the server
// side, and replies with a "joined" envelope plus TURN creds.
func (m *voiceManager) handleJoin(nick, channel, account string) {
	if !strings.HasPrefix(channel, "^") && !strings.HasPrefix(channel, "$") {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "not a voice or stream channel"})
		return
	}
	if m.isLocalExpected(channel, nick) {
		// In-process participant; the LocalPeer is created via
		// RegisterLocal, not via signaling. Don't allocate a PC.
		log.Printf("voice: %s is a local participant in %s; skip PC", nick, channel)
		return
	}
	room := m.getOrCreateRoom(channel)
	room.mu.Lock()
	if len(room.peers) >= m.cfg.MaxRoomSize {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{Type: "error", Error: "room_full"})
		return
	}
	if _, dup := room.peers[nick]; dup {
		// Idempotent: re-issue a fresh PC if a stale one still exists.
		room.peers[nick].close()
	}
	pc, err := m.api.NewPeerConnection(m.peerConnectionConfig())
	if err != nil {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{
			Type: "error", Error: "pc_alloc: " + err.Error(),
		})
		return
	}
	peer := &voicePeer{
		nick:       nick,
		room:       room,
		mgr:        m,
		pc:         pc,
		subSenders: map[string]*webrtc.RTPSender{},
		joinedAt:   time.Now(),
	}
	// Role assignment by room mode.
	//   voice (^):  every peer publishes -> all "streamer".
	//   stream ($): only the first joiner streams; everyone else is a
	//               viewer until promoted by an existing streamer.
	if room.mode == "stream" {
		peer.role = "viewer"
		if len(room.streamersUnsafe()) == 0 {
			peer.role = "streamer"
		}
	} else {
		peer.role = "streamer"
	}
	room.peers[nick] = peer
	members := make([]string, 0, len(room.peers)+len(room.localPeers))
	for n := range room.peers {
		if n == nick {
			continue
		}
		members = append(members, n)
	}
	for n := range room.localPeers {
		members = append(members, n)
	}
	streamers := streamerNicks(room.streamersUnsafe())
	room.mu.Unlock()

	// Subscribe to existing peers' tracks (so this new peer hears
	// them once their PC negotiation completes).
	room.mu.RLock()
	for _, other := range room.peers {
		if other.nick == nick {
			continue
		}
		if err := peer.subscribeTo(other); err != nil {
			log.Printf("voice: subscribe %s -> %s: %v",
				nick, other.nick, err)
		}
	}
	// Also subscribe to in-process local peers' tracks so the very
	// first packet they send (e.g. Orca's TTS reply) arrives on a
	// track that's already in this peer's initial offer -- no
	// mid-stream renegotiation, no chopped-off first 200 ms.
	localPeers := make([]*voiceLocalPeer, 0, len(room.localPeers))
	for _, lp := range room.localPeers {
		localPeers = append(localPeers, lp)
	}
	room.mu.RUnlock()
	for _, lp := range localPeers {
		lp.mu.Lock()
		audioTrack := lp.audio
		videoTrack := lp.video
		lp.mu.Unlock()
		for _, track := range []*webrtc.TrackLocalStaticRTP{audioTrack, videoTrack} {
			if track == nil {
				continue
			}
			s, err := pc.AddTrack(track)
			if err != nil {
				log.Printf("voice: subscribe %s -> local %s: %v",
					nick, lp.nick, err)
				continue
			}
			peer.mu.Lock()
			if peer.subSenders == nil {
				peer.subSenders = map[string]*webrtc.RTPSender{}
			}
			peer.subSenders[track.ID()] = s
			peer.mu.Unlock()
		}
	}
	// Local peers broadcast mic-on at registration time, which is
	// BEFORE any client is in the room. New joiners would therefore
	// see them as muted in the UI. Send mic-on DIRECTLY to the new
	// joiner (not broadcast) so it arrives in order AFTER the joined
	// envelope -- broadcasts can race with onJoined, which rebuilds
	// the members map from blank and clobbers any prior state.
	for _, lp := range localPeers {
		m.send(nick, signalEnvelope{
			Type:    "presence",
			Member:  lp.nick,
			State:   "on",
			Kind:    "mic",
			Channel: channel,
		})
	}

	// Hook ICE candidate emission so we relay them back to the client.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		j := c.ToJSON()
		idx := j.SDPMLineIndex
		m.send(nick, signalEnvelope{
			Type:          "ice",
			Candidate:     j.Candidate,
			SDPMid:        firstStr(j.SDPMid),
			SDPMLineIndex: idx,
		})
	})

	// When the client publishes (audio / video), latch onto the
	// inbound track and fan it out.
	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		go peer.fanOutTrack(remote)
	})

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed ||
			s == webrtc.PeerConnectionStateClosed ||
			s == webrtc.PeerConnectionStateDisconnected {
			m.handleLeave(nick, channel)
		}
	})

	turn := mintTurnCreds(m.cfg, account, 6*time.Hour)
	log.Printf("voice: sending joined to %s in %s members=%v", nick, channel, members)
	m.send(nick, signalEnvelope{
		Type:      "joined",
		Channel:   channel,
		Members:   members,
		TURN:      &turn,
		Tracks:    peer.trackHints(),
		Mode:      room.mode,
		Role:      peer.role,
		Streamers: streamers,
	})

	// Tell every other peer that someone joined (presence broadcast,
	// not media-bearing). Role rides along so viewers' clients can lay
	// out new arrivals correctly without an extra round-trip.
	m.broadcast(channel, nick, signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   "joined",
		Channel: channel,
		Role:    peer.role,
	})
}

// subscribeTo adds an RTPSender for each track `other` is publishing
// to *this* peer's PeerConnection, so this peer receives `other`'s
// media.  Caller holds room.mu.RLock OR is in a path where
// concurrent modification of `other.publishedX` is impossible.
func (p *voicePeer) subscribeTo(other *voicePeer) error {
	other.mu.Lock()
	defer other.mu.Unlock()
	for id, track := range other.publishedTracks {
		s, err := p.pc.AddTrack(track)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.subSenders[id] = s
		p.mu.Unlock()
	}
	return nil
}

// fanOutTrack reads RTP packets off the inbound track and writes them
// into the local fan-out track so all other peers' senders receive
// them.  The local fan-out track is created lazily on first packet.
func (p *voicePeer) fanOutTrack(remote *webrtc.TrackRemote) {
	// Stream-channel viewers are chat-only -- they can't push media
	// to the room. If a viewer's client tries (via a misbehaving build
	// or browser quirk), drop the inbound track silently rather than
	// fan it out to other peers.
	p.mu.Lock()
	role := p.role
	p.mu.Unlock()
	if p.room != nil && p.room.mode == "stream" && role != "streamer" {
		log.Printf("voice: dropping track from viewer %s in $%s",
			p.nick, p.room.name)
		return
	}
	kind := remote.Kind().String()
	codec := remote.Codec()
	// Use the remote track's id as a uniqueness suffix so a publisher
	// who fans out multiple tracks of the same kind (e.g. camera +
	// screen share, both kind="video") doesn't collide on a single
	// "<nick>-<kind>" identifier. The hint map sent to clients still
	// keys by track id, so attribution stays correct.
	//
	// Strip non-alphanumeric characters from the suffix: Firefox's
	// getDisplayMedia hands us a "{uuid}" with curly braces and dashes,
	// and embedding that verbatim in the SDP a=msid line we push to
	// the viewer trips Firefox into ignoring our msid and substituting
	// a fresh browser-generated stream id (so attachInboundTrack on
	// the viewer can't resolve the track to a member, drops it, and
	// the screen never renders). An ASCII-clean suffix sidesteps all
	// of that.
	rawSuffix := remote.ID()
	clean := make([]byte, 0, len(rawSuffix))
	for i := 0; i < len(rawSuffix); i++ {
		c := rawSuffix[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			clean = append(clean, c)
		}
	}
	if len(clean) == 0 {
		clean = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	localID := fmt.Sprintf("%s-%s-%s", p.nick, kind, string(clean))
	local, err := webrtc.NewTrackLocalStaticRTP(
		codec.RTPCodecCapability,
		localID,
		p.nick,
	)
	if err != nil {
		log.Printf("voice: fanout new track %s: %v", kind, err)
		return
	}
	log.Printf("voice: fanout %s kind=%s local_id=%s remote_id=%s codec=%s",
		p.nick, kind, localID, remote.ID(), codec.MimeType)
	p.mu.Lock()
	if p.publishedTracks == nil {
		p.publishedTracks = map[string]*webrtc.TrackLocalStaticRTP{}
	}
	p.publishedTracks[localID] = local
	p.mu.Unlock()

	// Subscribe each existing peer to this new track and re-negotiate
	// so the client side learns about the new RTPSender. Without the
	// renegotiate, AddTrack on the server side leaves the client's
	// view of the PC out of sync and the new audio/video/screen
	// stream never reaches them.
	p.room.mu.RLock()
	others := make([]*voicePeer, 0, len(p.room.peers))
	for _, other := range p.room.peers {
		if other.nick == p.nick {
			continue
		}
		s, addErr := other.pc.AddTrack(local)
		if addErr != nil {
			log.Printf("voice: AddTrack(%s) -> %s FAILED: %v",
				localID, other.nick, addErr)
			continue
		}
		log.Printf("voice: AddTrack(%s) -> %s ok", localID, other.nick)
		// Forward viewer-initiated keyframe requests (PLI/FIR) back
		// to the publisher. Without this, when a viewer's decoder
		// resyncs after packet loss it has no way to ask the
		// upstream encoder for a fresh keyframe; the screen tile
		// stays gray. RTPSender.Read returns RTCP packets the viewer
		// emitted for this sender's SSRC.
		if remote.Kind() == webrtc.RTPCodecTypeVideo {
			pubPC := p.pc
			ssrc := uint32(remote.SSRC())
			go func() {
				buf := make([]byte, 1500)
				for {
					n, _, err := s.Read(buf)
					if err != nil {
						return
					}
					pkts, err := rtcp.Unmarshal(buf[:n])
					if err != nil {
						continue
					}
					forwarded := false
					for _, pkt := range pkts {
						switch pkt.(type) {
						case *rtcp.PictureLossIndication,
							*rtcp.FullIntraRequest:
							forwarded = true
						}
					}
					if forwarded {
						_ = pubPC.WriteRTCP([]rtcp.Packet{
							&rtcp.PictureLossIndication{MediaSSRC: ssrc},
						})
					}
				}
			}()
		}
		other.mu.Lock()
		// Key by the unique localID so camera+screen (both kind=video)
		// from the same publisher each get their own slot.
		other.subSenders[localID] = s
		other.mu.Unlock()
		others = append(others, other)
	}
	p.room.mu.RUnlock()
	for _, other := range others {
		if p.mgr != nil {
			p.mgr.renegotiateFor(other)
		}
	}

	// Periodically nudge the publisher for a fresh keyframe.
	//
	// Background: a static screen-share emits no IDR / keyframes for
	// long stretches because the encoder skips unchanged content. Any
	// receiver that joins (or recovers from packet loss) is stuck with
	// no decodable frame -- their <video> tile shows a blank/gray fill
	// even though our SFU is forwarding the RTP stream. Camera shares
	// usually self-correct because the encoder's GOP interval triggers
	// regular keyframes regardless of motion.
	//
	// Sending a PictureLossIndication via the upstream RTCP channel
	// forces pion to forward a keyframe request to the publisher; the
	// publisher's encoder responds with an IDR and viewers finally
	// have something to render. We do this only for video tracks, on
	// a 2-second tick. The goroutine exits when the remote track does.
	if remote.Kind() == webrtc.RTPCodecTypeVideo {
		sendPLI := func() error {
			return p.pc.WriteRTCP([]rtcp.Packet{
				&rtcp.PictureLossIndication{
					MediaSSRC: uint32(remote.SSRC()),
				},
			})
		}
		// Kick an immediate PLI so the first viewer doesn't have to
		// wait up to one tick interval for a decodable frame.
		_ = sendPLI()
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for range t.C {
				if err := sendPLI(); err != nil {
					return
				}
			}
		}()
	}

	// Pump RTP.
	buf := make([]byte, 1500)
	for {
		n, _, readErr := remote.Read(buf)
		if readErr != nil {
			return
		}
		if _, writeErr := local.Write(buf[:n]); writeErr != nil {
			if errors.Is(writeErr, webrtc.ErrConnectionClosed) {
				return
			}
		}
		if p.room != nil {
			p.room.notifyLocalPeers(p.nick, kind, buf[:n])
		}
	}
}

func (p *voicePeer) close() {
	if p.pc != nil {
		_ = p.pc.Close()
	}
}

func (m *voiceManager) handleLeave(nick, channel string) {
	m.mu.RLock()
	room, ok := m.rooms[channel]
	m.mu.RUnlock()
	if !ok {
		return
	}
	room.mu.Lock()
	peer, ok := room.peers[nick]
	if !ok {
		room.mu.Unlock()
		return
	}
	delete(room.peers, nick)
	// Detach this peer's published tracks from everyone else's PC
	// so they stop reading/sending.
	for _, other := range room.peers {
		other.mu.Lock()
		for key, sender := range other.subSenders {
			if track := sender.Track(); track != nil && track.StreamID() == nick {
				_ = other.pc.RemoveTrack(sender)
				delete(other.subSenders, key)
			}
		}
		other.mu.Unlock()
	}
	empty := len(room.peers) == 0
	// Stream-channel: if every streamer just left, hand the role to
	// the longest-tenured remaining viewer so the channel doesn't
	// silently brick. Returning the promoted nick lets us broadcast
	// the role transition outside the lock.
	var promoted *voicePeer
	if !empty && room.mode == "stream" &&
		peer.role == "streamer" &&
		len(room.streamersUnsafe()) == 0 {
		var oldest *voicePeer
		for _, p := range room.peers {
			if oldest == nil || p.joinedAt.Before(oldest.joinedAt) {
				oldest = p
			}
		}
		if oldest != nil {
			oldest.role = "streamer"
			promoted = oldest
		}
	}
	room.mu.Unlock()

	peer.close()

	m.broadcast(channel, nick, signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   "left",
		Channel: channel,
	})

	if promoted != nil {
		m.broadcast(channel, "", signalEnvelope{
			Type:    "role",
			Member:  promoted.nick,
			Role:    "streamer",
			Channel: channel,
		})
	}

	if empty {
		m.reapEmpty(channel)
	}
}

func (m *voiceManager) handleOffer(nick, channel, sdp string) {
	room, peer := m.lookup(nick, channel)
	if peer == nil {
		m.send(nick, signalEnvelope{Type: "error", Error: "not_in_room"})
		return
	}
	_ = room
	if err := peer.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: sdp,
	}); err != nil {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "set_remote: " + err.Error()})
		return
	}
	answer, err := peer.pc.CreateAnswer(nil)
	if err != nil {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "create_answer: " + err.Error()})
		return
	}
	if err := peer.pc.SetLocalDescription(answer); err != nil {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "set_local: " + err.Error()})
		return
	}
	m.send(nick, signalEnvelope{
		Type:   "answer",
		SDP:    answer.SDP,
		Tracks: peer.trackHints(),
	})

	// If the peer has more server-side senders than fit in the
	// answer they just received (e.g. they joined a room where two
	// other peers already had camera + screen on, but their initial
	// offer only carried offerToReceiveAudio/Video which yields a
	// single recvonly slot per kind), pion's answer can only describe
	// matching m-lines and drops the rest. Push a follow-up server-
	// initiated offer so the client picks up the orphaned senders.
	if peer.hasUnnegotiatedSenders() {
		go func() {
			// Tiny delay so the client finishes applying our answer
			// before we slam another offer at it.
			time.Sleep(50 * time.Millisecond)
			m.renegotiateFor(peer)
		}()
	}
}

// handleClientAnswer applies an answer the client produced in response
// to a server-initiated offer (e.g. after we AddTrack'd a new peer's
// audio/video onto this peer's PC and pushed an offer with renegotiateFor).
func (m *voiceManager) handleClientAnswer(nick, channel, sdp string) {
	_, peer := m.lookup(nick, channel)
	if peer == nil {
		log.Printf("voice: handleClientAnswer unknown peer %s/%s", nick, channel)
		return
	}
	if err := peer.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: sdp,
	}); err != nil {
		log.Printf("voice: handleClientAnswer set_remote (%s): %v", nick, err)
		return
	}
	log.Printf("voice: handleClientAnswer ok %s sdpLen=%d", nick, len(sdp))
	// PC is back to stable -- drain any renegotiations that piled up.
	peer.mu.Lock()
	pending := peer.pendingRenegotiate
	peer.pendingRenegotiate = false
	peer.mu.Unlock()
	if pending {
		m.renegotiateFor(peer)
	}
}

// renegotiateFor pushes a fresh server-side offer to the given peer.
// Used whenever we mutate the peer's RTPSender set (e.g. fanOutTrack
// adds a new sender) so the client's mirrored PC state catches up.
//
// If the peer's PC isn't in stable signaling state (i.e. an earlier
// offer/answer exchange is still in flight), we mark pendingRenegotiate
// and bail; handleClientAnswer drains the flag once the PC returns to
// stable. This avoids the "have-local-offer->SetLocal(offer)" pion
// error when track changes pile up faster than clients can answer.
func (m *voiceManager) renegotiateFor(peer *voicePeer) {
	if peer.pc.SignalingState() != webrtc.SignalingStateStable {
		peer.mu.Lock()
		peer.pendingRenegotiate = true
		peer.mu.Unlock()
		return
	}
	offer, err := peer.pc.CreateOffer(nil)
	if err != nil {
		log.Printf("voice: renegotiate %s create_offer: %v", peer.nick, err)
		return
	}
	if err := peer.pc.SetLocalDescription(offer); err != nil {
		log.Printf("voice: renegotiate %s set_local: %v", peer.nick, err)
		return
	}
	hints := peer.trackHints()
	// Diagnostic: count video m-lines in the offer + log msid lines so
	// we can tell whether fanOutTrack actually pushed a screen video
	// transceiver to this peer's PC.
	mLineCount := 0
	msidLines := []string{}
	for _, ln := range strings.Split(offer.SDP, "\r\n") {
		if strings.HasPrefix(ln, "m=video") {
			mLineCount++
		}
		if strings.HasPrefix(ln, "a=msid:") {
			msidLines = append(msidLines, ln)
		}
	}
	log.Printf("voice: renegotiate %s videoMLines=%d hints=%d msids=%v",
		peer.nick, mLineCount, len(hints), msidLines)
	m.send(peer.nick, signalEnvelope{
		Type:   "offer",
		SDP:    offer.SDP,
		Tracks: hints,
	})
}

// hasUnnegotiatedSenders reports whether the peer's PC has any
// outgoing track whose transceiver hasn't been included in a
// completed offer/answer yet -- pion leaves Mid() empty until the
// transceiver appears in an applied SDP. After the initial join
// handshake we use this to decide whether to push a follow-up offer
// so late joiners pick up senders that didn't fit in the first
// recvonly slot of their original offer.
func (p *voicePeer) hasUnnegotiatedSenders() bool {
	for _, t := range p.pc.GetTransceivers() {
		s := t.Sender()
		if s == nil {
			continue
		}
		if s.Track() == nil {
			continue
		}
		if t.Mid() == "" {
			return true
		}
	}
	return false
}

// trackHints reports which fanned-out tracks are currently subscribed
// to this peer's PC. The client uses these as a side-channel to map
// inbound RTPReceiver tracks to publisher nicks even when the browser
// fails to honor pion's a=msid (Firefox in particular substitutes a
// random {uuid} for tracks added mid-session).
func (p *voicePeer) trackHints() []TrackHint {
	// Walk transceivers (not the subSenders map) so we can capture the
	// transceiver's Mid() -- Firefox preserves Mid on the receiving
	// side even when it discards or rewrites msid/track-id.
	out := []TrackHint{}
	for _, t := range p.pc.GetTransceivers() {
		s := t.Sender()
		if s == nil {
			continue
		}
		track := s.Track()
		if track == nil {
			continue
		}
		// Every fanned-out track carries its publisher's nick as the stream ID.
		out = append(out, TrackHint{
			TrackID: track.ID(),
			Mid:     t.Mid(),
			Member:  track.StreamID(),
			Kind:    track.Kind().String(),
		})
	}
	return out
}

func (m *voiceManager) handleICE(nick, channel string, env signalEnvelope) {
	_, peer := m.lookup(nick, channel)
	if peer == nil {
		return
	}
	cand := webrtc.ICECandidateInit{Candidate: env.Candidate}
	if env.SDPMid != "" {
		mid := env.SDPMid
		cand.SDPMid = &mid
	}
	if env.SDPMLineIndex != nil {
		cand.SDPMLineIndex = env.SDPMLineIndex
	}
	_ = peer.pc.AddICECandidate(cand)
}

// handleReaction broadcasts a transient emoji to the room. Reactions
// don't accumulate state; the receiving clients animate them and
// forget. We rebroadcast under type="react" (rather than presence)
// so the client can route them through onReaction without colliding
// with persistent presence state.
func (m *voiceManager) handleReaction(nick, channel string, env signalEnvelope) {
	if env.Emoji == "" {
		return
	}
	_, peer := m.lookup(nick, channel)
	if peer == nil {
		return
	}
	m.broadcast(channel, nick, signalEnvelope{
		Type:    "react",
		Member:  nick,
		Emoji:   env.Emoji,
		Channel: channel,
	})
}

// handlePromote: an existing streamer in a $-channel asks to promote
// `target` to streamer. Hard cap of streamMaxStreamers concurrent
// streamers; over the cap or unauthorized requests reflect an "error"
// envelope back to the requester. On success we broadcast a "role"
// envelope so every client (including viewers) can update its UI.
func (m *voiceManager) handlePromote(nick, channel string, env signalEnvelope) {
	target := strings.TrimSpace(env.Target)
	if target == "" {
		return
	}
	room, peer := m.lookup(nick, channel)
	if room == nil || peer == nil {
		return
	}
	if room.mode != "stream" {
		return
	}
	room.mu.Lock()
	if peer.role != "streamer" {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{Type: "error",
			Error: "only streamers can promote"})
		return
	}
	tp, ok := room.peers[target]
	if !ok || tp.role == "streamer" {
		room.mu.Unlock()
		return
	}
	if len(room.streamersUnsafe()) >= streamMaxStreamers {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{Type: "error",
			Error: fmt.Sprintf("max %d streamers", streamMaxStreamers)})
		return
	}
	tp.role = "streamer"
	room.mu.Unlock()
	m.broadcast(channel, "", signalEnvelope{
		Type:    "role",
		Member:  target,
		Role:    "streamer",
		Channel: channel,
	})
}

// handleDemote: a streamer can demote themselves OR another streamer
// back to viewer. The host (oldest streamer) can demote anyone; others
// can only demote themselves. We don't auto-promote here -- demotion
// shrinks the streamer list cleanly.
func (m *voiceManager) handleDemote(nick, channel string, env signalEnvelope) {
	target := strings.TrimSpace(env.Target)
	if target == "" {
		target = nick
	}
	room, peer := m.lookup(nick, channel)
	if room == nil || peer == nil {
		return
	}
	if room.mode != "stream" {
		return
	}
	room.mu.Lock()
	tp, ok := room.peers[target]
	if !ok || tp.role != "streamer" {
		room.mu.Unlock()
		return
	}
	streamers := room.streamersUnsafe()
	host := ""
	if len(streamers) > 0 {
		host = streamers[0].nick
	}
	if target != nick && nick != host {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{Type: "error",
			Error: "only the host can demote others"})
		return
	}
	tp.role = "viewer"
	// If the demoted peer was the host and others remain, the next
	// oldest streamer becomes the implicit host (no explicit role
	// change needed -- streamersUnsafe returns join order).
	room.mu.Unlock()
	m.broadcast(channel, "", signalEnvelope{
		Type:    "role",
		Member:  target,
		Role:    "viewer",
		Channel: channel,
	})
}

func (m *voiceManager) handleState(nick, channel string, env signalEnvelope) {
	// State (mute/cam/speaking/hand/etc) is presence -- rebroadcast
	// to everyone in the room. We forward env.Type as Kind so the
	// recipient can tell which specific state changed (mic vs video
	// vs hand etc.); the envelope Type itself stays "presence" so
	// onSignal dispatches to applyPresence on the client.
	_, peer := m.lookup(nick, channel)
	if peer == nil {
		return
	}
	m.broadcast(channel, "", signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   env.State,
		Kind:    env.Type,
		Channel: channel,
	})
}

func (m *voiceManager) lookup(nick, channel string) (*voiceRoom, *voicePeer) {
	m.mu.RLock()
	room, ok := m.rooms[channel]
	m.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	room.mu.RLock()
	peer := room.peers[nick]
	room.mu.RUnlock()
	return room, peer
}

func (m *voiceManager) send(target string, env signalEnvelope) {
	if m.outbound == nil {
		return
	}
	// Chunk SDP-bearing envelopes (offer / answer) so the IRCd's
	// TAGMSG line stays under MAXTAGSIZE=8192 after the JSON+IRC-tag
	// escape roundtrip. CR/LF in raw SDP go 1 -> 3 on the wire so the
	// safe raw-byte ceiling is well under 3000; we use 2000 to leave
	// headroom for the wrapper JSON ("type", "id", "seq", "total",
	// optional "tracks" hints) and any future field additions without
	// having to revisit this constant.
	if (env.Type == "offer" || env.Type == "answer") &&
		len(env.SDP) > sdpChunkRawLimit {
		m.sendChunked(target, env)
		return
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return
	}
	if err := m.outbound(target, string(payload)); err != nil {
		log.Printf("voice: outbound to %s: %v", target, err)
	}
}

const sdpChunkRawLimit = 2000

// sendChunked splits an oversized SDP into N envelopes, each carrying
// a slice of the SDP plus shared id and sequential seq/total. The
// receiving client reassembles via SignalEnvelope.id before applying
// the offer/answer. Track hints ride with chunk 0 only -- they're a
// small map and resending them on every chunk would just inflate the
// other chunks for no benefit.
func (m *voiceManager) sendChunked(target string, env signalEnvelope) {
	full := env.SDP
	id := chunkID()
	total := (len(full) + sdpChunkRawLimit - 1) / sdpChunkRawLimit
	for seq := 0; seq < total; seq++ {
		start := seq * sdpChunkRawLimit
		end := start + sdpChunkRawLimit
		if end > len(full) {
			end = len(full)
		}
		seqVal := seq
		totalVal := total
		chunk := signalEnvelope{
			Type:    env.Type,
			SDP:     full[start:end],
			ChunkID: id,
			Seq:     &seqVal,
			Total:   &totalVal,
		}
		// Keep track-attribution hints with chunk 0 -- the first chunk
		// is enough for the client to learn the mapping before the
		// reassembled offer/answer is applied.
		if seq == 0 {
			chunk.Tracks = env.Tracks
		}
		payload, err := json.Marshal(chunk)
		if err != nil {
			return
		}
		if err := m.outbound(target, string(payload)); err != nil {
			log.Printf("voice: outbound chunk %d/%d to %s: %v",
				seq+1, total, target, err)
			return
		}
	}
}

// chunkID returns a short random identifier shared across chunks of
// one logical envelope so the client can group them in its inbound
// reassembly buffer.
func chunkID() string {
	var b [6]byte
	_, _ = cryptorand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// broadcast sends to everyone in `channel` except optional excludeNick.
// `excludeNick` of "" sends to every member.  We deliberately address
// the channel rather than enumerating recipients here because the
// IRCd is the natural broadcaster -- it already has the channel
// membership and can fan TAGMSG out cheaply.
func (m *voiceManager) broadcast(channel, _excludeNick string, env signalEnvelope) {
	if m.outbound == nil {
		return
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return
	}
	_ = m.outbound(channel, string(payload))
}

func firstStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
