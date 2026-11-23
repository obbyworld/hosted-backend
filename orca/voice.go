package orca

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"backend/ai"
)

// VoiceConfig captures the env-driven setup for Orca's voice subsystem.
type VoiceConfig struct {
	Channels      []string      // ORCA_VOICE_CHANNELS
	WakeOnly      bool          // ORCA_VOICE_WAKE_ONLY=true to require a wake word every turn
	UtteranceMax  time.Duration // safety cap on a single utterance
	MirrorChannel string        // text channel for transcript mirror (auto from ORCA_CHANNELS)
}

func loadVoiceConfig(o *Orca) VoiceConfig {
	return VoiceConfig{
		Channels:      splitCSV(os.Getenv("ORCA_VOICE_CHANNELS")),
		WakeOnly:      strings.EqualFold(os.Getenv("ORCA_VOICE_WAKE_ONLY"), "true"),
		UtteranceMax:  30 * time.Second,
		MirrorChannel: o.pickVoiceMirrorChannel(),
	}
}

// voiceSubsystem owns the audio loop for one Orca instance across all
// configured voice channels.
type voiceSubsystem struct {
	o      *Orca
	cfg    VoiceConfig
	tap    VoiceTap
	wake   *wakeMatcher
	stt    ai.STTProvider
	tts    ai.TTSProvider
	chat   ai.ChatProvider

	mu      sync.Mutex
	running map[string]context.CancelFunc

	// followups tracks the open "wake-only listen window" per
	// channel|speaker. After a user says just "Hey Orca", they have
	// followupWindow seconds to speak again with the actual query
	// (no wake word required on the second utterance). Empty when
	// no window is open for a given speaker.
	followMu  sync.Mutex
	followups map[string]time.Time

	// ackAudio is a cached WAV of a short acknowledgement tone, built
	// lazily on first wake-only utterance. No TTS round-trip.
	ackOnce  sync.Once
	ackAudio []byte

	// activeVideo tracks one in-flight ffmpeg-driven video playback
	// per channel. play_video preempts any prior; stop_video kills it.
	videoMu     sync.Mutex
	activeVideo map[string]*videoPlayer

	// activeTTS holds the cancel func for the current in-flight TTS
	// playback per channel. A new wake-matched utterance cancels it
	// so the user can barge in instead of waiting for Orca to finish.
	ttsMu     sync.Mutex
	activeTTS map[string]context.CancelFunc
}

// armTTS preempts any in-flight TTS playback for the channel and
// returns a fresh cancellable context the caller should pass through
// to the TTS + Speak pipeline. On a brand new wake utterance, calling
// this is what stops Orca mid-sentence so the new ask can land.
func (vs *voiceSubsystem) armTTS(parent context.Context, channel string) context.Context {
	vs.ttsMu.Lock()
	if vs.activeTTS == nil {
		vs.activeTTS = map[string]context.CancelFunc{}
	}
	if prev, ok := vs.activeTTS[channel]; ok && prev != nil {
		prev()
	}
	ctx, cancel := context.WithCancel(parent)
	vs.activeTTS[channel] = cancel
	vs.ttsMu.Unlock()
	return ctx
}

// disarmTTS clears the active TTS handle for the channel without
// cancelling (called by the caller once Speak returns normally).
func (vs *voiceSubsystem) disarmTTS(channel string, ctx context.Context) {
	vs.ttsMu.Lock()
	if cancel, ok := vs.activeTTS[channel]; ok && cancel != nil {
		// Only delete if this is still the active one (don't blow
		// away a newer playback that armed after us).
		if ctx.Err() == nil {
			cancel()
			delete(vs.activeTTS, channel)
		}
	}
	vs.ttsMu.Unlock()
}

// summarizeChatError extracts a short human-readable phrase from a
// chat-provider error. The full err is usually a giant JSON blob; we
// just want one provider-agnostic line for the channel.
func summarizeChatError(err error) string {
	if err == nil {
		return "unknown error"
	}
	s := err.Error()
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "insufficient balance") ||
		strings.Contains(low, "no resource package") ||
		strings.Contains(low, "402") ||
		strings.Contains(low, "payment required") ||
		strings.Contains(low, "quota") ||
		strings.Contains(low, "billing"):
		return "chat provider says balance is depleted -- recharge needed"
	case strings.Contains(low, "401") || strings.Contains(low, "unauthor") || strings.Contains(low, "invalid api key"):
		return "chat provider auth failed -- check API key"
	case strings.Contains(low, "429") || strings.Contains(low, "rate"):
		return "rate-limited, try again in a moment"
	case strings.Contains(low, "timeout") || strings.Contains(low, "deadline"):
		return "model timed out"
	case strings.Contains(low, " 5") && strings.Contains(low, "00 "):
		return "upstream model error"
	}
	return truncate(s, 120)
}

// cancelTTS preempts any active TTS in the channel without arming a
// new one. Used by wake-only pings: we want to silence Orca mid-reply
// so the speaker has room for their follow-up.
func (vs *voiceSubsystem) cancelTTS(channel string) {
	vs.ttsMu.Lock()
	if cancel, ok := vs.activeTTS[channel]; ok && cancel != nil {
		cancel()
		delete(vs.activeTTS, channel)
	}
	vs.ttsMu.Unlock()
}

// followupWindow is how long Orca waits for a query after a bare
// "Hey Orca" before going silent again.
const followupWindow = 10 * time.Second

// WithVoiceTap replaces Orca's voice audio backend. Call before Start.
// Without a real tap, the audio path is a no-op (logs only).
func (o *Orca) WithVoiceTap(t VoiceTap) {
	if t == nil {
		return
	}
	o.voiceTap = t
}

// startVoice spins up the listen loops for every configured voice channel.
// Returns immediately; loops run until ctx is cancelled.
func (o *Orca) startVoice(ctx context.Context) {
	o.voiceChannels = splitCSV(os.Getenv("ORCA_VOICE_CHANNELS"))
	if !o.hasVoiceChannels() {
		return
	}
	if o.voiceTap == nil {
		o.voiceTap = nopVoiceTap{}
	}

	cfg := loadVoiceConfig(o)
	vs := &voiceSubsystem{
		o:       o,
		cfg:     cfg,
		tap:     o.voiceTap,
		wake:    newWakeMatcher(),
		stt:     o.stt,
		tts:     o.tts,
		chat:    o.chat,
		running: map[string]context.CancelFunc{},
	}
	o.voice = vs

	for _, ch := range cfg.Channels {
		ch := ch
		chCtx, cancel := context.WithCancel(ctx)
		vs.mu.Lock()
		vs.running[ch] = cancel
		vs.mu.Unlock()
		go vs.runChannel(chCtx, ch)
	}
}

func (vs *voiceSubsystem) runChannel(ctx context.Context, channel string) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := vs.tap.Join(ctx, channel); err != nil {
			log.Printf("[orca/voice] %s: join: %v (retrying in %s)", channel, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second

		frames, err := vs.tap.Frames(ctx, channel)
		if err != nil {
			log.Printf("[orca/voice] %s: frames: %v", channel, err)
			_ = vs.tap.Leave(ctx, channel)
			continue
		}

		log.Printf("[orca/voice] %s: listening (wake_only=%v)", channel, vs.cfg.WakeOnly)
		vs.consume(ctx, channel, frames)
		_ = vs.tap.Leave(ctx, channel)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (vs *voiceSubsystem) consume(ctx context.Context, channel string, frames <-chan AudioFrame) {
	type utterance struct {
		speaker    string
		pcm        bytes.Buffer
		sampleRate int
		channels   int
		started    time.Time
	}
	active := map[string]*utterance{}

	flush := func(u *utterance) {
		if u == nil || u.pcm.Len() == 0 {
			return
		}
		go vs.handleUtterance(ctx, channel, u.speaker,
			wavWrap(u.pcm.Bytes(), u.sampleRate, u.channels))
	}

	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-frames:
			if !ok {
				return
			}
			u := active[f.Speaker]
			if u == nil {
				u = &utterance{
					speaker:    f.Speaker,
					sampleRate: f.SampleRate,
					channels:   f.Channels,
					started:    time.Now(),
				}
				active[f.Speaker] = u
			}
			u.pcm.Write(f.PCM)
			if f.EndOfUtterance || time.Since(u.started) > vs.cfg.UtteranceMax {
				flush(u)
				delete(active, f.Speaker)
			}
		}
	}
}

func (vs *voiceSubsystem) handleUtterance(ctx context.Context, channel, speaker string, wav []byte) {
	if vs.stt == nil {
		return
	}
	resp, err := vs.stt.STT(ctx, ai.STTRequest{
		Audio:    wav,
		MimeType: "audio/wav",
	})
	if err != nil {
		log.Printf("[orca/voice] %s/%s: stt: %v", channel, speaker, err)
		return
	}
	transcript := strings.TrimSpace(resp.Text)
	if transcript == "" {
		return
	}

	log.Printf("[orca/voice] %s/%s: %q", channel, speaker, transcript)

	matched, query := vs.wake.match(transcript)

	// Wake-only utterance ("Hey Orca" with nothing else): play an
	// acknowledgement tone and arm a 10 s follow-up window so the
	// speaker can talk again WITHOUT having to say "Hey Orca" first.
	// Also barge-in: silence any in-flight TTS immediately so the
	// user doesn't have to wait for Orca to finish before being heard.
	if matched && (query == "" || query == "(Acknowledge briefly that you're here.)") {
		log.Printf("[orca/voice] %s/%s: wake-only -> ack + listen window", channel, speaker)
		vs.cancelTTS(channel)
		vs.armFollowup(channel, speaker)
		vs.playAck(ctx, channel)
		return
	}

	if !matched {
		// Not wake-addressed. Check if this speaker is inside an open
		// follow-up window from a recent wake-only ping.
		if vs.cfg.WakeOnly && !vs.consumeFollowup(channel, speaker) {
			return
		}
		query = transcript
	}
	if query == "" {
		return
	}
	// Any real query consumes any pending follow-up window for this
	// speaker, so a subsequent unrelated utterance doesn't get caught.
	vs.consumeFollowup(channel, speaker)

	// Barge-in: silence any prior in-flight TTS so the LLM round-trip
	// for THIS new ask can land on a quiet channel. The next Speak
	// call will arm a fresh TTS context.
	vs.cancelTTS(channel)

	answer, err := vs.askPlain(ctx, channel, speaker, query)
	if err != nil {
		log.Printf("[orca/voice] %s/%s: ask: %v", channel, speaker, err)
		// Surface chat failures into the channel so the user knows
		// Orca isn't dead -- pollen exhausted, model 5xx, etc. The
		// summary trims giant JSON error bodies down to one line.
		if gw := vs.o.Gateway(); gw != nil {
			gw.SendMessage(channel,
				fmt.Sprintf("%s: I can't reply right now (%s).", speaker, summarizeChatError(err)),
				false)
		}
		return
	}

	// Mirror Orca's own spoken answer into the voice channel's text
	// side as a PRIVMSG from Orca's ghost. Voice channels (^) accept
	// PRIVMSGs and the pushbot gateway's PB_OP_SEND_MESSAGE lets us
	// send spontaneously (no invocation context). Posted before TTS
	// kicks off so the text shows up immediately even if TTS is slow
	// or fails.
	if answer != "" && answer != "(no answer)" {
		if gw := vs.o.Gateway(); gw != nil {
			if err := gw.SendMessage(channel, answer, false); err != nil {
				log.Printf("[orca/voice] %s: mirror PRIVMSG: %v", channel, err)
			}
		}
	}

	if vs.tts == nil {
		log.Printf("[orca/voice] %s answer (no TTS): %s", channel, truncate(answer, 200))
		return
	}
	audio, mime, terr := vs.tts.TTS(ctx, ai.TTSRequest{Text: answer})
	if terr != nil {
		log.Printf("[orca/voice] %s: tts: %v", channel, terr)
		return
	}
	log.Printf("[orca/voice] %s: tts ok mime=%s bytes=%d head=%q",
		channel, mime, len(audio), truncate(string(audio), 64))
	// Arm a cancellable TTS context: a subsequent wake utterance for
	// this channel will fire cancelTTS to cut the playback short.
	speakCtx := vs.armTTS(ctx, channel)
	defer vs.disarmTTS(channel, speakCtx)
	if serr := vs.tap.Speak(speakCtx, channel, audio, mime); serr != nil {
		log.Printf("[orca/voice] %s: speak: %v", channel, serr)
	}
}

// voiceToolBudget caps how many tool round-trips a single spoken
// question can drive. Lower than /ask because voice round-trip latency
// is felt much more sharply -- 1-2 tool calls is usually plenty to
// resolve "who's in #X?" / "what channels exist?" style asks.
const voiceToolBudget = 3

// We ask the server on every call, since a user can lose +o at any moment.
func (o *Orca) isOper(ctx context.Context, nick string) bool {
	u, err := newIRCTool(o.irc).UserGet(ctx, nick, 2)
	if err != nil || u == nil {
		return false
	}
	return strings.Contains(getString(u, "user", "modes"), "o")
}

// askPlain runs an /ask-shaped exchange with the same admin-tool access
// /ask has, but with a smaller iteration budget so voice latency stays
// reasonable. Memory is kept per voice channel via the same ConvKey,
// so a follow-up question in voice resolves the context of the previous one.
func (vs *voiceSubsystem) askPlain(ctx context.Context, channel, speaker, query string) (string, error) {
	if vs.chat == nil {
		return "", fmt.Errorf("no chat provider")
	}
	key := ConvKey{Channel: channel}
	conv := vs.o.memory.GetOrCreate(key)

	speakerChanged := conv.LastSpeaker != "" && conv.LastSpeaker != speaker
	speakerNote := ""
	if speakerChanged {
		speakerNote = fmt.Sprintf("The current speaker changed: now talking to %s (previously %s).",
			speaker, conv.LastSpeaker)
	}

	sysPrompt := vs.voiceSystemPrompt(channel, speaker, conv)
	conv.append(ConvTurn{
		Role:    ai.RoleUser,
		Nick:    speaker,
		Time:    time.Now().UTC(),
		Content: query,
	})
	vs.o.logger.AppendTurn(key, ConvTurn{
		Role:    ai.RoleUser,
		Nick:    speaker,
		Time:    time.Now().UTC(),
		Content: query,
	})

	oper := vs.o.isOper(ctx, speaker)
	messages := vs.o.memory.BuildMessages(conv, oper, sysPrompt, speakerNote, "")
	tools := vs.o.aiTools(oper)

	var answer string
	for iter := 0; iter < voiceToolBudget; iter++ {
		resp, err := vs.chat.Chat(ctx, ai.ChatRequest{
			Messages: messages,
			Tools:    tools,
		})
		if err != nil {
			return "", err
		}
		asstTurn := ConvTurn{
			Role:      ai.RoleAssistant,
			Time:      time.Now().UTC(),
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		}
		conv.append(asstTurn)
		vs.o.logger.AppendTurn(key, asstTurn)

		if len(resp.Message.ToolCalls) == 0 {
			answer = strings.TrimSpace(resp.Message.Content)
			break
		}

		messages = append(messages, ai.Message{
			Role:      ai.RoleAssistant,
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		})
		for _, tc := range resp.Message.ToolCalls {
			params := map[string]any{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &params)
			}
			// Voice path has no WorkflowEmitter; invokeAITool tolerates nil.
			result, terr := vs.o.invokeAITool(ctx, oper, tc.Function.Name, params, nil)
			if terr != nil {
				result = fmt.Sprintf(`{"error":%q}`, terr.Error())
			}
			toolTurn := ConvTurn{
				Role:     ai.RoleTool,
				Time:     time.Now().UTC(),
				Content:  result,
				ToolName: tc.Function.Name,
				ToolCall: tc,
			}
			conv.append(toolTurn)
			vs.o.logger.AppendTurn(key, toolTurn)
			messages = append(messages, ai.Message{
				Role:       ai.RoleTool,
				Content:    result,
				Name:       tc.Function.Name,
				ToolCallID: tc.ID,
			})
		}
	}

	// NB: do NOT append the final assistant turn here -- the loop
	// already appended it (asstTurn) on the no-tool-calls iteration
	// that breaks out. A second append would corrupt the conversation
	// history with a duplicate assistant turn, which downstream
	// BuildMessages can slice through and produce orphan tool turns.
	if answer == "" {
		answer = "(no answer)"
	}
	go vs.o.memory.MaybeCompact(context.Background(), conv)
	return answer, nil
}

func (vs *voiceSubsystem) voiceSystemPrompt(channel, speaker string, conv *Conversation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are Orca, an IRC ops assistant, speaking aloud over a voice channel (%s). ", channel)
	fmt.Fprintf(&b, "Reply in one or two short spoken sentences -- no Markdown, no bullets, no code fences. ")
	fmt.Fprintf(&b, "The current speaker is %s.\n", speaker)
	if conv.LastSpeaker != "" && conv.LastSpeaker != speaker {
		fmt.Fprintf(&b, "The previous speaker was %s; the speaker just changed.\n", conv.LastSpeaker)
	}
	return b.String()
}

// wavWrap puts a minimal WAVE header around 16-bit PCM. STT providers
// reliably accept WAV uploads without negotiating a codec.
func wavWrap(pcm []byte, sampleRate, channels int) []byte {
	if sampleRate == 0 {
		sampleRate = 16000
	}
	if channels == 0 {
		channels = 1
	}
	byteRate := sampleRate * channels * 2
	blockAlign := channels * 2

	buf := bytes.NewBuffer(nil)
	buf.WriteString("RIFF")
	_ = binary.Write(buf, binary.LittleEndian, uint32(36+len(pcm)))
	buf.WriteString("WAVE")
	buf.WriteString("fmt ")
	_ = binary.Write(buf, binary.LittleEndian, uint32(16))
	_ = binary.Write(buf, binary.LittleEndian, uint16(1)) // PCM
	_ = binary.Write(buf, binary.LittleEndian, uint16(channels))
	_ = binary.Write(buf, binary.LittleEndian, uint32(sampleRate))
	_ = binary.Write(buf, binary.LittleEndian, uint32(byteRate))
	_ = binary.Write(buf, binary.LittleEndian, uint16(blockAlign))
	_ = binary.Write(buf, binary.LittleEndian, uint16(16))
	buf.WriteString("data")
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(pcm)))
	buf.Write(pcm)
	return buf.Bytes()
}

// armFollowup opens a follow-up window for (channel, speaker). The
// next utterance from that speaker within followupWindow is treated
// as a real query even if it doesn't start with a wake word.
func (vs *voiceSubsystem) armFollowup(channel, speaker string) {
	key := channel + "|" + strings.ToLower(speaker)
	vs.followMu.Lock()
	if vs.followups == nil {
		vs.followups = map[string]time.Time{}
	}
	vs.followups[key] = time.Now().Add(followupWindow)
	vs.followMu.Unlock()
}

// consumeFollowup reports whether (channel, speaker) is currently
// inside a live follow-up window, and clears it either way (one
// follow-up per ping). Expired entries are cleared opportunistically.
func (vs *voiceSubsystem) consumeFollowup(channel, speaker string) bool {
	key := channel + "|" + strings.ToLower(speaker)
	now := time.Now()
	vs.followMu.Lock()
	defer vs.followMu.Unlock()
	if vs.followups == nil {
		return false
	}
	deadline, ok := vs.followups[key]
	if !ok {
		return false
	}
	delete(vs.followups, key)
	return now.Before(deadline)
}

// playAck plays the cached acknowledgement tone into the channel.
// Cheap because the WAV is built once and replayed; no TTS round-trip.
func (vs *voiceSubsystem) playAck(ctx context.Context, channel string) {
	vs.ackOnce.Do(func() {
		vs.ackAudio = buildAckTone()
	})
	if vs.ackAudio == nil || vs.tap == nil {
		return
	}
	if err := vs.tap.Speak(ctx, channel, vs.ackAudio, "audio/wav"); err != nil {
		log.Printf("[orca/voice] %s: ack speak: %v", channel, err)
	}
}

// buildAckTone synthesizes a short 2-note chirp -- a quiet sine
// "bip-boop" at ~880 Hz then ~660 Hz, total ~200 ms. Universally
// reads as "I'm listening" without needing TTS.
func buildAckTone() []byte {
	const (
		rate     = 24000
		noteMs   = 90
		gapMs    = 10
		amp      = 0.18 // 0..1; keep quiet so it doesn't startle
	)
	samplesPerNote := rate * noteMs / 1000
	samplesGap := rate * gapMs / 1000
	notes := []float64{880, 660}

	pcm := make([]int16, 0, (samplesPerNote+samplesGap)*len(notes))
	for _, f := range notes {
		for i := 0; i < samplesPerNote; i++ {
			t := float64(i) / float64(rate)
			// Gentle attack/release envelope so it sounds like a bell,
			// not a click.
			env := 1.0
			fadeSamples := samplesPerNote / 6
			if i < fadeSamples {
				env = float64(i) / float64(fadeSamples)
			} else if i > samplesPerNote-fadeSamples {
				env = float64(samplesPerNote-i) / float64(fadeSamples)
			}
			s := amp * env * math.Sin(2*math.Pi*f*t)
			pcm = append(pcm, int16(s*32767))
		}
		for i := 0; i < samplesGap; i++ {
			pcm = append(pcm, 0)
		}
	}
	// 16-bit mono → wavWrap-friendly bytes.
	raw := make([]byte, len(pcm)*2)
	for i, v := range pcm {
		raw[2*i] = byte(v)
		raw[2*i+1] = byte(v >> 8)
	}
	return wavWrap(raw, rate, 1)
}
