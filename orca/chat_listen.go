package orca

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"backend/ai"
	"backend/bot"
)

// chatListenEnabled gates passive channel-message addressing. Defaults
// on; flip to false with ORCA_CHAT_LISTEN=false if cost or noise becomes
// an issue (each addressed message costs a chat round-trip).
func chatListenEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ORCA_CHAT_LISTEN")))
	if v == "" {
		return true
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}

// chatToolBudget caps tool round-trips for a chat-addressed query.
// Each iteration can carry several parallel tool calls, so the
// effective tool count is roughly N × tools-per-iteration; 8 lines
// up with the /ask budget and keeps tool-heavy "audit-and-ban" loops
// from truncating mid-pass.
const chatToolBudget = 8

// addressMatcher decides whether a channel message is targeted at the
// bot. Rule (per user request, simpler and more reliable than regex
// gymnastics): after stripping all punctuation to spaces, the nick
// must be either the FIRST or SECOND word of the message. Anywhere
// else and we ignore -- avoids false positives like "did you see the
// movie about Orca" or "thanks orca", and forces deliberate addressing.
//
// Examples that MATCH:
//   "Orca" / "Orca?" / "Orca, what time?"     (1st word)
//   "Hey Orca, what?" / "@Orca explain" / "OK Orca do X"   (2nd word)
//
// Examples that DON'T match:
//   "did you see that movie about Orca"
//   "talk about Orca it wouldn't care?"
//   "are you there orca?"   (4th word -- ask "orca, are you there?" instead)
//   "I love orca whales"
type addressMatcher struct {
	nick      string
	nickLower string
}

func newAddressMatcher(nick string) *addressMatcher {
	return &addressMatcher{
		nick:      nick,
		nickLower: strings.ToLower(nick),
	}
}

// match returns (addressed, query). If addressed=false, the message
// isn't for us. Query is the residual text after the addressing
// prefix is stripped, preserving ALL original punctuation in the
// remainder (URLs, etc.) -- only the addressing-detection itself
// strips punctuation. Empty query means a bare ping like "Orca?".
func (m *addressMatcher) match(text string) (bool, string) {
	if m.nick == "" {
		return false, ""
	}
	t := strings.TrimSpace(text)
	if t == "" {
		return false, ""
	}

	tokens := tokenizeStrippingPunct(t)
	if len(tokens) == 0 {
		return false, ""
	}

	idx := -1
	if strings.ToLower(tokens[0]) == m.nickLower {
		idx = 0
	} else if len(tokens) > 1 && strings.ToLower(tokens[1]) == m.nickLower {
		idx = 1
	}
	if idx == -1 {
		return false, ""
	}

	// Slice the ORIGINAL text after the (idx+1)-th word so URLs and
	// other punctuation-laden content survive intact.
	rest := strings.TrimSpace(sliceAfterNWords(t, idx+1))
	if rest == "" {
		// e.g. just "Orca?" or "Hey Orca" -- treat as a ping.
		return true, "(Acknowledge briefly that you're here.)"
	}
	return true, rest
}

// sliceAfterNWords walks the original text and returns whatever
// comes after the n-th alphanumeric word boundary, with leading
// addressing punctuation (commas, colons, dashes, etc.) trimmed --
// but not URL-significant characters within the remainder.
func sliceAfterNWords(s string, n int) string {
	if n <= 0 {
		return s
	}
	seen := 0
	inWord := false
	i := 0
	for i < len(s) {
		r, sz := utf8.DecodeRuneInString(s[i:])
		isWord := unicode.IsLetter(r) || unicode.IsDigit(r)
		if isWord {
			inWord = true
		} else if inWord {
			inWord = false
			seen++
			if seen >= n {
				return strings.TrimLeftFunc(s[i:], addressTrailingSep)
			}
		}
		i += sz
	}
	// Ended inside a word; that counts as one more.
	if inWord {
		seen++
	}
	if seen >= n {
		return ""
	}
	return ""
}

// addressTrailingSep matches the punctuation that typically appears
// right after the address ("hey orca, ...", "orca: ...", "orca - ..."),
// but stops at anything that could be the first character of a
// real query (letters, digits, '/', '@', '#', '+').
func addressTrailingSep(r rune) bool {
	switch r {
	case ' ', '\t', '\r', '\n',
		',', '.', ':', ';', '!', '?',
		'-', '—', '–':
		return true
	}
	return false
}

// tokenizeStrippingPunct turns the message into whitespace-separated
// tokens with every non-letter/non-digit character treated as a word
// separator. So "Hey, Orca!" -> ["Hey", "Orca"], "@orca foo" -> ["orca",
// "foo"], "isn't" -> ["isn", "t"] (good enough -- we only look at the
// first two tokens).
func tokenizeStrippingPunct(s string) []string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	return strings.Fields(b.String())
}

// handleChannelMessage is the dispatch entry from OnEvent. Filters out
// the cases we don't care about (TAGMSG, NOTICE, own messages,
// addressed-to-someone-else), then runs the same tool-enabled chat
// loop the voice path uses and posts the answer via gw.SendMessage.
func (o *Orca) handleChannelMessage(ctx context.Context, m bot.MessageCreate) {
	if !chatListenEnabled() {
		return
	}
	if m.IsNotice || m.IsTagmsg {
		return // never auto-reply to NOTICEs (loops!) or TAGMSGs
	}
	if m.Content == "" {
		return
	}

	channel, _ := m.Channel["name"].(string)
	speaker, _ := m.Author["nick"].(string)
	if channel == "" || speaker == "" {
		return
	}
	// Never reply to ourselves.
	if strings.EqualFold(speaker, o.nick) {
		return
	}
	// Don't double-handle slash-command invocations: those already
	// have a dedicated path through bot.Invocation. "!ask query" /
	// "/ask query" should go through that, not the chat-listen loop.
	if t := strings.TrimSpace(m.Content); strings.HasPrefix(t, "!") || strings.HasPrefix(t, "/") {
		return
	}

	matched, query := o.addressMatcher().match(m.Content)
	if !matched {
		return
	}
	if query == "" {
		return
	}

	oper, _ := m.Author["is_oper"].(bool)
	go o.runChatReply(ctx, channel, speaker, oper, query, m.Msgid)
}

// addressMatcher lazily builds the matcher once and caches it. Nick
// can't change during a single bot session, so this is fine.
func (o *Orca) addressMatcher() *addressMatcher {
	o.addrMu.Lock()
	defer o.addrMu.Unlock()
	if o.addrMatcher == nil {
		o.addrMatcher = newAddressMatcher(o.nick)
	}
	return o.addrMatcher
}

// runChatReply is the per-message worker: same tool-loop shape as
// askPlain but tuned for chat (text output, longer context budget, no
// TTS). Posts the reply with SendMessage.
func (o *Orca) runChatReply(ctx context.Context, channel, speaker string, oper bool, query, triggerMsgid string) {
	gw := o.Gateway()
	if gw == nil {
		log.Printf("[orca/chat] %s/%s: no gateway, can't reply", channel, speaker)
		return
	}
	if o.chat == nil {
		return
	}

	key := ConvKey{Channel: channel}
	conv := o.memory.GetOrCreate(key)

	speakerNote := ""
	if conv.LastSpeaker != "" && conv.LastSpeaker != speaker {
		speakerNote = fmt.Sprintf("The current speaker changed: now talking to %s (previously %s).",
			speaker, conv.LastSpeaker)
	}

	sysPrompt := o.chatSystemPrompt(channel, speaker, conv)
	now := time.Now().UTC()
	conv.append(ConvTurn{
		Role: ai.RoleUser, Nick: speaker, Time: now, Content: query,
	})
	o.logger.AppendTurn(key, ConvTurn{
		Role: ai.RoleUser, Nick: speaker, Time: now, Content: query,
	})

	messages := o.memory.BuildMessages(conv, oper, sysPrompt, speakerNote, "")
	tools := o.aiTools(oper)

	// Workflow card for the floating bot-tools UI. Lifetime is the
	// whole tool-call loop; we mark complete when the model returns
	// a final answer, failed if it errors, exhausted at budget cap.
	w := gw.NewWorkflow(channel, triggerMsgid, "chat:"+speaker)
	_ = w.Start("interactive", "reasoning")
	rs := w.ReasoningStart("Thinking")
	defer func() {
		if !w.IsTerminated() {
			_ = w.Failed()
		}
	}()

	var answer string
	for iter := 0; iter < chatToolBudget; iter++ {
		resp, err := o.chat.Chat(ctx, ai.ChatRequest{
			Messages: messages,
			Tools:    tools,
		})
		if iter == 0 && rs != nil {
			_ = rs.Complete()
			rs = nil
		}
		if err != nil {
			log.Printf("[orca/chat] %s/%s: ask: %v", channel, speaker, err)
			// Surface to the channel so the user knows we tried.
			gw.SendMessage(channel,
				fmt.Sprintf("%s: I can't reply right now (%s).", speaker, summarizeChatError(err)),
				false)
			return
		}
		asstTurn := ConvTurn{
			Role:      ai.RoleAssistant,
			Time:      time.Now().UTC(),
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		}
		conv.append(asstTurn)
		o.logger.AppendTurn(key, asstTurn)

		if len(resp.Message.ToolCalls) == 0 {
			answer = strings.TrimSpace(resp.Message.Content)
			break
		}
		messages = append(messages, ai.Message{
			Role: ai.RoleAssistant, Content: resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		})
		for _, tc := range resp.Message.ToolCalls {
			params := map[string]any{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &params)
			}
			result, terr := o.invokeAITool(ctx, oper, tc.Function.Name, params, w)
			if terr != nil {
				result = fmt.Sprintf(`{"error":%q}`, terr.Error())
			}
			toolTurn := ConvTurn{
				Role: ai.RoleTool, Time: time.Now().UTC(),
				Content: result, ToolName: tc.Function.Name, ToolCall: tc,
			}
			conv.append(toolTurn)
			o.logger.AppendTurn(key, toolTurn)
			messages = append(messages, ai.Message{
				Role: ai.RoleTool, Content: result,
				Name: tc.Function.Name, ToolCallID: tc.ID,
			})
		}
	}

	if answer == "" {
		answer = "(no reply)"
	}
	out := fmt.Sprintf("%s: %s", speaker, answer)
	if err := gw.SendMessageTagged(channel, out, false, w.TerminalReplyTags("complete")); err != nil {
		log.Printf("[orca/chat] %s: SendMessage: %v", channel, err)
	}
	// Trailing standalone workflow:complete TAGMSG -- matches fluffilloo.
	// The reply PRIVMSG/BATCH already carries +draft/bot-tools with
	// state=complete, but the client also needs to see it as a bare
	// TAGMSG to actually terminate the card.
	_ = w.Complete()

	go o.memory.MaybeCompact(context.Background(), conv)
}

func (o *Orca) chatSystemPrompt(channel, speaker string, conv *Conversation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are Orca, an IRC ops assistant active in channel %s. ", channel)
	fmt.Fprintf(&b, "A user addressed you directly in chat (not via /ask). ")
	fmt.Fprintf(&b, "Reply concisely -- one or two short sentences usually, more only if the question demands detail. No Markdown headers, no code fences unless quoting actual code/output. ")
	fmt.Fprintf(&b, "The speaker is %s. Use the available admin tools when the question needs real server data; don't guess.\n", speaker)
	if conv.LastSpeaker != "" && conv.LastSpeaker != speaker {
		fmt.Fprintf(&b, "Previous speaker was %s.\n", conv.LastSpeaker)
	}
	return b.String()
}

