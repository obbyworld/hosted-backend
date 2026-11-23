package orca

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"backend/ai"
	"backend/bot"
)

const maxToolIterations = 8

var askCommand = bot.Command{
	Name:        "ask",
	Description: "Ask Orca a natural-language admin question; AI may use admin tools.",
	Contexts:    []string{"public", "private", "pm"},
	Options: []bot.Option{
		{Name: "query", Type: "string", Required: true,
			Description: "What to ask."},
		{Name: "reset", Type: "bool", Required: false,
			Description: "Reset the conversation thread before asking."},
	},
}

// The gateway whispers every /ask reply, so we keep each invoker's thread
// apart from the channel's, keyed by account so a nick change cannot take it over.
func askThreadKey(a bot.Author) ConvKey {
	if a.Account != "" && a.Account != "*" {
		return ConvKey{Private: "account:" + a.Account}
	}
	return ConvKey{Private: "nick:" + a.Nick}
}

func (o *Orca) cmdAsk(ctx context.Context, inv *bot.Invocation) error {
	query := strings.TrimSpace(inv.String("query"))
	if query == "" {
		return inv.Whisper("ask: query required.")
	}

	// Pushbot's initial interaction TTL is 3s; AI calls always exceed
	// it. Defer immediately to buy 15s; we'll re-defer per tool loop
	// below if the model keeps calling tools.
	_ = inv.Defer()

	convKey := askThreadKey(inv.Author)

	if inv.Bool("reset") {
		o.memory.Reset(convKey)
		_ = inv.Whisper("(thread reset)")
	}

	conv := o.memory.GetOrCreate(convKey)

	speakerChanged := conv.LastSpeaker != "" && conv.LastSpeaker != inv.Author.Nick
	var speakerNote string
	if speakerChanged {
		speakerNote = fmt.Sprintf("The current speaker changed: now talking to %s (previously %s). Treat this as a new participant; don't carry their personal context over.", inv.Author.Nick, conv.LastSpeaker)
	}

	w := inv.NewWorkflow("ask")
	if err := w.Start("interactive", "reasoning"); err != nil {
		return err
	}
	rs := w.ReasoningStart("Thinking")

	now := time.Now().UTC()
	userTurn := ConvTurn{
		Role:    ai.RoleUser,
		Nick:    inv.Author.Nick,
		Account: inv.Author.Account,
		Msgid:   inv.Msgid,
		Time:    now,
		Content: query,
	}
	conv.append(userTurn)
	o.logger.AppendTurn(convKey, userTurn)

	sysPrompt := o.buildSystemPrompt(ctx, inv, conv)
	messages := o.memory.BuildMessages(conv, inv.Author.IsOper, sysPrompt, speakerNote, "")

	tools := o.aiTools(inv.Author.IsOper)

	for iter := 0; iter < maxToolIterations; iter++ {
		_ = inv.Defer()
		resp, err := o.chat.Chat(ctx, ai.ChatRequest{
			Messages: messages,
			Tools:    tools,
		})
		if iter == 0 && rs != nil {
			_ = rs.Complete()
			rs = nil
		}
		if err != nil {
			_ = w.Failed()
			return inv.Whisper("ask: " + err.Error())
		}

		// Record assistant turn (with any tool calls) in log + memory.
		asstTurn := ConvTurn{
			Role:      ai.RoleAssistant,
			Time:      time.Now().UTC(),
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		}
		conv.append(asstTurn)
		o.logger.AppendTurn(convKey, asstTurn)

		if len(resp.Message.ToolCalls) == 0 {
			reply := strings.TrimSpace(resp.Message.Content)
			if reply == "" {
				reply = "(no response)"
			}
			go o.memory.MaybeCompact(context.Background(), conv)
			err := inv.ReplyTagged(reply, w.TerminalReplyTags("complete"))
			_ = w.Complete() // trailing standalone TAGMSG -- see chat_listen
			return err
		}

		// Add the assistant message that called the tools.
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
			result, terr := o.invokeAITool(ctx, inv.Author.IsOper, tc.Function.Name, params, w)
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
			o.logger.AppendTurn(convKey, toolTurn)

			messages = append(messages, ai.Message{
				Role:       ai.RoleTool,
				Content:    result,
				Name:       tc.Function.Name,
				ToolCallID: tc.ID,
			})
		}
	}

	_ = w.Failed()
	return inv.Whisper(fmt.Sprintf("ask: model exceeded tool-call budget (%d); thread kept, retry with /ask reset:true if needed.", maxToolIterations))
}

func (o *Orca) invokeAITool(ctx context.Context, oper bool, name string, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	o.cmdMu.RLock()
	t, ok := o.aiToolMap[name]
	o.cmdMu.RUnlock()
	if !ok || !oper {
		return "", fmt.Errorf("unknown tool: %s", name)
	}
	return t.Handler(ctx, o, params, w)
}

func (o *Orca) buildSystemPrompt(ctx context.Context, inv *bot.Invocation, conv *Conversation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are Orca, the obbyircd admin assistant. You are an IRC bot operating under IRCop supervision. Be terse, factual, and unfailingly cite which tools you used.\n\n")
	if inv.Channel != "" {
		fmt.Fprintf(&b, "You are speaking in channel %s. Other IRC operators may also be present.\n", inv.Channel)
	} else {
		fmt.Fprintf(&b, "You are in a private message with %s.\n", inv.Author.Nick)
	}
	fmt.Fprintf(&b, "The current speaker is %s", inv.Author.Nick)
	if inv.Author.Account != "" && inv.Author.Account != "*" {
		fmt.Fprintf(&b, " (logged in as account %s)", inv.Author.Account)
	}
	fmt.Fprintf(&b, ".\n")

	if conv.LastSpeaker != "" && conv.LastSpeaker != inv.Author.Nick {
		fmt.Fprintf(&b, "The previous speaker in this thread was %s; the speaker just changed.\n", conv.LastSpeaker)
	}

	participants := participantsInConv(conv)
	if len(participants) > 1 {
		fmt.Fprintf(&b, "Participants who have spoken in this thread: %s.\n", strings.Join(participants, ", "))
	}

	fmt.Fprintf(&b, "\nGuidelines:\n")
	fmt.Fprintf(&b, "- Prefer tool calls to guessing. The tools return live network state.\n")
	fmt.Fprintf(&b, "- When asked about a user or channel, look them up before answering.\n")
	fmt.Fprintf(&b, "- Suggest precise masks via explain_mask before recommending any ban.\n")
	fmt.Fprintf(&b, "- IRCops on this network may use member-roles; channel mode strings may differ from stock UnrealIRCd.\n")
	fmt.Fprintf(&b, "- Answer in plain text suitable for an IRC line (no Markdown headings).\n")
	fmt.Fprintf(&b, "- If a tool errors, surface the error in your reply.\n")
	return b.String()
}

func participantsInConv(conv *Conversation) []string {
	conv.mu.Lock()
	defer conv.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range conv.Turns {
		if t.Role == ai.RoleUser && t.Nick != "" {
			seen[t.Nick] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
