package orca

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"backend/ai"
	"backend/bot"
	"backend/netguard"
)

type fakeIRC struct {
	operNicks []string
	methods   []string
}

func (f *fakeIRC) Query(_ context.Context, method string, params map[string]any) (any, error) {
	f.methods = append(f.methods, method)
	if method != "user.get" {
		return map[string]any{}, nil
	}
	modes := "iwx"
	if nick, _ := params["nick"].(string); slices.Contains(f.operNicks, nick) {
		modes = "iowx"
	}
	return map[string]any{"client": map[string]any{
		"ip":   "203.0.113.7",
		"user": map[string]any{"modes": modes},
	}}, nil
}

// scriptedChat asks for user_get once, then answers, and keeps every prompt.
type scriptedChat struct {
	prompts [][]ai.Message
}

func (c *scriptedChat) Chat(_ context.Context, req ai.ChatRequest) (*ai.ChatResponse, error) {
	c.prompts = append(c.prompts, req.Messages)
	if len(c.prompts) == 1 {
		call := ai.ToolCall{ID: "call-1", Type: "function",
			Function: ai.FunctionCall{Name: "user_get", Arguments: `{"nick":"alice"}`}}
		return &ai.ChatResponse{Message: ai.Message{Role: ai.RoleAssistant, ToolCalls: []ai.ToolCall{call}}}, nil
	}
	return &ai.ChatResponse{Message: ai.Message{Role: ai.RoleAssistant, Content: "alice connects from 203.0.113.7"}}, nil
}

func TestNonOperPromptHoldsNoToolOutputFromAnEarlierOperExchange(t *testing.T) {
	chat := &scriptedChat{}
	o, _ := newTestOrca(&fakeIRC{operNicks: []string{"root"}})
	o.chat = chat
	o.memory = NewMemory(chat)
	vs := &voiceSubsystem{o: o, chat: chat}
	if _, err := vs.askPlain(context.Background(), "^voice", "root", "who is alice"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(messagesText(chat.prompts[1]), "203.0.113.7") {
		t.Fatal("the oper never saw the tool result, so the test proves nothing")
	}
	conv := o.memory.GetOrCreate(ConvKey{Channel: "^voice"})
	conv.Summary = "alice is at 203.0.113.7"
	conv.SummaryHasToolOutput = true

	if _, err := vs.askPlain(context.Background(), "^voice", "bob", "what did you find on alice"); err != nil {
		t.Fatal(err)
	}
	prompt := chat.prompts[len(chat.prompts)-1]
	if text := messagesText(prompt); strings.Contains(text, "203.0.113.7") || strings.Contains(text, "user_get") {
		t.Fatalf("non-oper prompt holds tool output:\n%s", text)
	}
}

type promptChat struct {
	prompts chan []ai.Message
	reply   string
}

func (c *promptChat) Chat(_ context.Context, req ai.ChatRequest) (*ai.ChatResponse, error) {
	if c.prompts != nil {
		c.prompts <- req.Messages
	}
	return &ai.ChatResponse{Message: ai.Message{Role: ai.RoleAssistant, Content: c.reply}}, nil
}

func TestPrivateAskThreadStaysOutOfTheChannelThread(t *testing.T) {
	chat := &promptChat{prompts: make(chan []ai.Message, 1), reply: "ok"}
	o, _ := newTestOrca(&fakeIRC{})
	o.chat = chat
	o.memory = NewMemory(chat)
	o.SetGateway(&bot.Gateway{})

	// We store the turns the way cmdAsk does for an oper invoking /ask in #lobby.
	private := o.memory.GetOrCreate(askThreadKey(bot.Author{Nick: "root", Account: "root", IsOper: true}))
	private.append(ConvTurn{Role: ai.RoleUser, Nick: "root", Content: "who is alice"})
	private.append(ConvTurn{Role: ai.RoleAssistant, Content: "alice connects from 203.0.113.7"})

	o.handleChannelMessage(context.Background(), bot.MessageCreate{
		Channel: map[string]any{"name": "#lobby"},
		Author:  map[string]any{"nick": "bob", "is_oper": false},
		Content: "Orca, what did root ask you",
	})
	select {
	case prompt := <-chat.prompts:
		if text := messagesText(prompt); strings.Contains(text, "203.0.113.7") {
			t.Fatalf("channel prompt holds a private answer:\n%s", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the model was never asked")
	}

	if askThreadKey(bot.Author{Nick: "root", Account: "root"}) == askThreadKey(bot.Author{Nick: "root"}) {
		t.Error("a nick without the account shares the account's thread")
	}
	if askThreadKey(bot.Author{Nick: "root", Account: "*"}) != askThreadKey(bot.Author{Nick: "root"}) {
		t.Error("a logged-out user is not keyed by nick")
	}
}

func compactedConversation(t *testing.T, withTools bool) *Conversation {
	t.Helper()
	m := NewMemory(&promptChat{reply: "earlier chat summary"})
	conv := &Conversation{}
	for i := range m.compactionTrigger {
		conv.append(ConvTurn{Role: ai.RoleUser, Nick: "bob", Content: "hi"})
		turn := ConvTurn{Role: ai.RoleAssistant, Content: "hello"}
		if withTools && i == 0 {
			turn.ToolCalls = []ai.ToolCall{{ID: "c", Function: ai.FunctionCall{Name: "user_get"}}}
		}
		conv.append(turn)
	}
	m.MaybeCompact(context.Background(), conv)
	if conv.Summary == "" {
		t.Fatal("no compaction happened")
	}
	return conv
}

func TestNonOpersKeepASummaryWithoutToolOutput(t *testing.T) {
	m := NewMemory(nil)
	if text := messagesText(m.BuildMessages(compactedConversation(t, false), false, "", "", "")); !strings.Contains(text, "earlier chat summary") {
		t.Fatalf("plain summary hidden:\n%s", text)
	}
	if text := messagesText(m.BuildMessages(compactedConversation(t, true), false, "", "", "")); strings.Contains(text, "earlier chat summary") {
		t.Fatalf("summary built from tool output shown:\n%s", text)
	}
}

func messagesText(msgs []ai.Message) string {
	var b strings.Builder
	for _, m := range msgs {
		b.WriteString(string(m.Role) + " " + m.Name + " " + m.Content + "\n")
		for _, tc := range m.ToolCalls {
			b.WriteString(tc.Function.Name + tc.Function.Arguments + "\n")
		}
	}
	return b.String()
}

type recordingChat struct {
	tools chan []string
}

func (c *recordingChat) Chat(_ context.Context, req ai.ChatRequest) (*ai.ChatResponse, error) {
	names := make([]string, 0, len(req.Tools))
	for _, t := range req.Tools {
		names = append(names, t.Function.Name)
	}
	c.tools <- names
	return &ai.ChatResponse{Message: ai.Message{Role: ai.RoleAssistant, Content: "ok"}}, nil
}

func newTestOrca(irc IRC) (*Orca, *recordingChat) {
	chat := &recordingChat{tools: make(chan []string, 1)}
	o := &Orca{
		nick:      "Orca",
		irc:       irc,
		chat:      chat,
		memory:    NewMemory(chat),
		handlers:  map[string]Handler{},
		aiToolMap: map[string]Tool{},
	}
	o.registerDefaultTools()
	return o, chat
}

func receiveTools(t *testing.T, chat *recordingChat) []string {
	t.Helper()
	select {
	case tools := <-chat.tools:
		return tools
	case <-time.After(5 * time.Second):
		t.Fatal("the model was never asked")
		return nil
	}
}

var operDataTools = []string{
	"user_kill", "ban_add", "server_rehash", "channel_set_mode", "play_video",
	"user_get", "user_list", "channel_get", "channel_list", "bans_list",
	"spamfilter_list", "stats", "server_list", "explain_mask",
}

func checkAdminTools(t *testing.T, who string, tools []string, wantAdmin bool) {
	t.Helper()
	for _, name := range operDataTools {
		if slices.Contains(tools, name) != wantAdmin {
			t.Errorf("%s: offered %s = %v", who, name, !wantAdmin)
		}
	}
	if !wantAdmin && len(tools) != 0 {
		t.Errorf("%s: offered %v", who, tools)
	}
}

func TestChatListenOffersAdminToolsOnlyToOpers(t *testing.T) {
	for _, oper := range []bool{false, true} {
		o, chat := newTestOrca(&fakeIRC{})
		o.SetGateway(&bot.Gateway{})
		o.handleChannelMessage(context.Background(), bot.MessageCreate{
			Channel: map[string]any{"name": "#lobby"},
			Author:  map[string]any{"nick": "bob", "is_oper": oper},
			Content: "Orca, kill alice",
		})
		checkAdminTools(t, "chat", receiveTools(t, chat), oper)
	}
}

func TestVoiceAskOffersAdminToolsOnlyToOpers(t *testing.T) {
	irc := &fakeIRC{operNicks: []string{"root"}}
	for _, speaker := range []string{"bob", "root"} {
		o, chat := newTestOrca(irc)
		vs := &voiceSubsystem{o: o, chat: chat}
		if _, err := vs.askPlain(context.Background(), "^voice", speaker, "ban alice"); err != nil {
			t.Fatal(err)
		}
		checkAdminTools(t, "voice "+speaker, receiveTools(t, chat), speaker == "root")
	}
}

func TestNonOperCannotRunAnAdminToolByName(t *testing.T) {
	irc := &fakeIRC{}
	o, _ := newTestOrca(irc)
	params := map[string]any{
		"nick": "alice", "reason": "x", "channel": "#c", "mask": "*@*",
		"type": "gline", "name": "*@x", "modes": "+m", "url": "https://example.com/a.png",
	}
	for name := range o.aiToolMap {
		if _, err := o.invokeAITool(context.Background(), false, name, params, nil); err == nil {
			t.Errorf("%s ran for a non-oper", name)
		}
	}
	if len(irc.methods) != 0 {
		t.Fatalf("queries %v", irc.methods)
	}
}

func TestVideoDownloadRefusesInternalAddresses(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer internal.Close()

	for _, target := range []string{internal.URL, "http://10.0.0.1/a.mp4", "http://169.254.169.254/latest/meta-data/"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		path, err := downloadVideoToTemp(ctx, target)
		cancel()
		if !errors.Is(err, netguard.ErrInternalAddress) {
			t.Errorf("%s: path %q, err %v", target, path, err)
		}
	}
}

func TestVideoDownloadChecksEveryRedirect(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer internal.Close()
	redirector := httptest.NewServer(http.RedirectHandler(internal.URL, http.StatusFound))
	defer redirector.Close()

	// We let the dialer through to the loopback redirector only, standing in for a public host.
	redirectorAddr := strings.TrimPrefix(redirector.URL, "http://")
	transport := videoHTTPClient.Transport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		if address == redirectorAddr {
			return nil
		}
		return netguard.RefuseInternalAddress(network, address, c)
	}}).DialContext
	original := videoHTTPClient
	videoHTTPClient = &http.Client{Transport: transport}
	defer func() { videoHTTPClient = original }()

	path, err := downloadVideoToTemp(context.Background(), redirector.URL)
	if !errors.Is(err, netguard.ErrInternalAddress) {
		t.Fatalf("path %q, err %v", path, err)
	}
}
