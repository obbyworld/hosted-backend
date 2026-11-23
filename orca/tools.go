package orca

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"backend/ai"
	"backend/bot"
)

type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any
	Handler     func(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error)
}

// Every tool reads or changes server state that only opers can see, such as
// user IPs, secret channels and bans, so we give the model no tools for other users.
func (o *Orca) aiTools(oper bool) []ai.ToolSpec {
	if !oper {
		return nil
	}
	o.cmdMu.RLock()
	defer o.cmdMu.RUnlock()
	out := make([]ai.ToolSpec, 0, len(o.aiToolMap))
	names := make([]string, 0, len(o.aiToolMap))
	for n := range o.aiToolMap {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := o.aiToolMap[n]
		out = append(out, ai.ToolSpec{
			Type: "function",
			Function: ai.FunctionSpec{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}
	return out
}

func (o *Orca) registerTool(t Tool) {
	if o.aiToolMap == nil {
		o.aiToolMap = map[string]Tool{}
	}
	o.aiToolMap[t.Name] = t
}

func (o *Orca) registerDefaultTools() {
	o.registerTool(Tool{
		Name:        "user_get",
		Description: "Get full detail about a single user by nick.",
		Parameters: objectSchema(
			prop("nick", "string", "Nickname to look up."),
		).required("nick").build(),
		Handler: toolUserGet,
	})
	o.registerTool(Tool{
		Name:        "user_list",
		Description: "List all users on the network. Returns nick, host, account, idle for each.",
		Parameters:  objectSchema().build(),
		Handler:     toolUserList,
	})
	o.registerTool(Tool{
		Name:        "channel_get",
		Description: "Get full detail about a channel by name, including members, bans, and topic.",
		Parameters: objectSchema(
			prop("channel", "string", "Channel name including its prefix (e.g. #opers)."),
		).required("channel").build(),
		Handler: toolChannelGet,
	})
	o.registerTool(Tool{
		Name:        "channel_list",
		Description: "List all channels on the network with size and modes.",
		Parameters:  objectSchema().build(),
		Handler:     toolChannelList,
	})
	o.registerTool(Tool{
		Name:        "bans_list",
		Description: "List server-side bans (K-lines / G-lines).",
		Parameters:  objectSchema().build(),
		Handler:     toolBansList,
	})
	o.registerTool(Tool{
		Name:        "stats",
		Description: "Get server statistics (connections, channels, opers, etc.).",
		Parameters:  objectSchema().build(),
		Handler:     toolStats,
	})
	o.registerTool(Tool{
		Name:        "explain_mask",
		Description: "Walk current users and report what a ban/extban/k-line mask matches. Useful for validating before applying.",
		Parameters: objectSchema(
			prop("mask", "string", "Ban mask, extban, or CIDR."),
		).required("mask").build(),
		Handler: toolExplainMask,
	})

	// --- Admin actions: destructive, IRCop-only -------------------------

	o.registerTool(Tool{
		Name:        "user_kill",
		Description: "Disconnect a user from the network (server-side KILL). The user is told the reason and dropped immediately.",
		Parameters: objectSchema(
			prop("nick", "string", "Nickname of the user to disconnect."),
			prop("reason", "string", "Reason shown to the user and other opers."),
		).required("nick", "reason").build(),
		Handler: toolUserKill,
	})
	o.registerTool(Tool{
		Name:        "channel_kick",
		Description: "Kick a user from a specific channel (channel.kick RPC). User stays connected but leaves that one channel.",
		Parameters: objectSchema(
			prop("channel", "string", "Channel to kick from, including its prefix (e.g. #opers)."),
			prop("nick", "string", "Nickname to kick."),
			prop("reason", "string", "Reason shown in the kick."),
		).required("channel", "nick", "reason").build(),
		Handler: toolChannelKick,
	})
	o.registerTool(Tool{
		Name:        "channel_set_topic",
		Description: "Set the topic of a channel.",
		Parameters: objectSchema(
			prop("channel", "string", "Channel name."),
			prop("topic", "string", "New topic text."),
		).required("channel", "topic").build(),
		Handler: toolChannelSetTopic,
	})
	o.registerTool(Tool{
		Name:        "channel_set_mode",
		Description: "Set channel modes. modes is the IRC mode string (e.g. '+m', '-o'). parameters is the space-joined argument list for modes that take one (e.g. nick for +o), empty string if none.",
		Parameters: objectSchema(
			prop("channel", "string", "Channel name."),
			prop("modes", "string", "Mode string, e.g. '+m' or '+bo'."),
			prop("parameters", "string", "Mode parameters, space-separated, or empty."),
		).required("channel", "modes", "parameters").build(),
		Handler: toolChannelSetMode,
	})
	o.registerTool(Tool{
		Name:        "ban_add",
		Description: "Add a server-side ban. type is one of: gline (network-wide ban), kline (this-server ban), zline (IP ban this server), gzline (IP ban network), shun (silence user), spamfilter. name is the mask (e.g. *@badhost.com). duration uses UnrealIRCd time format (e.g. '1d', '30m', '0' or empty for permanent).",
		Parameters: objectSchema(
			prop("type", "string", "Ban type: gline, kline, zline, gzline, shun, spamfilter."),
			prop("name", "string", "Mask, e.g. *@bad.example.com or nick!*@*."),
			prop("reason", "string", "Reason shown to the banned user and stored in the ban entry."),
			prop("duration", "string", "Duration: '1d', '30m', '2w'. Empty/'0' = permanent."),
		).required("type", "name", "reason").build(),
		Handler: toolBanAdd,
	})
	o.registerTool(Tool{
		Name:        "ban_del",
		Description: "Remove a server-side ban. type + name must match exactly an existing entry from bans_list.",
		Parameters: objectSchema(
			prop("type", "string", "Ban type: gline, kline, zline, gzline, shun, spamfilter."),
			prop("name", "string", "Exact mask of the ban to remove."),
		).required("type", "name").build(),
		Handler: toolBanDel,
	})
	o.registerTool(Tool{
		Name:        "nick_ban_add",
		Description: "Add a nick-name ban (Q-line). Prevents anyone from using that nickname.",
		Parameters: objectSchema(
			prop("name", "string", "Nickname pattern to forbid, e.g. BadNick or evilbot*."),
			prop("reason", "string", "Reason shown to users trying that nick."),
			prop("duration", "string", "Duration: '1d', '30m'. Empty = permanent."),
		).required("name", "reason").build(),
		Handler: toolNickBanAdd,
	})
	o.registerTool(Tool{
		Name:        "nick_ban_del",
		Description: "Remove a nick-name ban (Q-line).",
		Parameters: objectSchema(
			prop("name", "string", "Exact nickname pattern of the Q-line to remove."),
		).required("name").build(),
		Handler: toolNickBanDel,
	})
	o.registerTool(Tool{
		Name:        "server_rehash",
		Description: "Reload the obbyircd configuration (rehash). Equivalent to /REHASH.",
		Parameters:  objectSchema().build(),
		Handler:     toolServerRehash,
	})
	o.registerTool(Tool{
		Name:        "server_list",
		Description: "List linked servers on the network with their basic info.",
		Parameters:  objectSchema().build(),
		Handler:     toolServerList,
	})
	o.registerTool(Tool{
		Name:        "spamfilter_list",
		Description: "List all configured spamfilter rules.",
		Parameters:  objectSchema().build(),
		Handler:     toolSpamfilterList,
	})

	// --- Voice-channel media tools (operator-only, voice-only) ---------

	o.registerTool(Tool{
		Name:        "play_video",
		Description: "Display a video OR a static image by URL on Orca's video feed in a voice channel. Use the same voice channel the user is currently in. Videos play with audio; images are shown looped as a still frame until stop_video is called or the 10-minute cap is hit. Accepts PNG, JPEG, GIF, WebP, and any video format ffmpeg understands. Preempts any previously playing media in the same channel.",
		Parameters: objectSchema(
			prop("channel", "string", "Voice channel to play in (e.g. ^vc-opers). Use the channel the speaker is in."),
			prop("url", "string", "HTTP(S) URL of the video or image to display."),
		).required("channel", "url").build(),
		Handler: toolPlayVideo,
	})
	o.registerTool(Tool{
		Name:        "stop_video",
		Description: "Stop any currently-playing video in a voice channel.",
		Parameters: objectSchema(
			prop("channel", "string", "Voice channel to stop playback in."),
		).required("channel").build(),
		Handler: toolStopVideo,
	})
}

func toolUserGet(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	nick, _ := params["nick"].(string)
	if nick == "" {
		return "", fmt.Errorf("nick required")
	}
	st := w.StartToolCall("user-get", "Look up "+nick, params)
	u, err := newIRCTool(o.irc).UserGet(ctx, nick, 4)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	if u == nil {
		_ = st.Result("not online")
		return "{}  // user not online", nil
	}
	b, _ := json.Marshal(u)
	_ = st.Result(truncate(string(b), 240))
	return string(b), nil
}

func toolUserList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("user-list", "List all users", nil)
	users, err := newIRCTool(o.irc).UserList(ctx, 2)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{
			"nick":    getString(u, "name"),
			"host":    getString(u, "hostname"),
			"ip":      getString(u, "ip"),
			"account": getString(u, "user", "account"),
		})
	}
	b, _ := json.Marshal(out)
	_ = st.Result(fmt.Sprintf("%d users", len(out)))
	return string(b), nil
}

func toolChannelGet(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	if channel == "" {
		return "", fmt.Errorf("channel required")
	}
	st := w.StartToolCall("channel-get", "Look up "+channel, params)
	ch, err := newIRCTool(o.irc).ChannelGet(ctx, channel, 4)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	if ch == nil {
		_ = st.Result("not found")
		return "{}", nil
	}
	b, _ := json.Marshal(ch)
	_ = st.Result(fmt.Sprintf("ok: %d members",
		len(toMapList(ch, "members"))))
	return string(b), nil
}

func toolChannelList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("channel-list", "List all channels", nil)
	chans, err := newIRCTool(o.irc).ChannelList(ctx, 1)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	out := make([]map[string]any, 0, len(chans))
	for _, c := range chans {
		out = append(out, map[string]any{
			"name":  getString(c, "name"),
			"size":  getInt(c, "num_users"),
			"modes": getString(c, "modes"),
		})
	}
	b, _ := json.Marshal(out)
	_ = st.Result(fmt.Sprintf("%d channels", len(out)))
	return string(b), nil
}

func toolBansList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("bans-list", "List server bans", nil)
	bans, err := newIRCTool(o.irc).BansList(ctx)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	b, _ := json.Marshal(bans)
	_ = st.Result(fmt.Sprintf("%d bans", len(bans)))
	return string(b), nil
}

func toolStats(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("stats", "Server stats", nil)
	s, err := newIRCTool(o.irc).Stats(ctx)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	b, _ := json.Marshal(s)
	_ = st.Result("ok")
	return string(b), nil
}

func toolExplainMask(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	maskStr, _ := params["mask"].(string)
	if maskStr == "" {
		return "", fmt.Errorf("mask required")
	}
	st := w.StartToolCall("explain-mask", "Walk users vs mask", params)
	parsed := parseMask(maskStr)
	if parsed.kind == maskUnknown {
		_ = st.Failed("unparseable")
		return `{"error":"could not parse mask"}`, nil
	}
	users, err := newIRCTool(o.irc).UserList(ctx, 2)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	matched := []string{}
	for _, u := range users {
		if parsed.matches(u) {
			matched = append(matched, getString(u, "name"))
		}
	}
	res := map[string]any{
		"mask":     maskStr,
		"kind":     parsed.describe(),
		"scanned":  len(users),
		"matches":  len(matched),
		"matched":  matched,
	}
	b, _ := json.Marshal(res)
	_ = st.Result(fmt.Sprintf("%d/%d matched", len(matched), len(users)))
	return string(b), nil
}

// --- Admin tool handlers ------------------------------------------------

func toolUserKill(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	nick, _ := params["nick"].(string)
	reason, _ := params["reason"].(string)
	if nick == "" || reason == "" {
		return "", fmt.Errorf("nick and reason required")
	}
	st := w.StartToolCall("user-kill", "KILL "+nick, params)
	if err := newIRCTool(o.irc).UserKill(ctx, nick, reason); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("killed " + nick)
	return fmt.Sprintf(`{"ok":true,"killed":%q,"reason":%q}`, nick, reason), nil
}

func toolChannelKick(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	nick, _ := params["nick"].(string)
	reason, _ := params["reason"].(string)
	if channel == "" || nick == "" || reason == "" {
		return "", fmt.Errorf("channel, nick, reason required")
	}
	st := w.StartToolCall("channel-kick", fmt.Sprintf("KICK %s from %s", nick, channel), params)
	if err := newIRCTool(o.irc).ChannelKick(ctx, channel, nick, reason); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result(fmt.Sprintf("kicked %s from %s", nick, channel))
	return fmt.Sprintf(`{"ok":true,"channel":%q,"kicked":%q}`, channel, nick), nil
}

func toolChannelSetTopic(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	topic, _ := params["topic"].(string)
	if channel == "" {
		return "", fmt.Errorf("channel required")
	}
	st := w.StartToolCall("channel-set-topic", "TOPIC "+channel, params)
	if err := newIRCTool(o.irc).ChannelSetTopic(ctx, channel, topic); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("topic set")
	return fmt.Sprintf(`{"ok":true,"channel":%q}`, channel), nil
}

func toolChannelSetMode(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	modes, _ := params["modes"].(string)
	parameters, _ := params["parameters"].(string)
	if channel == "" || modes == "" {
		return "", fmt.Errorf("channel and modes required")
	}
	st := w.StartToolCall("channel-set-mode", fmt.Sprintf("MODE %s %s %s", channel, modes, parameters), params)
	if err := newIRCTool(o.irc).ChannelSetMode(ctx, channel, modes, parameters); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("mode applied")
	return fmt.Sprintf(`{"ok":true,"channel":%q,"modes":%q}`, channel, modes), nil
}

func toolBanAdd(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	banType, _ := params["type"].(string)
	name, _ := params["name"].(string)
	reason, _ := params["reason"].(string)
	duration, _ := params["duration"].(string)
	if banType == "" || name == "" || reason == "" {
		return "", fmt.Errorf("type, name, reason required")
	}
	st := w.StartToolCall("ban-add", fmt.Sprintf("%s %s", banType, name), params)
	if err := newIRCTool(o.irc).BanAdd(ctx, banType, name, reason, duration); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	dur := duration
	if dur == "" {
		dur = "permanent"
	}
	_ = st.Result(fmt.Sprintf("%s %s (%s)", banType, name, dur))
	return fmt.Sprintf(`{"ok":true,"type":%q,"name":%q,"duration":%q}`, banType, name, dur), nil
}

func toolBanDel(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	banType, _ := params["type"].(string)
	name, _ := params["name"].(string)
	if banType == "" || name == "" {
		return "", fmt.Errorf("type and name required")
	}
	st := w.StartToolCall("ban-del", fmt.Sprintf("%s %s", banType, name), params)
	if err := newIRCTool(o.irc).BanDel(ctx, banType, name); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("removed " + name)
	return fmt.Sprintf(`{"ok":true,"removed":%q}`, name), nil
}

func toolNickBanAdd(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	name, _ := params["name"].(string)
	reason, _ := params["reason"].(string)
	duration, _ := params["duration"].(string)
	if name == "" || reason == "" {
		return "", fmt.Errorf("name and reason required")
	}
	st := w.StartToolCall("nick-ban-add", name, params)
	if err := newIRCTool(o.irc).NickBanAdd(ctx, name, reason, duration); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("Q-lined " + name)
	return fmt.Sprintf(`{"ok":true,"name":%q}`, name), nil
}

func toolNickBanDel(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	name, _ := params["name"].(string)
	if name == "" {
		return "", fmt.Errorf("name required")
	}
	st := w.StartToolCall("nick-ban-del", name, params)
	if err := newIRCTool(o.irc).NickBanDel(ctx, name); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("removed " + name)
	return fmt.Sprintf(`{"ok":true,"removed":%q}`, name), nil
}

func toolServerRehash(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("server-rehash", "/REHASH", nil)
	if err := newIRCTool(o.irc).ServerRehash(ctx); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("rehashed")
	return `{"ok":true}`, nil
}

func toolServerList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("server-list", "Linked servers", nil)
	servers, err := newIRCTool(o.irc).ServerList(ctx)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	b, _ := json.Marshal(servers)
	_ = st.Result(fmt.Sprintf("%d servers", len(servers)))
	return string(b), nil
}

func toolPlayVideo(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	url, _ := params["url"].(string)
	if channel == "" || url == "" {
		return "", fmt.Errorf("channel and url required")
	}
	if o.voice == nil {
		return "", fmt.Errorf("voice subsystem not running")
	}
	st := w.StartToolCall("play-video", "Play "+url+" in "+channel, params)
	// Use a background context so the playback survives the
	// invocation's own context cancelling when the LLM round-trip
	// finishes -- the player has its own duration cap and explicit
	// stop tool.
	if err := o.voice.playVideo(context.Background(), channel, url); err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	_ = st.Result("playing " + url)
	return fmt.Sprintf(`{"ok":true,"channel":%q,"url":%q,"note":"playback started; auto-stops after 10 min or on stop_video"}`, channel, url), nil
}

func toolStopVideo(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	if channel == "" {
		return "", fmt.Errorf("channel required")
	}
	if o.voice == nil {
		return "", fmt.Errorf("voice subsystem not running")
	}
	st := w.StartToolCall("stop-video", "Stop video in "+channel, params)
	stopped := o.voice.stopVideo(channel)
	if stopped {
		_ = st.Result("stopped")
		return fmt.Sprintf(`{"ok":true,"channel":%q,"stopped":true}`, channel), nil
	}
	_ = st.Result("nothing playing")
	return fmt.Sprintf(`{"ok":true,"channel":%q,"stopped":false,"note":"no active playback"}`, channel), nil
}

func toolSpamfilterList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("spamfilter-list", "Spamfilter rules", nil)
	rules, err := newIRCTool(o.irc).SpamfilterList(ctx)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	b, _ := json.Marshal(rules)
	_ = st.Result(fmt.Sprintf("%d rules", len(rules)))
	return string(b), nil
}

// objectSchema is a tiny builder for OpenAI-style function parameter JSON Schema.
type schemaBuilder struct {
	props      map[string]any
	requireds  []string
}

func objectSchema(props ...map[string]any) *schemaBuilder {
	b := &schemaBuilder{props: map[string]any{}}
	for _, p := range props {
		for k, v := range p {
			b.props[k] = v
		}
	}
	return b
}

func prop(name, jsonType, desc string) map[string]any {
	return map[string]any{
		name: map[string]any{"type": jsonType, "description": desc},
	}
}

func (b *schemaBuilder) required(names ...string) *schemaBuilder {
	b.requireds = append(b.requireds, names...)
	return b
}

func (b *schemaBuilder) build() map[string]any {
	out := map[string]any{
		"type":       "object",
		"properties": b.props,
	}
	if len(b.requireds) > 0 {
		out["required"] = b.requireds
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func toolNameList(m map[string]Tool) string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}
