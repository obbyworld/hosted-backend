package main

// Web Push (RFC 8030 / 8291 / 8292) sender for the soju.im/webpush
// IRCv3 extension.
//
// obbyircd owns the IRC-protocol half: the soju.im/webpush capability,
// the WEBPUSH REGISTER/UNREGISTER commands, the per-account subscription
// store, and the decision of *when* a push should fire.  It does NOT do
// the encryption itself -- obbyircd's outbound HTTP path is strlen-based
// and would truncate the aes128gcm ciphertext at its first NUL byte.
//
// So obbyircd POSTs a small JSON blob (the subscription + the plaintext
// IRC line) to this backend, which owns the VAPID keypair and does the
// RFC 8291 encryption + delivery via webpush-go.  The VAPID public key
// is exposed at /push/vapid-key so obbyircd can advertise it in the
// VAPID= ISUPPORT token at startup.

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

var (
	vapidPrivateKey string
	vapidPublicKey  string
	vapidSubject    string
)

type vapidKeyfile struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

// vapidKeyPath returns where the VAPID keypair is persisted.  Defaults
// to data/vapid.json, the directory the stack mounts as a volume, so the
// key survives a redeploy; override with VAPID_KEY_FILE.
func vapidKeyPath() string {
	if p := os.Getenv("VAPID_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join("data", "vapid.json")
}

// InitWebPush loads the VAPID keypair from disk, generating and
// persisting a fresh one on first run.  The keypair must be stable
// across restarts: the public half is baked into every client's push
// subscription, so regenerating it would silently invalidate every
// existing subscription.
func InitWebPush() error {
	path := vapidKeyPath()
	if data, err := os.ReadFile(path); err == nil {
		var k vapidKeyfile
		if json.Unmarshal(data, &k) == nil && k.Private != "" && k.Public != "" {
			vapidPrivateKey = k.Private
			vapidPublicKey = k.Public
		}
	}

	if vapidPrivateKey == "" || vapidPublicKey == "" {
		priv, pub, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			return err
		}
		vapidPrivateKey, vapidPublicKey = priv, pub
		b, _ := json.MarshalIndent(vapidKeyfile{Private: priv, Public: pub}, "", "  ")
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			log.Printf("webpush: WARNING could not persist VAPID keys to %s: %v", path, err)
			log.Printf("webpush: keys are in-memory only; a restart will invalidate all subscriptions")
		} else {
			log.Printf("webpush: generated new VAPID keypair -> %s", path)
		}
	}

	// VAPID 'sub' claim: a mailto: or https URL identifying the sender,
	// shown to push services for abuse contact.
	vapidSubject = os.Getenv("VAPID_SUBJECT")
	if vapidSubject == "" {
		vapidSubject = "mailto:admin@obby.t3ks.com"
	}
	log.Printf("webpush: ready (VAPID public key %s…)", truncForLog(vapidPublicKey, 12))
	return nil
}

func truncForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// handleVapidKey serves the VAPID public key.  The public key is, by
// design, non-secret -- clients embed it in their PushManager
// subscription and obbyircd advertises it in ISUPPORT -- so this needs
// no auth.
func handleVapidKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": vapidPublicKey})
}

// pushSendRequest is the JSON obbyircd POSTs to /push/send.
type pushSendRequest struct {
	Endpoint string `json:"endpoint"`
	P256dh   string `json:"p256dh"`
	Auth     string `json:"auth"`
	Payload  string `json:"payload"`
	TTL      int    `json:"ttl"`
}

// handlePushSend encrypts `payload` for the given subscription and
// delivers it to the push service.  Guarded by ServerAuthMiddleware
// (X-ObsidianIRC-Key) -- only obbyircd should reach this.
//
// The push service's HTTP status is relayed back in the response so
// obbyircd can prune dead subscriptions when it sees 404/410 (RFC 8030
// "subscription expired or no longer valid").
func handlePushSend(w http.ResponseWriter, r *http.Request) {
	var req pushSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Endpoint == "" || req.P256dh == "" || req.Auth == "" {
		http.Error(w, "missing subscription fields", http.StatusBadRequest)
		return
	}
	if !isPushEndpointURL(req.Endpoint) {
		replyEndpointGone(w, "endpoint must be an https URL")
		return
	}

	sub := &webpush.Subscription{
		Endpoint: req.Endpoint,
		Keys: webpush.Keys{
			P256dh: req.P256dh,
			Auth:   req.Auth,
		},
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 86400 // 1 day; push services hold the message this long if the device is offline
	}

	resp, err := webpush.SendNotification([]byte(req.Payload), sub, &webpush.Options{
		Subscriber:      vapidSubject,
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             ttl,
		HTTPClient:      pushHTTPClient,
	})
	if err != nil {
		log.Printf("webpush: send error to %s: %v", truncForLog(req.Endpoint, 48), err)
		if errors.Is(err, errInternalAddress) {
			replyEndpointGone(w, "endpoint resolves to an internal address")
			return
		}
		http.Error(w, "send failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("webpush: delivered to %s -> push service status %d",
		truncForLog(req.Endpoint, 48), resp.StatusCode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"status": resp.StatusCode})
}

// Any logged-in IRC user can register an endpoint, so we only ever POST to
// public HTTPS hosts, checked on the address we actually connect to so a
// DNS answer cannot point us at an internal service.
var pushHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
			Control: refuseInternalAddress,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var errInternalAddress = errors.New("push endpoint resolves to an internal address")

func refuseInternalAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !isPublicIP(ip) {
		return errInternalAddress
	}
	return nil
}

var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		sharedAddressSpace.Contains(ip))
}

func isPushEndpointURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}

// We report an endpoint that will never work as a 410 from the push service,
// inside a 200 because obbyircd only reads the body of a 200, so it drops the
// subscription.
func replyEndpointGone(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": http.StatusGone, "error": reason})
}
