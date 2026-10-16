package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPushEndpointMustBeHTTPS(t *testing.T) {
	for _, endpoint := range []string{
		"http://push.example.com/abc",
		"ftp://push.example.com/abc",
		"https://user:pass@push.example.com/abc",
		"not a url",
	} {
		if isPushEndpointURL(endpoint) {
			t.Errorf("accepted %q", endpoint)
		}
	}
	if !isPushEndpointURL("https://fcm.googleapis.com/fcm/send/abc") {
		t.Error("refused a real push service endpoint")
	}
}

func TestPushRefusesInternalAddresses(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:443", "[::1]:443", "10.1.2.3:443", "172.22.0.4:443",
		"192.168.1.10:443", "169.254.169.254:80", "100.64.0.1:443", "0.0.0.0:443",
	} {
		if refuseInternalAddress("tcp", address, nil) == nil {
			t.Errorf("allowed %s", address)
		}
	}
	if err := refuseInternalAddress("tcp", net.JoinHostPort("142.250.74.106", "443"), nil); err != nil {
		t.Errorf("refused a public address: %v", err)
	}
}

func TestPushSendRejectsAPlainHTTPEndpoint(t *testing.T) {
	body := `{"endpoint":"http://obbyircd:8600/","p256dh":"a","auth":"b","payload":"x"}`
	recorder := httptest.NewRecorder()
	handlePushSend(recorder, httptest.NewRequest(http.MethodPost, "/push/send", strings.NewReader(body)))
	if !strings.Contains(recorder.Body.String(), `"status":410`) {
		t.Fatalf("body %s, want the endpoint reported gone", recorder.Body.String())
	}
}

func TestInitWebPushKeepsAnUnreadableKeyfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vapid.json")
	if err := os.WriteFile(path, []byte(`{"priv`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAPID_KEY_FILE", path)
	if err := InitWebPush(); err == nil {
		t.Fatal("started with a truncated keyfile")
	}
	if data, _ := os.ReadFile(path); string(data) != `{"priv` {
		t.Errorf("overwrote the keyfile with %q", data)
	}
}

func TestInitWebPushPersistsANewKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "vapid.json")
	t.Setenv("VAPID_KEY_FILE", path)
	if err := InitWebPush(); err != nil {
		t.Fatal(err)
	}
	first := vapidPublicKey
	if err := InitWebPush(); err != nil {
		t.Fatal(err)
	}
	if vapidPublicKey != first {
		t.Error("generated a second key instead of loading the saved one")
	}
}

type recordingTransport struct{ request *http.Request }

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.request = request
	return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestPushSendAsksForHighUrgency(t *testing.T) {
	t.Setenv("VAPID_KEY_FILE", filepath.Join(t.TempDir(), "vapid.json"))
	if err := InitWebPush(); err != nil {
		t.Fatal(err)
	}
	transport := &recordingTransport{}
	saved := pushHTTPClient
	pushHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { pushHTTPClient = saved })

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	body := `{"endpoint":"https://fcm.googleapis.com/fcm/send/abc","p256dh":"` +
		encode(key.PublicKey().Bytes()) + `","auth":"` + encode(make([]byte, 16)) + `","payload":"x"}`
	recorder := httptest.NewRecorder()
	handlePushSend(recorder, httptest.NewRequest(http.MethodPost, "/push/send", strings.NewReader(body)))

	if transport.request == nil {
		t.Fatalf("sent nothing, answered %s", recorder.Body.String())
	}
	if urgency := transport.request.Header.Get("Urgency"); urgency != "high" {
		t.Errorf("Urgency %q, want high", urgency)
	}
}
