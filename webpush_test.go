package main

import (
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
