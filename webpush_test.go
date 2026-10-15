package main

import (
	"net"
	"net/http"
	"net/http/httptest"
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
