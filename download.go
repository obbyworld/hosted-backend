package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

var errDownloadTooLarge = errors.New("download exceeds the configured size limit")

// Clients choose the address we download from, so we dial only public hosts,
// on every redirect too.
var downloadHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
			Control: refuseInternalAddress,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	},
}

func downloadPublicURL(rawURL string, limit int64) ([]byte, error) {
	target, err := url.Parse(rawURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, errors.New("only http and https URLs can be downloaded")
	}
	resp, err := downloadHTTPClient.Get(target.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errDownloadTooLarge
	}
	return data, nil
}
