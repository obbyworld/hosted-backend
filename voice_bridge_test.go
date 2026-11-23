package main

import (
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func chunk(id string, seq, total int, sdp string) signalEnvelope {
	return signalEnvelope{Type: "offer", ChunkID: id, Seq: &seq, Total: &total, SDP: sdp}
}

func TestChunkedSDPReassemblesOutOfOrder(t *testing.T) {
	b := newVoiceBridge(VoiceConfig{}, nil)
	if b.assembleChunk("alice", chunk("x", 2, 3, "c")) != nil {
		t.Fatal("finished after one chunk")
	}
	if b.assembleChunk("alice", chunk("x", 0, 3, "a")) != nil {
		t.Fatal("finished after two chunks")
	}
	env := b.assembleChunk("alice", chunk("x", 1, 3, "b"))
	if env == nil || env.SDP != "abc" || env.Total != nil || len(b.chunkBuf) != 0 {
		t.Fatalf("got %+v, %d open buffers", env, len(b.chunkBuf))
	}
}

func TestChunkWithAHugeTotalIsRefusedWithoutAllocating(t *testing.T) {
	b := newVoiceBridge(VoiceConfig{}, nil)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	env := b.assembleChunk("mallory", chunk("x", 0, 1<<20, "a"))
	runtime.ReadMemStats(&after)
	if env != nil || len(b.chunkBuf) != 0 {
		t.Fatalf("accepted the chunk: %+v", env)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("allocated %d bytes", grew)
	}
}

func TestOpenChunkBuffersAreCappedPerSender(t *testing.T) {
	b := newVoiceBridge(VoiceConfig{}, nil)
	for i := range maxOpenChunksPerPeer + 3 {
		b.assembleChunk("mallory", chunk(strconv.Itoa(i), 0, 2, "a"))
	}
	if n := len(b.chunkBuf["mallory"]); n != maxOpenChunksPerPeer {
		t.Fatalf("%d open buffers, want %d", n, maxOpenChunksPerPeer)
	}
	if b.assembleChunk("alice", chunk("x", 0, 1, "a")) == nil {
		t.Fatal("another sender was blocked")
	}
}

func bridgeAt(clock *time.Time) *voiceBridge {
	b := newVoiceBridge(VoiceConfig{}, nil)
	b.now = func() time.Time { return *clock }
	return b
}

func TestSlowChunksStillReassemble(t *testing.T) {
	start := time.Now()
	clock := start
	b := bridgeAt(&clock)
	b.assembleChunk("alice", chunk("x", 0, 3, "a"))
	clock = start.Add(100 * time.Second)
	b.assembleChunk("alice", chunk("x", 1, 3, "b"))
	clock = start.Add(125 * time.Second)
	env := b.assembleChunk("alice", chunk("x", 2, 3, "c"))
	if env == nil || env.SDP != "abc" {
		t.Fatalf("got %+v", env)
	}
}

func TestIdleChunkBuffersExpire(t *testing.T) {
	clock := time.Now()
	b := bridgeAt(&clock)
	b.assembleChunk("mallory", chunk("old", 0, 2, "a"))
	clock = clock.Add(chunkIdleTimeout + time.Second)
	b.assembleChunk("alice", chunk("new", 0, 2, "a"))
	if _, ok := b.chunkBuf["mallory"]; ok {
		t.Fatal("idle buffer kept")
	}
}

func TestTURNRelaysOnlyToPublicPeersAndTheSFU(t *testing.T) {
	allowed := turnPeerFilter("192.168.1.20")
	for _, ip := range []string{
		"127.0.0.1", "::1", "10.0.0.5", "172.18.0.2", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "fd00::1", "fe80::1", "0.0.0.0", "::", "::ffff:10.0.0.1", "224.0.0.1",
	} {
		if allowed(nil, net.ParseIP(ip)) {
			t.Errorf("relay to %s allowed", ip)
		}
	}
	for _, ip := range []string{"142.250.74.106", "192.168.1.20"} {
		if !allowed(nil, net.ParseIP(ip)) {
			t.Errorf("relay to %s refused", ip)
		}
	}
	if turnPeerFilter("")(nil, net.ParseIP("0.0.0.0")) {
		t.Error("an unset SFU address allowed 0.0.0.0")
	}
}
