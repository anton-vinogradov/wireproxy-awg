package wireproxy

import (
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Given a tunnel with saved input and output pipes, when a TCP peer exchanges
// data, then both directions use those pipes instead of process-wide stdio.
func TestSTDIOTunnelUsesConfiguredStreams(t *testing.T) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	listener, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = inputWriter.Close() })
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outputReader.Close(); _ = output.Close() })
	conf := &STDIOTunnelConfig{Target: listener.Addr().String(), Input: input, Output: output}
	conf.SpawnRoutine(&VirtualTun{Tnet: tnet})
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- peer
	}()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case err := <-acceptError:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not connect to peer")
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := inputWriter.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(peer, request); err != nil {
		t.Fatalf("configured input did not reach peer: %v", err)
	}
	if string(request) != "request" {
		t.Fatalf("peer received %q", request)
	}
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := outputReader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("response"))
	if _, err := io.ReadFull(outputReader, response); err != nil {
		t.Fatalf("peer response did not reach configured output: %v", err)
	}
	if string(response) != "response" {
		t.Fatalf("configured output received %q", response)
	}
}
