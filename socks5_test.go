package wireproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Exercise the production server options, real SOCKS5 negotiation and a UDP
// echo target that exists only inside the tunnel netstack. An accidental
// net.Dial fallback cannot reach it. The returned relay must bind to loopback.
func TestSocks5UDPUsesTunnelAndLoopbackRelay(t *testing.T) {
	for _, mode := range []string{"default", "log-only", "matching-rule"} {
		t.Run(mode, func(t *testing.T) {
			tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil, 1420)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tun.Close() }()
			echo, err := tnet.ListenUDPAddrPort(netip.MustParseAddrPort("192.0.2.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = echo.Close() }()
			cfg := &Socks5Config{LogDomains: mode == "log-only"}
			if mode == "matching-rule" {
				cfg.TunnelDomains = mustCompile(t, `^192\.0\.2\.1$`)
			}
			server := cfg.newServer(&VirtualTun{Tnet: tnet})
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					_ = server.ServeConn(conn)
				}
			}()
			control, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = control.Close() }()
			_ = control.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := control.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			auth := make([]byte, 2)
			if _, err := io.ReadFull(control, auth); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(auth, []byte{5, 0}) {
				t.Fatalf("auth reply: %v", auth)
			}
			if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 10)
			if _, err := io.ReadFull(control, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
				t.Fatalf("associate reply: %v", reply)
			}
			relayIP := net.IP(reply[4:8])
			if !relayIP.Equal(net.ParseIP("127.0.0.1")) {
				t.Fatalf("relay must bind to loopback, got %s", relayIP)
			}
			relay, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: relayIP, Port: int(binary.BigEndian.Uint16(reply[8:]))})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = relay.Close() }()
			packet := []byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 0}
			binary.BigEndian.PutUint16(packet[8:], uint16(echo.LocalAddr().(*net.UDPAddr).Port))
			packet = append(packet, []byte("tunnel probe")...)
			if _, err := relay.Write(packet); err != nil {
				t.Fatal(err)
			}
			_ = echo.SetReadDeadline(time.Now().Add(3 * time.Second))
			payload := make([]byte, 128)
			n, addr, err := echo.ReadFrom(payload)
			if err != nil {
				t.Fatalf("UDP did not reach tunnel target: %v", err)
			}
			if !bytes.Equal(payload[:n], []byte("tunnel probe")) {
				t.Fatalf("unexpected tunnel payload: %q", payload[:n])
			}
			if _, err := echo.WriteTo(payload[:n], addr); err != nil {
				t.Fatal(err)
			}
			_ = relay.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err = relay.Read(payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(payload[:n], []byte("tunnel probe")) {
				t.Fatalf("unexpected relay response: %q", payload[:n])
			}
		})
	}
}
