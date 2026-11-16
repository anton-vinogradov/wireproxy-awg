package wireproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/dns/dnsmessage"
)

// Given a local DNS server, use the real system resolver against its UDP replies.
// When a name is queried, return the advertised A/AAAA records or NXDOMAIN.
// Then resolver tests need no external DNS service or fabricated lookup result.
func useResolveTestDNS(t *testing.T) {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveResolveTestDNS(t, listener)
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp4", listener.LocalAddr().String())
		},
	}
	t.Cleanup(func() { net.DefaultResolver = previous })
}

// Given a UDP listener, answer dual.test, v4.test and v6.test with real DNS packets.
// When another name is queried, return NXDOMAIN so the resolver produces its error.
// Then tests exercise DNS parsing, family selection and lookup failures together.
func serveResolveTestDNS(t *testing.T, listener net.PacketConn) {
	t.Helper()
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		packet := make([]byte, 2048)
		for {
			n, client, err := listener.ReadFrom(packet)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(packet[:n]); err != nil {
				t.Error(err)
				return
			}
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true},
				Questions: query.Questions,
			}
			for _, question := range query.Questions {
				header := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET}
				host := question.Name.String()
				if host != "dual.test." && host != "v4.test." && host != "v6.test." {
					response.RCode = dnsmessage.RCodeNameError
					continue
				}
				if question.Type == dnsmessage.TypeA && host != "v6.test." {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: header, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
					})
				}
				if question.Type == dnsmessage.TypeAAAA && host != "v4.test." {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: header, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()},
					})
				}
			}
			payload, err := response.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := listener.WriteTo(payload, client); err != nil {
				return
			}
		}
	}()
}

// Given both A and AAAA records and the configured tunnel addresses,
// When resolving a host repeatedly, Then every choice follows ResolveStrategy.
func TestResolveAddrPrefersConfiguredFamily(t *testing.T) {
	useResolveTestDNS(t)
	for _, test := range []struct {
		name      string
		strategy  string
		addresses []netip.Addr
		wantIPv4  bool
	}{
		{name: "ipv4", strategy: "ipv4", wantIPv4: true},
		{name: "ipv6", strategy: "ipv6"},
		{name: "auto IPv4 only", strategy: "auto", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, wantIPv4: true},
		{name: "auto IPv6 only", strategy: "auto", addresses: []netip.Addr{netip.MustParseAddr("2001:db8::2")}},
		{name: "auto dual stack", strategy: "auto", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}},
		{name: "default IPv4 only", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, wantIPv4: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			vt := VirtualTun{
				SystemDNS:     true,
				Conf:          &DeviceConfig{Endpoint: test.addresses},
				ResolveConfig: &ResolveConfig{ResolveStrategy: test.strategy},
			}
			if test.strategy == "" {
				vt.ResolveConfig = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for range 32 {
				addr, err := vt.ResolveAddrWithContext(ctx, "dual.test")
				if err != nil {
					t.Fatal(err)
				}
				if addr.Is4() != test.wantIPv4 {
					t.Fatalf("resolved %s with strategy %s", addr, test.strategy)
				}
			}
		})
	}
}

// Given only records from the other family, When resolving with a preference,
// Then the available address remains usable instead of causing an error.
func TestResolveAddrFallsBackToAvailableFamily(t *testing.T) {
	useResolveTestDNS(t)
	for _, test := range []struct {
		strategy, host, want string
	}{
		{strategy: "ipv4", host: "v6.test", want: "2001:db8::1"},
		{strategy: "ipv6", host: "v4.test", want: "192.0.2.1"},
	} {
		t.Run(test.strategy, func(t *testing.T) {
			vt := VirtualTun{SystemDNS: true, ResolveConfig: &ResolveConfig{ResolveStrategy: test.strategy}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			addr, err := vt.ResolveAddrWithContext(ctx, test.host)
			if err != nil {
				t.Fatal(err)
			}
			if addr.String() != test.want {
				t.Fatalf("resolved %s, want %s", addr, test.want)
			}
		})
	}
}

// Given a DNS NXDOMAIN response, When resolving the absent host,
// Then the caller receives the resolver's not-found error.
func TestResolveAddrPreservesDNSError(t *testing.T) {
	useResolveTestDNS(t)
	vt := VirtualTun{SystemDNS: true, ResolveConfig: &ResolveConfig{ResolveStrategy: "ipv4"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := vt.ResolveAddrWithContext(ctx, "missing.test")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("expected DNS not-found error, got %v", err)
	}
}

// Given DNS reachable only inside netstack and both address families,
// When resolving with ipv4, Then tunnel DNS supplies the preferred A record.
func TestResolveAddrUsesTunnelDNS(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	tun, tnet, err := netstack.CreateNetTUN(addresses, addresses[:1], 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	listener, err := tnet.ListenUDPAddrPort(netip.MustParseAddrPort("192.0.2.53:53"))
	if err != nil {
		t.Fatal(err)
	}
	serveResolveTestDNS(t, listener)
	vt := VirtualTun{Tnet: tnet, Conf: &DeviceConfig{Endpoint: addresses}, ResolveConfig: &ResolveConfig{ResolveStrategy: "ipv4"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 32 {
		addr, err := vt.ResolveAddrWithContext(ctx, "dual.test")
		if err != nil {
			t.Fatal(err)
		}
		if !addr.Is4() {
			t.Fatalf("resolved %s through tunnel DNS, want IPv4", addr)
		}
	}
}
