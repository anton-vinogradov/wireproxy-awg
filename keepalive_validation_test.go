package wireproxy

import (
	"strconv"
	"strings"
	"testing"
)

func TestCreateIPCRequestRejectsInvalidProgrammaticKeepalive(t *testing.T) {
	tests := []struct {
		name string
		peer PeerConfig
	}{
		{name: "negative minimum", peer: PeerConfig{KeepAlive: -1}},
		{name: "negative maximum", peer: PeerConfig{KeepAlive: 1, KeepAliveMax: -1}},
	}
	if strconv.IntSize == 64 {
		tooLargeUint32 := uint64(1) << 32
		tests = append(tests,
			struct {
				name string
				peer PeerConfig
			}{name: "minimum exceeds uint32", peer: PeerConfig{KeepAlive: int(tooLargeUint32)}},
			struct {
				name string
				peer PeerConfig
			}{name: "maximum exceeds uint32", peer: PeerConfig{KeepAlive: 1, KeepAliveMax: int(tooLargeUint32)}},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CreateIPCRequest(&DeviceConfig{Peers: []PeerConfig{tt.peer}}); err == nil {
				t.Fatal("expected invalid PersistentKeepalive error")
			}
		})
	}
}

func TestParsedKeepaliveAllowsProgrammaticChange(t *testing.T) {
	iniData, err := loadIniConfig(`[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15-25
`)
	if err != nil {
		t.Fatal(err)
	}
	var peers []PeerConfig
	if err := ParsePeers(iniData, &peers); err != nil {
		t.Fatal(err)
	}
	peers[0].KeepAlive, peers[0].KeepAliveMax = 30, 40
	setting, err := CreateIPCRequest(&DeviceConfig{Peers: peers})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(setting.IpcRequest, "persistent_keepalive_interval=30-40\n") {
		t.Fatal("parsed values overrode the caller's keepalive change")
	}
	peers[0].KeepAlive = -1
	if _, err := CreateIPCRequest(&DeviceConfig{Peers: peers}); err == nil {
		t.Fatal("parsed values bypassed validation of the caller's invalid change")
	}
}
