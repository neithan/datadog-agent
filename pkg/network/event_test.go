package network

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

var (
	testConn = ConnectionStats{
		Pid:                123,
		Type:               1,
		Source:             netaddr.MustParseIP("192.168.0.1"),
		Dest:               netaddr.MustParseIP("192.168.0.103"),
		SPort:              123,
		DPort:              35000,
		MonotonicSentBytes: 123123,
		MonotonicRecvBytes: 312312,
	}
)

func TestBeautifyKey(t *testing.T) {
	buf := make([]byte, ConnectionByteKeyMaxLen)
	for _, c := range []ConnectionStats{
		testConn,
		{
			Pid:    345,
			Type:   0,
			Source: netaddr.MustParseIP("::7f00:35:0:1"),
			Dest:   netaddr.MustParseIP("2001:db8::2:1"),
			SPort:  4444,
			DPort:  8888,
		},
		{
			Pid:       32065,
			Type:      0,
			Direction: 2,
			Source:    netaddr.MustParseIP("172.21.148.124"),
			Dest:      netaddr.MustParseIP("130.211.21.187"),
			SPort:     52012,
			DPort:     443,
		},
	} {
		bk, err := c.ByteKey(buf)
		require.NoError(t, err)
		family := AFINET
		if c.Source.Is6() {
			family = AFINET6
		}

		expected := fmt.Sprintf(keyFmt, c.Pid, c.Source.String(), c.SPort, c.Dest.String(), c.DPort, family, c.Type)
		assert.Equal(t, expected, BeautifyKey(string(bk)))
	}
}

func TestConnStatsByteKey(t *testing.T) {
	buf := make([]byte, ConnectionByteKeyMaxLen)
	addrA := netaddr.MustParseIP("127.0.0.1")
	addrB := netaddr.MustParseIP("127.0.0.2")

	for _, test := range []struct {
		a ConnectionStats
		b ConnectionStats
	}{
		{ // Port is different
			a: ConnectionStats{Source: addrA, Dest: addrB, Pid: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Type is different
			a: ConnectionStats{Source: addrA, Dest: addrB, Type: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Source is different
			a: ConnectionStats{Source: netaddr.MustParseIP("123.255.123.0"), Dest: addrB},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Dest is different
			a: ConnectionStats{Source: addrA, Dest: netaddr.MustParseIP("129.0.1.2")},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Source port is different
			a: ConnectionStats{Source: addrA, Dest: addrB, SPort: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Dest port is different
			a: ConnectionStats{Source: addrA, Dest: addrB, DPort: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Fields set, but sources are different
			a: ConnectionStats{Pid: 1, Type: 1, Source: addrA, Dest: addrB},
			b: ConnectionStats{Pid: 1, Type: 1, Source: addrB, Dest: addrB},
		},
		{ // Both sources and dest are different
			a: ConnectionStats{Pid: 1, Dest: addrB, Type: 1, Source: addrA},
			b: ConnectionStats{Pid: 1, Dest: addrA, Type: 1, Source: addrB},
		},
		{ // Type are different
			a: ConnectionStats{Pid: 1, Source: addrA, Dest: addrB},
			b: ConnectionStats{Pid: 1, Source: addrA, Dest: addrB, Type: 1},
		},
	} {
		var keyA, keyB string
		if b, err := test.a.ByteKey(buf); assert.NoError(t, err) {
			keyA = string(b)
		}
		if b, err := test.b.ByteKey(buf); assert.NoError(t, err) {
			keyB = string(b)
		}
		assert.NotEqual(t, keyA, keyB)
	}
}

func TestIsExpired(t *testing.T) {
	// 10mn
	var timeout uint64 = 600000000000
	for _, tc := range []struct {
		stats      ConnectionStats
		latestTime uint64
		expected   bool
	}{
		{
			ConnectionStats{LastUpdateEpoch: 101},
			100,
			false,
		},
		{
			ConnectionStats{LastUpdateEpoch: 100},
			101,
			false,
		},
		{
			ConnectionStats{LastUpdateEpoch: 100},
			101 + timeout,
			true,
		},
	} {
		assert.Equal(t, tc.expected, tc.stats.IsExpired(tc.latestTime, timeout))
	}
}

func BenchmarkByteKey(b *testing.B) {
	buf := make([]byte, ConnectionByteKeyMaxLen)
	addrA := netaddr.MustParseIP("127.0.0.1")
	addrB := netaddr.MustParseIP("127.0.0.2")
	c := ConnectionStats{Pid: 1, Dest: addrB, Type: 1, Source: addrA}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.ByteKey(buf)
	}
	runtime.KeepAlive(buf)
}
