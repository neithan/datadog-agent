// +build linux_bpf
// +build !android

package netlink

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/network/netlink/testutil"
	nettestutil "github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	ct "github.com/florianl/go-conntrack"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestConntrackExists(t *testing.T) {
	srvPort, natPort := nettestutil.RandomPortPair()

	defer testutil.TeardownCrossNsDNAT(t)
	testutil.SetupCrossNsDNAT(t, natPort, srvPort)

	tcpCloser := nettestutil.StartServerTCPNs(t, net.ParseIP("2.2.2.4"), srvPort, "test")
	defer tcpCloser.Close()

	udpCloser := nettestutil.StartServerUDPNs(t, net.ParseIP("2.2.2.4"), srvPort, "test")
	defer udpCloser.Close()

	tcpConn := nettestutil.PingTCP(t, net.ParseIP("2.2.2.4"), natPort)
	defer tcpConn.Close()

	udpConn := nettestutil.PingUDP(t, net.ParseIP("2.2.2.4"), natPort)
	defer udpConn.Close()

	testNs, err := netns.GetFromName("test")
	require.NoError(t, err)
	defer testNs.Close()

	ctrks := map[int]Conntrack{}
	defer func() {
		for _, ctrk := range ctrks {
			ctrk.Close()
		}
	}()

	tcpLaddr := tcpConn.LocalAddr().(*net.TCPAddr)
	udpLaddr := udpConn.LocalAddr().(*net.UDPAddr)
	// test a combination of (tcp, udp) x (root ns, test ns)
	testConntrackExists(t, tcpLaddr.IP.String(), tcpLaddr.Port, natPort, srvPort, "tcp", testNs, ctrks)
	testConntrackExists(t, udpLaddr.IP.String(), udpLaddr.Port, natPort, srvPort, "udp", testNs, ctrks)
}

func TestConntrackExistsRootDNAT(t *testing.T) {
	srvPort, natPort := nettestutil.RandomPortPair()

	defer testutil.TeardownCrossNsDNAT(t)
	testutil.SetupCrossNsDNAT(t, natPort, srvPort)
	defer nettestutil.RunCommands(t, []string{
		fmt.Sprintf("iptables --table nat --delete CLUSTERIPS --destination 10.10.1.1 --protocol tcp --match tcp --dport %d --jump DNAT --to-destination 2.2.2.4:%d", natPort, natPort),
		"iptables --table nat --delete PREROUTING --jump CLUSTERIPS",
		"iptables --table nat --delete OUTPUT --jump CLUSTERIPS",
		"iptables --table nat --delete-chain CLUSTERIPS",
	}, true)
	nettestutil.RunCommands(t, []string{
		"iptables --table nat --new-chain CLUSTERIPS",
		"iptables --table nat --append PREROUTING --jump CLUSTERIPS",
		"iptables --table nat --append OUTPUT --jump CLUSTERIPS",
		fmt.Sprintf("iptables --table nat --append CLUSTERIPS --destination 10.10.1.1 --protocol tcp --match tcp --dport %d --jump DNAT --to-destination 2.2.2.4:%d", natPort, natPort),
	}, false)

	testNs, err := netns.GetFromName("test")
	require.NoError(t, err)
	defer testNs.Close()

	rootNs, err := util.GetRootNetNamespace("/proc")
	require.NoError(t, err)
	defer rootNs.Close()

	destIP := "10.10.1.1"
	destPort := natPort
	var tcpCloser io.Closer
	_ = util.WithNS("/proc", testNs, func() error {
		tcpCloser = nettestutil.StartServerTCP(t, net.ParseIP("2.2.2.4"), srvPort)
		return nil
	})
	defer tcpCloser.Close()

	tcpConn := nettestutil.PingTCP(t, net.ParseIP(destIP), destPort)
	defer tcpConn.Close()

	rootck, err := NewConntrack(int(rootNs))
	require.NoError(t, err)

	testck, err := NewConntrack(int(testNs))
	require.NoError(t, err)

	tcpLaddr := tcpConn.LocalAddr().(*net.TCPAddr)
	c := &Con{
		Con: ct.Con{
			Origin: newIPTuple(tcpLaddr.IP.String(), destIP, uint16(tcpLaddr.Port), uint16(destPort), unix.IPPROTO_TCP),
		},
	}

	exists, err := rootck.Exists(c)
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = testck.Exists(c)
	require.NoError(t, err)
	assert.False(t, exists)
}

func testConntrackExists(t *testing.T, laddrIP string, laddrPort int, natPort int, srvPort int, proto string, testNs netns.NsHandle, ctrks map[int]Conntrack) {
	rootNs, err := util.GetRootNetNamespace("/proc")
	require.NoError(t, err)
	defer rootNs.Close()

	var ipProto uint8 = unix.IPPROTO_UDP
	if proto == "tcp" {
		ipProto = unix.IPPROTO_TCP
	}
	tests := []struct {
		desc   string
		c      Con
		exists bool
		ns     int
	}{
		{
			desc: fmt.Sprintf("net ns 0, origin exists, proto %s", proto),
			c: Con{
				Con: ct.Con{
					Origin: newIPTuple(laddrIP, "2.2.2.4", uint16(laddrPort), uint16(natPort), ipProto),
				},
			},
			exists: true,
			ns:     int(rootNs),
		},
		{
			desc: fmt.Sprintf("net ns 0, reply exists, proto %s", proto),
			c: Con{
				Con: ct.Con{
					Reply: newIPTuple("2.2.2.4", laddrIP, uint16(natPort), uint16(laddrPort), ipProto),
				},
			},
			exists: true,
			ns:     int(rootNs),
		},
		{
			desc: fmt.Sprintf("net ns 0, origin does not exist, proto %s", proto),
			c: Con{
				Con: ct.Con{
					Origin: newIPTuple(laddrIP, "2.2.2.3", uint16(laddrPort), uint16(natPort), ipProto),
				},
			},
			exists: false,
			ns:     int(rootNs),
		},
		{
			desc: fmt.Sprintf("net ns %d, origin exists, proto %s", int(testNs), proto),
			c: Con{
				Con: ct.Con{
					Origin: newIPTuple(laddrIP, "2.2.2.4", uint16(laddrPort), uint16(natPort), ipProto),
				},
			},
			exists: true,
			ns:     int(testNs),
		},
		{
			desc: fmt.Sprintf("net ns %d, reply exists, proto %s", int(testNs), proto),
			c: Con{
				Con: ct.Con{
					Reply: newIPTuple("2.2.2.4", laddrIP, uint16(srvPort), uint16(laddrPort), ipProto),
				},
			},
			exists: true,
			ns:     int(testNs),
		},
		{
			desc: fmt.Sprintf("net ns %d, origin does not exist, proto %s", int(testNs), proto),
			c: Con{
				Con: ct.Con{
					Origin: newIPTuple(laddrIP, "2.2.2.3", uint16(laddrPort), uint16(natPort), ipProto),
				},
			},
			exists: false,
			ns:     int(testNs),
		},
	}

	for _, te := range tests {
		t.Run(te.desc, func(t *testing.T) {
			ctrk, ok := ctrks[te.ns]
			if !ok {
				var err error
				ctrk, err = NewConntrack(te.ns)
				require.NoError(t, err)

				ctrks[te.ns] = ctrk
			}

			ok, err := ctrk.Exists(&te.c)
			require.NoError(t, err)
			require.Equal(t, te.exists, ok)
		})
	}
}
