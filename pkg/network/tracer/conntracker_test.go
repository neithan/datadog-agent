// +build linux_bpf

package tracer

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/netlink"
	netlinktestutil "github.com/DataDog/datadog-agent/pkg/network/netlink/testutil"
	nettestutil "github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

func TestConntrackers(t *testing.T) {
	conntrackers := []struct {
		name   string
		create func(*config.Config) (netlink.Conntracker, error)
	}{
		{"netlink", setupNetlinkConntracker},
		{"eBPF", setupEBPFConntracker},
	}
	for _, conntracker := range conntrackers {
		t.Run(conntracker.name, func(t *testing.T) {
			t.Run("IPv4", func(t *testing.T) {
				cfg := config.New()
				ct, err := conntracker.create(cfg)
				require.NoError(t, err)
				defer ct.Close()

				defer netlinktestutil.TeardownDNAT(t)
				netlinktestutil.SetupDNAT(t)

				testConntracker(t, net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), ct)
			})
			t.Run("IPv6", func(t *testing.T) {
				if !kernel.IsIPv6Enabled() {
					t.Skip("IPv6 not enabled on host")
				}

				cfg := config.New()
				ct, err := conntracker.create(cfg)
				require.NoError(t, err)
				defer ct.Close()

				defer netlinktestutil.TeardownDNAT6(t)
				netlinktestutil.SetupDNAT6(t)

				testConntracker(t, net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), ct)
			})
			t.Run("cross namespace - NAT rule on test namespace", func(t *testing.T) {
				cfg := config.New()
				cfg.EnableConntrackAllNamespaces = true
				ct, err := conntracker.create(cfg)
				require.NoError(t, err)
				defer ct.Close()

				testConntrackerCrossNamespace(t, ct)
			})
			t.Run("cross namespace - NAT rule on root namespace", func(t *testing.T) {
				cfg := config.New()
				cfg.EnableConntrackAllNamespaces = true
				ct, err := conntracker.create(cfg)
				require.NoError(t, err)
				defer ct.Close()

				testConntrackerCrossNamespaceNATonRoot(t, ct)
			})
		})
	}
}

func setupEBPFConntracker(cfg *config.Config) (netlink.Conntracker, error) {
	cfg.EnableRuntimeCompiler = true
	cfg.AllowPrecompiledFallback = false
	return NewEBPFConntracker(cfg)
}

func setupNetlinkConntracker(cfg *config.Config) (netlink.Conntracker, error) {
	cfg.ConntrackMaxStateSize = 100
	cfg.ConntrackRateLimit = 500
	ct, err := netlink.NewConntracker(cfg)
	time.Sleep(100 * time.Millisecond)
	return ct, err
}

func testConntracker(t *testing.T, serverIP, clientIP net.IP, ct netlink.Conntracker) {
	srv1 := nettestutil.StartServerTCP(t, serverIP, 0)
	defer srv1.Close()
	natPort, err := nettestutil.ListenerPort(srv1)
	require.NoError(t, err)

	srv2 := nettestutil.StartServerTCP(t, serverIP, 0)
	defer srv2.Close()
	nonNatPort, err := nettestutil.ListenerPort(srv1)
	require.NoError(t, err)

	srv3 := nettestutil.StartServerUDP(t, serverIP, natPort)
	defer srv3.Close()

	localAddr := nettestutil.PingTCP(t, clientIP, natPort).LocalAddr().(*net.TCPAddr)
	time.Sleep(1 * time.Second)

	curNs, err := util.GetCurrentIno()
	require.NoError(t, err)

	family := network.AFINET
	if len(localAddr.IP) == net.IPv6len {
		family = network.AFINET6
	}

	trans := ct.GetTranslationForConn(
		network.ConnectionStats{
			Source: util.AddressFromNetIP(localAddr.IP),
			SPort:  uint16(localAddr.Port),
			Dest:   util.AddressFromNetIP(clientIP),
			DPort:  uint16(natPort),
			Type:   network.TCP,
			Family: family,
			NetNS:  curNs,
		},
	)
	require.NotNil(t, trans)
	assert.Equal(t, util.AddressFromNetIP(serverIP), trans.ReplSrcIP)

	localAddrUDP := nettestutil.PingUDP(t, clientIP, natPort).LocalAddr().(*net.UDPAddr)
	time.Sleep(time.Second)

	family = network.AFINET
	if len(localAddrUDP.IP) == net.IPv6len {
		family = network.AFINET6
	}

	trans = ct.GetTranslationForConn(
		network.ConnectionStats{
			Source: util.AddressFromNetIP(localAddrUDP.IP),
			SPort:  uint16(localAddrUDP.Port),
			Dest:   util.AddressFromNetIP(clientIP),
			DPort:  uint16(natPort),
			Type:   network.UDP,
			Family: family,
			NetNS:  curNs,
		},
	)
	require.NotNil(t, trans)
	assert.Equal(t, util.AddressFromNetIP(serverIP), trans.ReplSrcIP)

	// now dial TCP directly
	localAddr = nettestutil.PingTCP(t, serverIP, nonNatPort).LocalAddr().(*net.TCPAddr)
	time.Sleep(time.Second)

	trans = ct.GetTranslationForConn(
		network.ConnectionStats{
			Source: util.AddressFromNetIP(localAddr.IP),
			SPort:  uint16(localAddr.Port),
			Dest:   util.AddressFromNetIP(serverIP),
			DPort:  uint16(nonNatPort),
			Type:   network.TCP,
			NetNS:  curNs,
		},
	)
	assert.Nil(t, trans)
}

func testConntrackerCrossNamespace(t *testing.T, ct netlink.Conntracker) {
	srvPort, natPort := nettestutil.RandomPortPair()
	t.Cleanup(func() {
		netlinktestutil.TeardownCrossNsDNAT(t)
	})
	netlinktestutil.SetupCrossNsDNAT(t, natPort, srvPort)

	closer := nettestutil.StartServerTCPNs(t, net.ParseIP("2.2.2.4"), srvPort, "test")
	laddr := nettestutil.PingTCP(t, net.ParseIP("2.2.2.4"), natPort).LocalAddr().(*net.TCPAddr)
	defer closer.Close()

	testNs, err := netns.GetFromName("test")
	require.NoError(t, err)
	defer testNs.Close()
	testIno, err := util.GetInoForNs(testNs)
	require.NoError(t, err)

	var trans *network.IPTranslation
	require.Eventually(t, func() bool {
		trans = ct.GetTranslationForConn(
			network.ConnectionStats{
				Source: util.AddressFromNetIP(laddr.IP),
				SPort:  uint16(laddr.Port),
				Dest:   util.AddressFromString("2.2.2.4"),
				DPort:  uint16(natPort),
				Type:   network.TCP,
				NetNS:  testIno,
			},
		)

		return trans != nil
	}, 5*time.Second, 1*time.Second, "timed out waiting for conntrack entry")

	assert.Equal(t, uint16(srvPort), trans.ReplSrcPort)
}

func testConntrackerCrossNamespaceNATonRoot(t *testing.T, ct netlink.Conntracker) {
	defer netlinktestutil.TeardownVethPair(t)
	netlinktestutil.SetupVethPair(t)

	// SetupDNAT sets up a NAT translation from 3.3.3.3 to 1.1.1.1
	defer netlinktestutil.TeardownDNAT(t)
	netlinktestutil.SetupDNAT(t)

	// Setup TCP server on root namespace
	srv := nettestutil.StartServerTCP(t, net.ParseIP("1.1.1.1"), 0)
	defer srv.Close()
	srvPort, err := nettestutil.ListenerPort(srv)
	require.NoError(t, err)

	// Now switch to the test namespace and make a request to the root namespace server
	var laddr *net.TCPAddr
	var testIno uint32
	done := make(chan struct{})
	go func() {
		var err error
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		originalNS, _ := netns.Get()
		defer originalNS.Close()

		testNS, err := netns.GetFromName("test")
		require.NoError(t, err)

		testIno, err = util.GetInoForNs(testNS)
		require.NoError(t, err)

		defer netns.Set(originalNS)
		defer close(done)
		netns.Set(testNS)
		laddr = nettestutil.PingTCP(t, net.ParseIP("3.3.3.3"), srvPort).LocalAddr().(*net.TCPAddr)
	}()
	<-done

	require.NotNil(t, laddr)

	var trans *network.IPTranslation
	require.Eventually(t, func() bool {
		trans = ct.GetTranslationForConn(
			network.ConnectionStats{
				Source: util.AddressFromNetIP(laddr.IP),
				SPort:  uint16(laddr.Port),
				Dest:   util.AddressFromString("3.3.3.3"),
				DPort:  uint16(srvPort),
				Type:   network.TCP,
				NetNS:  testIno,
			},
		)

		return trans != nil
	}, 5*time.Second, 1*time.Second, "timed out waiting for conntrack entry")

	assert.Equal(t, util.AddressFromString("1.1.1.1"), trans.ReplSrcIP)
}
