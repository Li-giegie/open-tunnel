package core

import (
	"fmt"
	"net"
	"testing"
)

func TestRoute(t *testing.T) {
	srv := new(Server)
	ipNets := []string{"127.0.0.1/32", "192.0.0.1/24", "192.0.0.1/30"}
	for i, s := range ipNets {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		err = srv.AddIPV4Route(ipNet, net.IPv4(1, 1, 1, byte(i)))
		if err != nil {
			t.Fatal(err)
		}
	}
	srv.RangeIPV4Route(func(ipNet *net.IPNet, via net.IP) bool {
		fmt.Printf("ip route %s via %s\n", ipNet.String(), via.String())
		return true
	})

	fmt.Println(srv.GetIPV4Route(net.IPv4(127, 0, 0, 1)))
	fmt.Println(srv.GetIPV4Route(net.IPv4(192, 0, 0, 1)))

	for _, s := range ipNets {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		if !srv.DelIPV4Route(ipNet) {
			t.Fatal("DelIPV4Route failed", ipNet.String(), "not exist")
		}
		println("del ip route", ipNet.String())
		srv.RangeIPV4Route(func(ipNet *net.IPNet, via net.IP) bool {
			fmt.Printf("ip route %s via %s\n", ipNet.String(), via.String())
			return true
		})
		println()
	}

}
