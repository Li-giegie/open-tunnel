package core

import (
	"net"
	"testing"
	"time"
)

func TestRangeSessionsAccount(t *testing.T) {
	s := &Session{
		udpAddrSet: make(map[uint64]*SessionEntry),
		ipSet:      map[uint32]uint64{},
	}
	s.CreateSession("alice", 42, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678})
	s.SetSessionIP(42, net.IPv4(10, 20, 0, 2))

	var got struct {
		id      uint64
		account string
		addr    string
		ips     int
	}
	s.RangeSessions(func(sessionId uint64, account string, addr *net.UDPAddr, _ time.Time, ips []net.IP) bool {
		got.id, got.account, got.addr, got.ips = sessionId, account, addr.String(), len(ips)
		return false
	})
	if got.id != 42 || got.account != "alice" || got.addr != "1.2.3.4:5678" || got.ips != 1 {
		t.Fatalf("RangeSessions snapshot wrong: %+v", got)
	}
}

func TestRemoveSession(t *testing.T) {
	s := &Session{
		udpAddrSet: make(map[uint64]*SessionEntry),
		ipSet:      map[uint32]uint64{},
	}
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
	ip := net.IPv4(10, 20, 0, 2)
	s.CreateSession("alice", 42, addr)
	s.SetSessionIP(42, ip)
	if _, ok := s.GetSessionUDPAddrByIP(ip); !ok {
		t.Fatal("ip mapping should exist before removal")
	}

	s.RemoveSession(42)

	if _, ok := s.GetSession(42); ok {
		t.Fatal("session should be removed")
	}
	if _, ok := s.GetSessionUDPAddrByIP(ip); ok {
		t.Fatal("ip mapping should be removed with the session")
	}
	// 不存在的会话是空操作，不应 panic
	s.RemoveSession(999)
}

func TestRemoveSessionGuardsReassignedIP(t *testing.T) {
	s := NewSession()
	ip := net.IPv4(10, 20, 0, 2)
	// 客户端重连：同账户新会话接管同一隧道 IP
	s.CreateSession("alice", 1, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 100})
	s.SetSessionIP(1, ip)
	s.CreateSession("alice", 2, &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 200})
	s.SetSessionIP(2, ip)

	// 删除旧会话不应误删已被新会话接管的 IP 映射
	s.RemoveSession(1)
	udpAddr, ok := s.GetSessionUDPAddrByIP(ip)
	if !ok || udpAddr.String() != "2.2.2.2:200" {
		t.Fatalf("ip mapping should belong to session 2, got %v ok=%v", udpAddr, ok)
	}

	// 删除拥有该映射的新会话后才清理
	s.RemoveSession(2)
	if _, ok = s.GetSessionUDPAddrByIP(ip); ok {
		t.Fatal("ip mapping should be removed with the owning session")
	}
}

func TestRemoveAccountSessions(t *testing.T) {
	s := NewSession()
	s.CreateSession("alice", 1, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 100})
	s.CreateSession("alice", 2, &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 200})
	s.CreateSession("bob", 3, &net.UDPAddr{IP: net.IPv4(3, 3, 3, 3), Port: 300})

	if n := s.RemoveAccountSessions("alice"); n != 2 {
		t.Fatalf("RemoveAccountSessions removed %d sessions, want 2", n)
	}
	if _, ok := s.GetSession(1); ok {
		t.Fatal("alice session 1 should be removed")
	}
	if _, ok := s.GetSession(2); ok {
		t.Fatal("alice session 2 should be removed")
	}
	if _, ok := s.GetSession(3); !ok {
		t.Fatal("bob session should be kept")
	}
	if n := s.RemoveAccountSessions("carol"); n != 0 {
		t.Fatalf("unknown account removed %d sessions, want 0", n)
	}
}
