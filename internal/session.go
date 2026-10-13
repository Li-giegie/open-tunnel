package internal

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type Session struct {
	udpAddrSet     map[uint64]*SessionEntry
	udpAddrSetLock sync.RWMutex
	ipSet          map[uint32]uint64
	ipSetLock      sync.RWMutex
}

func (s *Session) SetSessionAddr(sessionId uint64, addr *net.UDPAddr) {
	s.udpAddrSetLock.Lock()
	s.udpAddrSet[sessionId] = &SessionEntry{
		addr:       addr,
		updateTime: time.Now(),
	}
	s.udpAddrSetLock.Unlock()
}

func (s *Session) SetSessionIP(sessionId uint64, ip net.IP) {
	s.ipSetLock.Lock()
	s.ipSet[binary.BigEndian.Uint32(ip.To4())] = sessionId
	s.ipSetLock.Unlock()

	s.udpAddrSetLock.Lock()
	entry, ok := s.udpAddrSet[sessionId]
	if ok {
		entry.ips = append(entry.ips, ip)
	}
	s.udpAddrSetLock.Unlock()
}

func (s *Session) GetSession(sessionId uint64) (*SessionEntry, bool) {
	s.udpAddrSetLock.RLock()
	v, ok := s.udpAddrSet[sessionId]
	s.udpAddrSetLock.RUnlock()
	return v, ok
}

func (s *Session) GetSessionUDPAddr(sessionId uint64) (*net.UDPAddr, bool) {
	s.udpAddrSetLock.RLock()
	v, ok := s.udpAddrSet[sessionId]
	s.udpAddrSetLock.RUnlock()
	if !ok {
		return nil, false
	}
	return v.addr, ok
}

func (s *Session) GetSessionUDPAddrByIP(ip net.IP) (*net.UDPAddr, bool) {
	s.ipSetLock.RLock()
	v, ok := s.ipSet[binary.BigEndian.Uint32(ip.To4())]
	s.ipSetLock.RUnlock()
	if !ok {
		return nil, false
	}
	return s.GetSessionUDPAddr(v)
}

type SessionEntry struct {
	addr       *net.UDPAddr
	updateTime time.Time
	ips        []net.IP
}
