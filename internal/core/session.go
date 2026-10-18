package core

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

func NewSession() *Session {
	return &Session{
		udpAddrSet: make(map[uint64]*SessionEntry),
		ipSet:      map[uint32]uint64{},
	}
}

type Session struct {
	udpAddrSet     map[uint64]*SessionEntry
	udpAddrSetLock sync.RWMutex
	ipSet          map[uint32]uint64
	ipSetLock      sync.RWMutex
}

func (s *Session) CreateSession(account string, sessionId uint64, addr *net.UDPAddr) {
	s.udpAddrSetLock.Lock()
	s.udpAddrSet[sessionId] = &SessionEntry{
		account:    account,
		addr:       addr,
		updateTime: time.Now(),
	}
	s.udpAddrSetLock.Unlock()
}

func (s *Session) SetSessionAddr(sessionId uint64, addr *net.UDPAddr) {
	s.udpAddrSetLock.Lock()
	entry := s.udpAddrSet[sessionId]
	entry.updateTime = time.Now()
	entry.addr = addr
	s.udpAddrSetLock.Unlock()
}

func (s *Session) SetSessionIP(sessionId uint64, ip net.IP) {
	s.ipSetLock.Lock()
	s.ipSet[binary.BigEndian.Uint32(ip.To4())] = sessionId
	s.ipSetLock.Unlock()

	s.udpAddrSetLock.Lock()
	defer s.udpAddrSetLock.Unlock()
	entry, ok := s.udpAddrSet[sessionId]
	if ok {
		for _, item := range entry.ips {
			if item.Equal(ip) {
				return
			}
		}
		entry.ips = append(entry.ips, ip)
	}

}

// RangeSessions 遍历所有会话，fn 返回 false 时停止。
// 先在读锁内做快照、释放锁后再回调，fn 中可以安全地调用 Session 的其他方法。
func (s *Session) RangeSessions(fn func(sessionId uint64, account string, addr *net.UDPAddr, updateTime time.Time, ips []net.IP) bool) {
	type snapshot struct {
		id         uint64
		account    string
		addr       net.UDPAddr
		updateTime time.Time
		ips        []net.IP
	}
	s.udpAddrSetLock.RLock()
	snapshots := make([]snapshot, 0, len(s.udpAddrSet))
	for id, entry := range s.udpAddrSet {
		ips := make([]net.IP, len(entry.ips))
		copy(ips, entry.ips)
		snapshots = append(snapshots, snapshot{id: id, account: entry.account, addr: *entry.addr, updateTime: entry.updateTime, ips: ips})
	}
	s.udpAddrSetLock.RUnlock()
	for i := range snapshots {
		if !fn(snapshots[i].id, snapshots[i].account, &snapshots[i].addr, snapshots[i].updateTime, snapshots[i].ips) {
			return
		}
	}
}

func (s *Session) GetSession(sessionId uint64) (*SessionEntry, bool) {
	s.udpAddrSetLock.RLock()
	v, ok := s.udpAddrSet[sessionId]
	s.udpAddrSetLock.RUnlock()
	if ok {
		v.updateTime = time.Now()
	}
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

// RemoveSession 删除指定会话并清理其隧道 IP 映射，返回被删除的会话。
func (s *Session) RemoveSession(sessionId uint64) (*SessionEntry, bool) {
	s.udpAddrSetLock.Lock()
	entry, ok := s.udpAddrSet[sessionId]
	if ok {
		delete(s.udpAddrSet, sessionId)
	}
	s.udpAddrSetLock.Unlock()
	if ok && len(entry.ips) > 0 {
		s.ipSetLock.Lock()
		for _, ip := range entry.ips {
			// 该 IP 可能已被重新认证的新会话接管，只清理仍属于本会话的映射
			key := binary.BigEndian.Uint32(ip.To4())
			if s.ipSet[key] == sessionId {
				delete(s.ipSet, key)
			}
		}
		s.ipSetLock.Unlock()
	}
	return entry, ok
}

// RemoveAccountSessions 删除指定账户的全部会话，返回删除的会话数。
// 用于同账户重新认证时清理遗留的旧会话。
func (s *Session) RemoveAccountSessions(account string) int {
	ids := make([]uint64, 0)
	s.udpAddrSetLock.RLock()
	for id, entry := range s.udpAddrSet {
		if entry.account == account {
			ids = append(ids, id)
		}
	}
	s.udpAddrSetLock.RUnlock()
	for _, id := range ids {
		s.RemoveSession(id)
	}
	return len(ids)
}

type SessionEntry struct {
	account    string
	addr       *net.UDPAddr
	updateTime time.Time
	ips        []net.IP
}
