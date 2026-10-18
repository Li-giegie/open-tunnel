package core

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/maphash"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/songgao/water/waterutil"
)

type SrvCfg struct {
	Addr                string
	CheckHealthInterval time.Duration
	CheckHealthTimeout  time.Duration
	UserStore           UserStore
}

func NewServer(c SrvCfg) *Server {
	var h maphash.Hash
	h.SetSeed(maphash.MakeSeed())
	srv := &Server{
		addr:                c.Addr,
		UserStore:           c.UserStore,
		Session:             NewSession(),
		checkHealthInterval: c.CheckHealthInterval,
		checkHealthTimeout:  c.CheckHealthTimeout,
		hash:                h,
		startTime:           time.Now(),
	}
	return srv
}

type Server struct {
	addr   string
	ctx    context.Context
	cancel context.CancelFunc
	*Session
	checkHealthInterval  time.Duration
	checkHealthTimeout   time.Duration
	broadcastDedupSet    sync.Map
	broadcastDedupWindow time.Duration // 在该窗口内，同一条消息最多向同一个客户端广播一次。< 0 关闭 == 0 默认值 6s
	hash                 maphash.Hash
	routeTable           []*routeEntry
	routeTableLock       sync.RWMutex
	startTime            time.Time
	UserStore
}

// Addr 返回 UDP 监听地址。
func (s *Server) Addr() string {
	return s.addr
}

// Uptime 返回服务端启动至今的时长。
func (s *Server) Uptime() time.Duration {
	return time.Since(s.startTime)
}

func (s *Server) Serve(ctx context.Context) error {
	addrPort, err := netip.ParseAddrPort(s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addrPort))
	if err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer func() {
		s.cancel()
		conn.Close()
	}()
	go s.checkHealth()

	errDone := make(chan error, 1)
	go func() {
		defer close(errDone)
		ctx := &Context{
			UDPConn:     conn,
			Packet:      new(Packet),
			ReadBuffer:  make([]byte, 1500),
			WriteBuffer: make([]byte, 1500),
			response:    new(Packet),
		}
		var err error
		for {
			ctx.PacketSize, ctx.UDPAddr, err = conn.ReadFromUDP(ctx.ReadBuffer)
			if err != nil {
				errDone <- err
				return
			}
			if err = ctx.Decode(ctx.ReadBuffer[:ctx.PacketSize]); err != nil {
				log.Printf("Error decoding packet: %v", err)
				continue
			}
			if err = s.Handle(ctx); err != nil {
				errDone <- err
				return
			}
		}
	}()

	go s.clearBroadcastDedupSet()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return nil
	case err = <-errDone:
		return err
	}
}

func (s *Server) checkHealth() {
	checkHealthTimeout := s.checkHealthTimeout
	if checkHealthTimeout <= 0 {
		checkHealthTimeout = time.Minute * 2
	}
	checkHealthInterval := s.checkHealthInterval
	if checkHealthInterval <= 0 {
		checkHealthInterval = time.Minute
	}

	ticker := time.NewTicker(checkHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var removeSessionIds []uint64
			s.RangeSessions(func(sessionId uint64, account string, addr *net.UDPAddr, updateTime time.Time, ips []net.IP) bool {
				if time.Since(updateTime) > checkHealthTimeout {
					removeSessionIds = append(removeSessionIds, sessionId)
				}
				return true
			})
			for _, id := range removeSessionIds {
				s.RemoveSession(id)
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) Handle(ctx *Context) error {
	log.Println("handling packet", ctx.SessionId, ctx.Packet.Cmd.String())
	switch ctx.Cmd {
	case CmdAuthReq:
		if ctx.SessionId != 0 {
			log.Printf("AuthReq session id invalid  %d\n", ctx.SessionId)
			return nil
		}
		req, err := NewAuthReq(ctx.Data)
		if err != nil {
			log.Println(err)
			return nil
		}
		if s.UserStore != nil {
			if err = s.UserStore.VerifyAccountPassword(req.Account, req.Password); err != nil {
				return ctx.SendEncoder(CmdAuthResp, &AuthResp{Code: 1})
			}
		}
		sessionId := uint64(binary.BigEndian.Uint32(ctx.UDPAddr.IP.To4()))<<32 | uint64(uint32(ctx.UDPAddr.Port))<<16 | uint64(uint16(rand.Uint()))
		// 同账户重新认证时清理旧会话，避免遗留会话超时清理时误删新会话的 IP 映射
		s.RemoveAccountSessions(req.Account)
		s.CreateSession(req.Account, sessionId, ctx.UDPAddr)
		return ctx.SendEncoder(CmdAuthResp, &AuthResp{Code: 0, SessionId: sessionId})
	default:
		_, ok := s.GetSession(ctx.SessionId)
		if !ok {
			log.Printf("session id %d invalid  %v\n", ctx.SessionId, ctx.UDPAddr.String())
			ctx.SendTo(CmdSessionInvalid, nil)
			return nil
		}

		switch ctx.Cmd {
		case CmdForward:
			if !waterutil.IsIPv4(ctx.Data) {
				log.Println("Forwarding not IPv4")
				return nil
			}
			sourceIp := waterutil.IPv4Source(ctx.Data).To4()
			destIp := waterutil.IPv4Destination(ctx.Data).To4()

			s.SetSessionIP(ctx.SessionId, sourceIp)

			var udpAddr *net.UDPAddr
			if udpAddr, ok = s.GetSessionUDPAddrByIP(destIp); !ok {
				via, viaExist := s.GetIPV4Route(destIp)
				if viaExist {
					udpAddr, ok = s.GetSessionUDPAddrByIP(via)
				}
				if !viaExist || !ok {
					log.Println("Forwarding address not found via invalid", "src", sourceIp.String(), "dest", destIp.String())
					return s.Broadcast(ctx.UDPConn, ctx.UDPAddr, (&Packet{Cmd: CmdQuestionIP, SessionId: 0, Data: destIp}).Encode(ctx.WriteBuffer[:0]))
				}
			}
			_, err := ctx.UDPConn.WriteToUDP(ctx.ReadBuffer[:ctx.PacketSize], udpAddr)
			return err
		case CmdPing:
			s.SetSessionAddr(ctx.SessionId, ctx.UDPAddr)
			return ctx.SendTo(CmdPong, nil)
		case CmdAnswerIP:
			if len(ctx.Data) != 4 {
				log.Println("Answer IP length invalid")
				return nil
			}
			s.SetSessionIP(ctx.SessionId, net.IPv4(ctx.Data[0], ctx.Data[1], ctx.Data[2], ctx.Data[3]))
			return nil
		default:
			log.Println("Unknown command:", ctx.Cmd)
			return nil
		}
	}
}

func (s *Server) clearBroadcastDedupSet() {
	dw := s.broadcastDedupWindow
	if dw < 0 {
		return
	}
	if dw == 0 {
		dw = time.Second * 6
	}
	tick := time.NewTicker(dw * 2)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			s.broadcastDedupSet.Range(func(k, v interface{}) bool {
				if time.Now().Sub(v.(time.Time)) > dw {
					s.broadcastDedupSet.Delete(k)
				}
				return true
			})
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) Broadcast(conn *net.UDPConn, src *net.UDPAddr, data []byte) error {
	s.udpAddrSetLock.RLock()
	defer s.udpAddrSetLock.RUnlock()

	for _, entry := range s.udpAddrSet {
		if !entry.addr.IP.Equal(src.IP) {
			if dw := s.broadcastDedupWindow; dw > -1 {
				s.hash.Reset()
				_, err := s.hash.Write(entry.addr.IP.To4())
				if err != nil {
					return err
				}
				if _, err = s.hash.Write([]byte{byte(uint16(entry.addr.Port) >> 8), byte(uint16(entry.addr.Port))}); err != nil {
					return err
				}
				if _, err = s.hash.Write(data); err != nil {
					return err
				}
				if dw == 0 {
					dw = time.Second * 6
				}
				n := s.hash.Sum64()
				a, ok := s.broadcastDedupSet.Load(n)
				if ok && time.Since(a.(time.Time)) < dw {
					log.Println("最近6秒发送过", entry.addr.String(), n)
					continue
				}
				s.broadcastDedupSet.Store(n, time.Now())
				log.Println("发送广播消息", entry.addr, n)
			}

			if _, err := conn.WriteToUDP(data, entry.addr); err != nil {
				return err
			}
		}
	}
	return nil
}

type routeEntry struct {
	dst *net.IPNet
	via net.IP
}

func (s *Server) AddIPV4Route(dst *net.IPNet, via net.IP) error {
	if dst.IP.To4() == nil {
		return errors.New("dst is not ipv4")
	}
	if _, bits := dst.Mask.Size(); bits != 32 {
		return errors.New("mask size is invalid")
	}
	if via.To4() == nil {
		return errors.New("via is not ipv4")
	}
	s.routeTableLock.Lock()
	defer s.routeTableLock.Unlock()
	for _, entry := range s.routeTable {
		if entry.dst.String() == dst.String() {
			return nil
		}
	}
	s.routeTable = append(s.routeTable, &routeEntry{
		dst: dst,
		via: via,
	})
	return nil
}

func (s *Server) GetIPV4Route(dst net.IP) (via net.IP, ok bool) {
	if dst.To4() == nil {
		return nil, false
	}
	matchOnes := -1
	s.routeTableLock.RLock()
	for _, entry := range s.routeTable {
		if entry.dst.Contains(dst) {
			ok = true
			if ones, _ := entry.dst.Mask.Size(); ones > matchOnes {
				matchOnes = ones
				via = entry.via
			}
		}
	}
	s.routeTableLock.RUnlock()

	return
}

func (s *Server) DelIPV4Route(dst *net.IPNet) bool {
	s.routeTableLock.Lock()
	defer s.routeTableLock.Unlock()
	for i, entry := range s.routeTable {
		if dst.String() == entry.dst.String() {
			copy(s.routeTable[i:], s.routeTable[i+1:])
			s.routeTable = s.routeTable[:len(s.routeTable)-1]
			return true
		}
	}
	return false
}

func (s *Server) RangeIPV4Route(fn func(ipNet *net.IPNet, via net.IP) bool) {
	s.routeTableLock.RLock()
	defer s.routeTableLock.RUnlock()
	for _, entry := range s.routeTable {
		if !fn(entry.dst, entry.via) {
			return
		}
	}
	return
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}
