package internal

import (
	"context"
	"encoding/binary"
	"github.com/songgao/water/waterutil"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"
)

type SrvCfg struct {
	Addr                string
	CheckHealthInterval time.Duration
	CheckHealthTimeout  time.Duration
	Validator           Validator
}

func NewServer(c SrvCfg) *Server {
	return &Server{
		addr:      c.Addr,
		Validator: c.Validator,
		session: &Session{
			udpAddrSet: make(map[uint64]*SessionEntry),
			ipSet:      map[uint32]uint64{},
		},
		checkHealthInterval: c.CheckHealthInterval,
		checkHealthTimeout:  c.CheckHealthTimeout,
	}
}

type Server struct {
	addr   string
	ctx    context.Context
	cancel context.CancelFunc
	Validator
	session             *Session
	checkHealthInterval time.Duration
	checkHealthTimeout  time.Duration
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
			s.session.udpAddrSetLock.Lock()
			s.session.ipSetLock.Lock()
			for k, entry := range s.session.udpAddrSet {
				if time.Now().Sub(entry.updateTime) > checkHealthTimeout {
					delete(s.session.udpAddrSet, k)
					for _, ip := range entry.ips {
						delete(s.session.ipSet, binary.BigEndian.Uint32(ip.To4()))
					}
				}
			}
			s.session.ipSetLock.Unlock()
			s.session.udpAddrSetLock.Unlock()
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
		if s.Validator != nil {
			if !s.Validator.ValidUsernamePassword(req.Username, req.Password) {
				return ctx.SendEncoder(CmdAuthResp, &AuthResp{Code: 1})
			}
		}
		sessionId := uint64(binary.BigEndian.Uint32(ctx.UDPAddr.IP.To4()))<<32 | uint64(uint32(ctx.UDPAddr.Port))<<16 | uint64(uint16(rand.Uint()))
		s.session.SetSessionAddr(sessionId, ctx.UDPAddr)
		return ctx.SendEncoder(CmdAuthResp, &AuthResp{Code: 0, SessionId: sessionId})
	default:
		entry, ok := s.session.GetSession(ctx.SessionId)
		if !ok {
			log.Printf("session id %d invalid  %v\n", ctx.SessionId, ctx.UDPAddr.String())
			return nil
		}
		entry.updateTime = time.Now()

		switch ctx.Cmd {
		case CmdForward:
			if !waterutil.IsIPv4(ctx.Data) {
				log.Println("Forwarding not IPv4")
				return nil
			}
			sourceIp := waterutil.IPv4Source(ctx.Data).To4()
			destIp := waterutil.IPv4Destination(ctx.Data).To4()

			s.session.SetSessionIP(ctx.SessionId, sourceIp)

			udpAddr, ok := s.session.GetSessionUDPAddrByIP(destIp)
			if !ok {
				log.Println("Forwarding address not found", "src", sourceIp.String(), "dest", destIp.String())
				return s.Broadcast(ctx.UDPConn, (&Packet{Cmd: CmdQuestionIP, SessionId: 0, Data: destIp}).Encode(ctx.WriteBuffer[:0]))
			}
			_, err := ctx.UDPConn.WriteToUDP(ctx.ReadBuffer[:ctx.PacketSize], udpAddr)
			return err
		case CmdPing:
			s.session.SetSessionAddr(ctx.SessionId, ctx.UDPAddr)
			return ctx.SendTo(CmdPong, nil)
		case CmdAnswerIP:
			if len(ctx.Data) != 4 {
				log.Println("Answer IP length invalid")
				return nil
			}
			s.session.SetSessionIP(ctx.SessionId, net.IPv4(ctx.Data[0], ctx.Data[1], ctx.Data[2], ctx.Data[3]))
			return nil
		default:
			log.Println("Unknown command:", ctx.Cmd)
			return nil
		}
	}
}

func (s *Server) Broadcast(conn *net.UDPConn, data []byte) error {
	s.session.udpAddrSetLock.RLock()
	defer s.session.udpAddrSetLock.RUnlock()
	for _, entry := range s.session.udpAddrSet {
		if _, err := conn.WriteToUDP(data, entry.addr); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}
