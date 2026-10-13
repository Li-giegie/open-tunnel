package internal

import (
	"context"
	"errors"
	"fmt"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"log"
	"net"
	"net/netip"
	"time"
)

type CliCfg struct {
	Addr      string
	Username  string
	Password  string
	Keepalive time.Duration
	Timeout   time.Duration
}

func NewClient(c CliCfg) *Client {
	return &Client{
		addr:       c.Addr,
		username:   c.Username,
		password:   c.Password,
		updateTime: time.Now(),
		keepalive:  c.Keepalive,
		timeout:    c.Timeout,
	}
}

type Client struct {
	addr       string
	username   string
	password   string
	sessionId  uint64
	updateTime time.Time
	keepalive  time.Duration
	timeout    time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
}

func (c *Client) Serve(ctx context.Context) error {
	addrPort, err := netip.ParseAddrPort(c.addr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addrPort))
	if err != nil {
		return err
	}
	defer conn.Close()

	if err = c.Auth(conn); err != nil {
		return err
	}

	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return err
	}
	defer iface.Close()

	c.ctx, c.cancel = context.WithCancel(context.TODO())
	defer c.cancel()

	connDone := make(chan error, 1)
	go func() {
		defer close(connDone)
		connDone <- c.handleConn(conn, iface)

	}()

	ifaceDone := make(chan error, 1)
	go func() {
		defer close(ifaceDone)
		ifaceDone <- c.handleIface(conn, iface)
	}()

	healthDone := make(chan error, 1)
	go func() {
		defer close(healthDone)
		healthDone <- c.handleHealth(conn)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-connDone:
		return err
	case err := <-ifaceDone:
		return err
	case err := <-healthDone:
		return err
	case <-c.ctx.Done():
		return nil
	}
}

func (c *Client) Auth(conn *net.UDPConn) error {

	timeout := make(chan struct{})
	time.AfterFunc(time.Minute, func() { close(timeout) })

	done := make(chan error, 1)
	go func() {
		defer close(done)
		_, err := conn.Write((&Packet{Cmd: CmdAuthReq, SessionId: 0, Data: (&AuthReq{Username: c.username, Password: c.password}).Encode()}).Encode(nil))
		if err != nil {
			done <- err
			return
		}
		buffer := make([]byte, 1500)
		n := 0
		if n, err = conn.Read(buffer); err != nil {
			done <- err
			return
		}
		pkt := new(Packet)
		if err = pkt.Decode(buffer[:n]); err != nil {
			done <- err
			return
		}

		resp, err := NewAuthResp(pkt.Data)
		if err != nil {
			done <- err
			return
		}
		if resp.Code != 0 {
			done <- fmt.Errorf("认证失败")
			return
		}
		c.sessionId = resp.SessionId
	}()

	select {
	case <-timeout:
		return errors.New("timeout")
	case err := <-done:
		return err
	}
}

func (c *Client) handleHealth(conn *net.UDPConn) error {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = time.Minute * 2
	}
	timeoutTicker := time.NewTicker(timeout + 3*time.Second)
	defer timeoutTicker.Stop()

	keepalive := c.keepalive
	if keepalive <= 0 {
		keepalive = 15 * time.Second
	}
	keepaliveTicker := time.NewTicker(keepalive)
	defer keepaliveTicker.Stop()

	log.Println(timeout, keepalive)

	data := (&Packet{Cmd: CmdPing, SessionId: c.sessionId}).Encode(nil)
	for {
		select {
		case <-keepaliveTicker.C:
			_, err := conn.Write(data)
			if err != nil {
				return err
			}
			log.Println("发送ping")
		case <-timeoutTicker.C:
			if time.Now().Sub(c.updateTime) > timeout {
				return errors.New("health err: timeout")
			}
		case <-c.ctx.Done():
			return nil
		}
	}
}

func (c *Client) handleConn(conn *net.UDPConn, iface *water.Interface) error {
	c.updateTime = time.Now()
	buffer := make([]byte, 1500)
	writeBuffer := make([]byte, 1500)
	packet := new(Packet)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		if err = packet.Decode(buffer[:n]); err != nil {
			return err
		}
		log.Println("receive packet", packet.Cmd.String(), packet.SessionId)
		switch packet.Cmd {
		case CmdForward:
			if _, err = iface.Write(packet.Data); err != nil {
				return err
			}
		case CmdPong:
			c.updateTime = time.Now()
		case CmdQuestionIP:
			if len(packet.Data) != 4 {
				log.Println("invalid cmd CmdAnswerIP")
				continue
			}
			addrs, err := net.InterfaceAddrs()
			if err != nil {
				log.Println("Error getting interface addresses")
				continue
			}
			queryIP := net.IPv4(packet.Data[0], packet.Data[1], packet.Data[2], packet.Data[3])
			exist := false
		a:
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.Equal(queryIP) {
						exist = true
						break a
					}
				case *net.IPAddr:
					if v.IP.Equal(queryIP) {
						exist = true
						break a
					}
				}
			}
			if exist {
				packet.SessionId = c.sessionId
				packet.Cmd = CmdAnswerIP
				if _, err = conn.Write(packet.Encode(writeBuffer[:0])); err != nil {
					return err
				}
			}
		default:
			log.Println("unknown Cmd", packet.Cmd)
		}
	}
}

func (c *Client) handleIface(conn *net.UDPConn, iface *water.Interface) error {
	buffer := make([]byte, 1500)
	writeBuffer := make([]byte, 1500)
	packet := new(Packet)
	packet.SessionId = c.sessionId
	for {
		n, err := iface.Read(buffer)
		if err != nil {
			return err
		}
		if !waterutil.IsIPv4(buffer[:n]) {
			continue
		}
		packet.Cmd = CmdForward
		packet.Data = buffer[:n]
		if _, err = conn.Write(packet.Encode(writeBuffer[:0])); err != nil {
			return err
		}
	}
}

func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}
