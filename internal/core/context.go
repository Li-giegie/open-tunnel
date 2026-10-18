package core

import (
	"net"
)

type Context struct {
	*Packet
	*net.UDPConn
	*net.UDPAddr
	PacketSize  int
	ReadBuffer  []byte
	WriteBuffer []byte
	response    *Packet
}

func (c *Context) SendEncoder(cmd Cmd, enc Encoder) error {
	c.WriteBuffer = c.WriteBuffer[:0]
	c.response.Cmd = cmd
	c.response.SessionId = c.SessionId
	c.WriteBuffer = c.response.Encode(c.WriteBuffer)
	c.WriteBuffer = enc.Encode(c.WriteBuffer)
	_, err := c.WriteToUDP(c.WriteBuffer, c.UDPAddr)
	return err
}

func (c *Context) SendTo(cmd Cmd, data []byte) error {
	c.WriteBuffer = c.WriteBuffer[:0]
	c.response.Cmd = cmd
	c.response.SessionId = c.SessionId
	c.response.Data = data
	c.WriteBuffer = c.response.Encode(c.WriteBuffer)
	_, err := c.WriteToUDP(c.WriteBuffer, c.UDPAddr)
	return err
}

func (c *Context) Send(cmd Cmd, data []byte) error {
	c.WriteBuffer = c.WriteBuffer[:0]
	c.response.Cmd = cmd
	c.response.SessionId = c.SessionId
	c.response.Data = data
	c.WriteBuffer = c.response.Encode(c.WriteBuffer)
	_, err := c.Write(c.WriteBuffer)
	return err
}
