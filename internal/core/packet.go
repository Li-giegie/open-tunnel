package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

type Cmd uint8

const (
	CmdForward Cmd = iota

	CmdPing
	CmdPong

	CmdAuthReq
	CmdAuthResp

	CmdQuestionIP
	CmdAnswerIP

	CmdSessionInvalid
)

func (c Cmd) String() string {
	switch c {
	case CmdForward:
		return "Forward"
	case CmdPing:
		return "Ping"
	case CmdPong:
		return "Pong"
	case CmdAuthReq:
		return "AuthReq"
	case CmdAuthResp:
		return "AuthResp"
	case CmdQuestionIP:
		return "QuestionIP"
	case CmdAnswerIP:
		return "AnswerIP"
	case CmdSessionInvalid:
		return "SessionInvalid"
	default:
		return "Unknown"
	}
}

type Encoder interface {
	Encode([]byte) []byte
}

type Decoder interface {
	Decode([]byte) error
}

type Packet struct {
	Cmd       Cmd
	SessionId uint64
	Data      []byte
}

func (p *Packet) Copy() *Packet {
	data := make([]byte, len(p.Data))
	copy(data, p.Data)
	return &Packet{
		Cmd:       p.Cmd,
		SessionId: p.SessionId,
		Data:      data,
	}
}

func (p *Packet) Encode(buffer []byte) []byte {
	buffer = append(buffer, byte(p.Cmd), byte(p.SessionId>>56), byte(p.SessionId>>48), byte(p.SessionId>>40), byte(p.SessionId>>32), byte(p.SessionId>>24), byte(p.SessionId>>16), byte(p.SessionId>>8), byte(p.SessionId))
	buffer = append(buffer, p.Data...)
	return buffer
}

func (p *Packet) Decode(b []byte) error {
	if len(b) < 9 {
		return errors.New("packet length too small")
	}
	p.Cmd = Cmd(b[0])
	p.SessionId = binary.BigEndian.Uint64(b[1:9])
	p.Data = b[9:]
	return nil
}

func NewAuthReq(b []byte) (*AuthReq, error) {
	var req AuthReq
	err := req.Decode(b)
	return &req, err
}

type AuthReq struct {
	Account  string
	Password string
}

func (a *AuthReq) Encode() []byte {
	return []byte(strings.Join([]string{a.Account, a.Password}, string([]byte{0, 0})))
}

func (a *AuthReq) Decode(b []byte) error {
	if len(b) < 2 {
		return errors.New("Packet length too short")
	}
	n := bytes.Index(b, []byte{0, 0})
	if n == -1 {
		return errors.New("Packet length too short")
	}
	a.Account = string(b[:n])
	a.Password = string(b[n+2:])
	return nil
}

func NewAuthResp(b []byte) (*AuthResp, error) {
	var req AuthResp
	err := req.Decode(b)
	return &req, err
}

type AuthResp struct {
	Code      uint8
	SessionId uint64
}

func (a *AuthResp) Encode(buffer []byte) []byte {
	buffer = append(buffer, a.Code)
	buffer = binary.BigEndian.AppendUint64(buffer, a.SessionId)
	return buffer
}

func (a *AuthResp) Decode(b []byte) error {
	if len(b) != 9 {
		return errors.New("decode AuthResp err")
	}
	a.Code = b[0]
	a.SessionId = binary.BigEndian.Uint64(b[1:])
	return nil
}

var Nil Nothing

type Nothing struct{}

func (n Nothing) Encode(buf *bytes.Buffer) error {
	return nil
}

func (n Nothing) Decode(b []byte) error {
	return nil
}
