package socks5

import (
	"github.com/cieons/socks5/internal/proto"
	"io"
)

type Authenticator interface {
	Authenticate(r io.ReadWriter) error
	Method() byte // return the method byte defined in socks5 protocol
}

type NoneAuthenticator struct{}

func (a *NoneAuthenticator) Authenticate(_ io.ReadWriter) error {
	return nil
}

func (a *NoneAuthenticator) Method() byte {
	return proto.AuthMethodNone
}

/*
UserPassAuthRequest
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+
  - VER: should be 0x01



UserPassAuthReply
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+
Status 0x00 means success

*/

type (
	UserPassAuthenticator struct {
		credential map[string]string
	}

	UserPassAuthRequest struct {
		Ver    byte
		ULen   byte
		UName  []byte
		PLen   byte
		Passwd []byte
	}

	UserPassAuthReply struct {
		Ver    byte
		Status byte
	}
)

func newUserPassAuthReply(success bool) *UserPassAuthReply {
	var status byte = 0xff
	if success {
		status = 0x00
	}

	return &UserPassAuthReply{
		Ver:    proto.AuthMethodUserPassVer,
		Status: status,
	}
}

func (r *UserPassAuthReply) Bytes() []byte {
	return []byte{r.Ver, r.Status}
}

func (a *UserPassAuthenticator) Authenticate(r io.ReadWriter) error {
	req := new(UserPassAuthRequest)

	tmp := make([]byte, 2)
	if _, err := io.ReadFull(r, tmp); err != nil {
		return err
	}

	req.Ver, req.ULen = tmp[0], tmp[1]
	if req.Ver != proto.AuthMethodUserPassVer {
		return proto.ErrInvalidUserPassAuthVersion
	}
	if req.ULen == 0 {
		return proto.ErrBadRequest
	}

	req.UName = make([]byte, req.ULen)
	if _, err := io.ReadFull(r, req.UName); err != nil {
		return err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(r, plen); err != nil {
		return err
	}
	req.PLen = plen[0]
	if req.PLen == 0 {
		return proto.ErrBadRequest
	}

	req.Passwd = make([]byte, req.PLen)
	if _, err := io.ReadFull(r, req.Passwd); err != nil {
		return err
	}

	pass, ok := a.credential[string(req.UName)]

	success := ok && pass == string(req.Passwd)

	var reply = newUserPassAuthReply(success)
	_, err := r.Write(reply.Bytes())
	if err != nil {
		return err
	}

	if !success {
		return proto.ErrUserPassAuthFailure
	}

	return nil
}

func newUserPassAuthenticator(credential map[string]string) *UserPassAuthenticator {
	return &UserPassAuthenticator{credential: credential}
}

func (a *UserPassAuthenticator) Method() byte {
	return proto.AuthMethodUserPass
}
