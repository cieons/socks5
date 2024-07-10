package socks5

import (
	"github.com/cieons/socks5/internal/proto"
	"io"
)

/*
NegotiateRequest
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

  - VER: MUST BE 0x01

NegotiateReply
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
*/

type (
	NegotiateRequest struct {
		Ver      byte
		NMethods byte
		Methods  []byte
	}

	NegotiateReply struct {
		Ver    byte
		Method byte
	}
)

func newNegotiateRequest(r io.Reader) (*NegotiateRequest, error) {
	req := new(NegotiateRequest)

	tmp := make([]byte, 2)
	_, err := io.ReadFull(r, tmp)
	if err != nil {
		return nil, err
	}

	req.Ver, req.NMethods = tmp[0], tmp[1]

	req.Methods = make([]byte, req.NMethods)
	_, err = io.ReadFull(r, req.Methods)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func newNegotiateReply(method byte) *NegotiateReply {
	return &NegotiateReply{
		Ver:    proto.VersionSocks5,
		Method: method,
	}
}

func (np *NegotiateReply) Bytes() []byte {
	return []byte{np.Ver, np.Method}
}

func (s *Server) chooseAuthMethod(req *NegotiateRequest) (byte, error) {

	if req.Ver != proto.VersionSocks5 {
		return 0xff, proto.ErrInvalidSocksVersion
	}

	for _, m := range req.Methods {
		if m == s.authenticator.Method() {
			return m, nil
		}
	}

	return proto.AuthMethodNotSupport, nil
}
