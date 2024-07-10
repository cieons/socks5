package socks5

import (
	"github.com/cieons/socks5/internal/proto"
	"io"
)

func (s *Server) parseNegotiateRequest(r io.Reader) (*proto.NegotiateRequest, error) {
	req := new(proto.NegotiateRequest)

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

func (s *Server) negotiateReply(method byte) *proto.NegotiateReply {
	return &proto.NegotiateReply{
		Ver:    proto.VersionSocks5,
		Method: method,
	}
}

func (s *Server) chooseAuthMethod(req *proto.NegotiateRequest) (byte, error) {

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
