package socks5

import (
	"encoding/binary"
	"github.com/cieons/socks5/internal/proto"
	"io"
	"net"
)

func (s *Server) parseRequest(r io.Reader) (*proto.Request, error) {
	req := new(proto.Request)

	tmp := make([]byte, 4)
	if _, err := io.ReadFull(r, tmp); err != nil {
		return nil, err
	}

	req.Ver, req.Cmd, req.Rsv, req.ATyp = tmp[0], tmp[1], tmp[2], tmp[3]

	var dstAddr []byte
	switch req.ATyp {
	case proto.ATypIPv4:
		dstAddr = make([]byte, 4)
		if _, err := io.ReadFull(r, dstAddr); err != nil {
			return nil, err
		}
	case proto.ATypIPv6:
		dstAddr = make([]byte, 16)
		if _, err := io.ReadFull(r, dstAddr); err != nil {
			return nil, err
		}
	case proto.ATypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return nil, err
		}
		if length[0] == 0 {
			return nil, proto.ErrBadRequest
		}
		dstAddr = make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, dstAddr); err != nil {
			return nil, err
		}
		dstAddr = append(length, dstAddr...)
	}

	dstPort := make([]byte, 2)
	if _, err := io.ReadFull(r, dstPort); err != nil {
		return nil, err
	}

	req.DstAddr = dstAddr
	req.DstPort = dstPort

	return req, nil
}

func (s *Server) reply(rep byte, localAddr net.Addr) *proto.RequestReply {
	var reply = &proto.RequestReply{
		Ver:  proto.VersionSocks5,
		Rep:  rep,
		Rsv:  0x00,
		ATyp: proto.ATypIPv4, // default set to IPv4
	}

	if rep != proto.RepSuccess {
		return reply
	}

	serverAddr, _, err := net.SplitHostPort(localAddr.String())
	if err != nil {
		reply.Rep = proto.RepServerFailure
		return reply
	}

	if ip := net.ParseIP(serverAddr); ip != nil {
		if ip.To4() == nil {
			reply.ATyp = proto.ATypIPv6
			reply.BndAddr = ip.To16()
		} else {
			reply.ATyp = proto.ATypIPv4
			reply.BndAddr = ip.To4()
		}
	} else {
		reply.ATyp = proto.ATypDomain
	}

	reply.BndPort = make([]byte, 2)
	binary.BigEndian.PutUint16(reply.BndPort, uint16(localAddr.(*net.TCPAddr).Port))

	return reply
}
