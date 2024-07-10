package socks5

import (
	"encoding/binary"
	"fmt"
	"github.com/cieons/socks5/internal/proto"
	"io"
	"net"
)

/*

 - Request
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

VER : 0x05
CMD : 0x01 => Connect ; 0x02 => Bind ;0x03  => UDP Relay
RSV : must be 0x00
ATYP : 	0x01 => IPv4 , 4 bytes
		0x03 => Domain Name, first byte is the length of domain name
		0x04 => IPv6 ,16 bytes

- Reply
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
VER : 0x05
Req :
	X’00’ succeeded
	X’01’ general SOCKS server failure
	X’02’ connection not allowed by ruleset
	X’03’ Network unreachable
	X’04’ Host unreachable
	X’05’ Connection refused
	X’06’ TTL expired
	X’07’ Command not supported
	X’08’ Address type not supported
	X’09’ to X’FF’ unassigned
BND.ADDR，BND.PORT : server bound address

*/

type (
	Request struct {
		Ver     byte
		Cmd     byte
		Rsv     byte // 0x00
		ATyp    byte
		DstAddr []byte
		DstPort []byte // 2 bytes
	}

	RequestReply struct {
		Ver     byte
		Rep     byte
		Rsv     byte // 0x00
		ATyp    byte
		BndAddr []byte
		BndPort []byte // 2 bytes
	}

	// Address The wrapper of BndAddr and BndPort
	Address struct {
		ATyp byte
		FQDN string
		IP   net.IP
		Port int
	}
)

// Addr FQDN should be resolved to IP
func (a *Address) Addr() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s:%d", a.FQDN, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

func (r *Request) Address() *Address {
	a := new(Address)

	a.ATyp = r.ATyp
	a.Port = int(binary.BigEndian.Uint16(r.DstPort))

	switch a.ATyp {
	case proto.ATypIPv4, proto.ATypIPv6:
		a.IP = r.DstAddr
	case proto.ATypDomain:
		a.FQDN = string(r.DstAddr[1:])
	}
	return a
}

func newRequest(r io.Reader) (*Request, error) {
	req := new(Request)

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

func newRequestReply(rep, aTyp byte, bindAddr net.Addr) *RequestReply {
	var bndAddr []byte
	var bndPort = []byte{0x00, 0x00}
	var _atyp = aTyp

	if bindAddr == nil {
		switch _atyp {
		case proto.ATypIPv4, proto.ATypDomain:
			bndAddr = net.IPv4zero
			_atyp = proto.ATypIPv4
		case proto.ATypIPv6:
			bndAddr = net.IPv6zero
		}
	} else {
		// has bindAddr means successfully established remote connection
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok && tcpAddr != nil {
			bndAddr = tcpAddr.IP
			binary.BigEndian.PutUint16(bndPort, uint16(tcpAddr.Port))
		} else if udpAddr, ok := bindAddr.(*net.UDPAddr); ok && udpAddr != nil {
			bndAddr = udpAddr.IP
			binary.BigEndian.PutUint16(bndPort, uint16(udpAddr.Port))
		} else {
			rep = proto.RepServerFailure
		}
	}

	return &RequestReply{
		Ver:     proto.VersionSocks5,
		Rep:     rep,
		Rsv:     0x00,
		ATyp:    _atyp,
		BndAddr: bndAddr,
		BndPort: bndPort,
	}
}

func (r *RequestReply) Bytes() []byte {
	return append(append([]byte{r.Ver, r.Rep, r.Rsv, r.ATyp}, r.BndAddr...), r.BndPort...)
}
