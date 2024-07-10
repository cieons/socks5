package proto

import (
	"encoding/binary"
	"net"
	"strconv"
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
)

func (r *Request) Destination() string {
	port := binary.BigEndian.Uint16(r.DstPort)
	switch r.ATyp {
	case ATypIPv4, ATypIPv6:
		return net.IP(r.DstAddr[:]).String() + ":" + strconv.Itoa(int(port))
	case ATypDomain:
		return string(r.DstAddr[1:]) + ":" + strconv.Itoa(int(port))
	}
	return ""
}

func (r *RequestReply) Bytes() []byte {
	return append(append([]byte{r.Ver, r.Rep, r.Rsv, r.ATyp}, r.BndAddr...), r.BndPort...)
}
