package proto

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

func (np *NegotiateReply) Bytes() []byte {
	return []byte{np.Ver, np.Method}
}
