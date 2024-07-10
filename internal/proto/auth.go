package proto

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

func (r *UserPassAuthReply) Bytes() []byte {
	return []byte{r.Ver, r.Status}
}
