package socks5

import (
	"github.com/cieons/socks5/internal/proto"
	"io"
	"net"
	"strings"
)

func (s *Server) handleConnect(conn net.Conn, remoteAddr *Address) {
	var remoteConn net.Conn
	var err error

	remoteConn, err = net.Dial("tcp", remoteAddr.Addr())
	if err != nil {
		msg := err.Error()
		resp := proto.RepHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = proto.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = proto.RepNetworkUnreachable
		}
		s.logger.Debug().Err(err).Msg("dial remote failed")

		_, err = conn.Write(newRequestReply(resp, remoteAddr.ATyp, nil).Bytes())
		if err != nil {
			s.logger.Err(err).Msg("write reply failed")
		}

		return
	}
	defer remoteConn.Close()

	//send request reply first
	_, err = conn.Write(newRequestReply(proto.RepSuccess, proto.ATypIPv4, remoteConn.LocalAddr()).Bytes())
	if err != nil {
		s.logger.Err(err).Msg("write reply failed")
		return
	}

	// start to relay data
	s.proxy(remoteConn, conn)
}

func (s *Server) proxy(remote, client net.Conn) {
	errCh := make(chan error, 2)

	var relay = func(_dst io.Writer, _src io.Reader) {
		_, err := io.Copy(_dst, _src)
		if err != nil {
			//fmt.Println(err.Error())
			errCh <- err
		}
	}

	go relay(client, remote)
	go relay(remote, client)

	err := <-errCh
	s.logger.Debug().Err(err).Msg("error occurred when relay data, stop proxying")

	return
}
