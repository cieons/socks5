package socks5

import (
	"context"
	"github.com/cieons/socks5/internal/proto"
	"github.com/rs/zerolog"
	"os"
	"time"

	"net"
)

type Server struct {
	ctx           context.Context
	authenticator Authenticator
	debug         bool
	logger        zerolog.Logger
	supportedCmd  []byte

	addr net.Addr
}

type NewServerOption func(s *Server)

func NewServer(opts ...NewServerOption) *Server {
	srv := &Server{
		ctx:           context.Background(),
		debug:         false,
		authenticator: &NoneAuthenticator{},
		supportedCmd:  []byte{proto.CmdConnect},
	}

	for _, opt := range opts {
		opt(srv)
	}

	if srv.debug {
		srv.logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.StampMilli}).
			With().Caller().Timestamp().Logger().Level(zerolog.DebugLevel)
	} else {
		srv.logger = zerolog.New(nil)
	}

	return srv
}

func (s *Server) Run(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Err(err).Msg("listen failed")
		return err
	}
	s.logger.Info().Str("addr", addr).Msg("server start")

	s.addr = listener.Addr()

	defer func() {
		_ = listener.Close()
	}()

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info().Msg("server shutdown...")
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Err(err).Msg("accept connection failed")
				return err
			}

			s.logger.Debug().Str("remote", conn.RemoteAddr().String()).Msg("start handling new connection")

			go s.handleConn(conn)
		}
	}
}

func (s *Server) Shutdown() {
	s.ctx.Done()
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	negotiateReq, err := s.parseNegotiateRequest(conn)
	if err != nil {
		s.logger.Debug().Err(err).Msg("invalid negotiate request, close connection")
		return
	}

	replyMethod, err := s.chooseAuthMethod(negotiateReq)
	if err != nil {
		s.logger.Debug().Err(err).Msg("choose auth method failed")
		return
	}

	_, err = conn.Write(s.negotiateReply(replyMethod).Bytes())
	if err != nil {
		s.logger.Err(err).Msg("write negotiate reply failed")
		return
	}

	s.logger.Debug().Bytes("auth method", []byte{replyMethod}).Msg("negotiate reply success")

	// no need to continue if not supported
	if replyMethod == proto.AuthMethodNotSupport {
		s.logger.Debug().Msg("auth method not supported, close connection")
		return
	}

	// todo authenticate log
	err = s.authenticator.Authenticate(conn)
	if err != nil {
		s.logger.Debug().Err(err).Msg("authenticate failed, close connection")
		return
	}

	req, err := s.parseRequest(conn)
	if err != nil {
		s.logger.Debug().Err(err).Msg("parse client request failed")
		return
	}
	if req.Ver != proto.VersionSocks5 {
		s.logger.Debug().Err(proto.ErrInvalidSocksVersion).Msg("invalid request, close connection")
		return
	}
	var support bool
	for _, c := range s.supportedCmd {
		if c == req.Cmd {
			support = true
			break
		}
	}
	if !support {
		s.logger.Debug().Err(proto.ErrCommandNotSupported).Msg("request command not supported")
		_, err = conn.Write(s.reply(proto.RepCommandNotSupported, nil).Bytes())
		if err != nil {
			s.logger.Err(err).Msg("write reply failed")
		}
		return
	}

	if req.ATyp != proto.ATypIPv4 && req.ATyp != proto.ATypIPv6 && req.ATyp != proto.ATypDomain {
		s.logger.Debug().Err(proto.ErrATypNotSupported).Msg("request address type not supported")
		_, err = conn.Write(s.reply(proto.RepCommandNotSupported, nil).Bytes())
		if err != nil {
			s.logger.Err(err).Msg("write reply failed")
		}
		return
	}

	s.handleRequest(conn, req)
}

func (s *Server) handleRequest(conn net.Conn, req *proto.Request) {
	switch req.Cmd {
	case proto.CmdConnect:
		s.handleCmdConnect(conn, req.Destination())
	default:
		_, err := conn.Write(s.reply(proto.RepCommandNotSupported, nil).Bytes())
		if err != nil {
			s.logger.Err(err).Msg("write reply failed")
			return
		}
	}
}

// aTyp return the type of server bind address
func (s *Server) aTyp() byte {
	serverAddr, _, _ := net.SplitHostPort(s.addr.String())
	if ip := net.ParseIP(serverAddr); ip != nil {
		if ip.To4() != nil {
			return proto.ATypIPv4
		} else {
			return proto.ATypIPv6
		}
	} else {
		return proto.ATypDomain
	}
}

func WithUserPassAuthenticator(credential map[string]string) NewServerOption {
	return func(s *Server) {
		s.authenticator = newUserPassAuthenticator(credential)
	}
}

func WithDebug(debug bool) NewServerOption {
	return func(s *Server) {
		s.debug = debug
	}
}
