package proto

import "errors"

const VersionSocks5 byte = 0x05

const (
	AuthMethodNone        byte = 0x00
	AuthMethodGSSAPI      byte = 0x01 // todo
	AuthMethodUserPass    byte = 0x02
	AuthMethodNotSupport  byte = 0xFF
	AuthMethodUserPassVer byte = 0x01
)

const (
	CmdConnect byte = 0x01
	CmdBind    byte = 0x02
	CmdUDP     byte = 0x03
)

const (
	ATypIPv4   byte = 0x01
	ATypDomain byte = 0x03
	ATypIPv6   byte = 0x04
)

const (
	RepSuccess              byte = 0x00
	RepServerFailure        byte = 0x01
	RepConnectionNotAllowed byte = 0x02
	RepNetworkUnreachable   byte = 0x03
	RepHostUnreachable      byte = 0x04
	RepConnectionRefused    byte = 0x05
	RepTTLExpired           byte = 0x06
	RepCommandNotSupported  byte = 0x07
	RepAddressNotSupported  byte = 0x08
)

var (
	ErrBadRequest          = errors.New("bad request")
	ErrInvalidSocksVersion = errors.New("invalid socks version")

	ErrInvalidUserPassAuthVersion = errors.New("invalid version of username password auth")
	ErrUserPassAuthFailure        = errors.New("username password auth failure")

	ErrCommandNotSupported = errors.New("command not supported")
	ErrATypNotSupported    = errors.New("address type not supported")
	ErrHostUnreachable     = errors.New("host unreachable")
)
