package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/txthinking/socks5"
	"net"
	"time"
)

type Client struct {
	ServerTCPAddr *net.TCPAddr
	Username      string
	Password      string
	NegTimeout    time.Duration
}

func NewClient(serverAddr string, username string, password string, negTimeout time.Duration) (*Client, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	return &Client{
		ServerTCPAddr: tcpAddr,
		Username:      username,
		Password:      password,
		NegTimeout:    negTimeout,
	}, nil
}

func (c *Client) negotiate(conn *net.TCPConn) error {
	m := []byte{socks5.MethodNone}
	if c.Username != "" && c.Password != "" {
		m = append(m, socks5.MethodUsernamePassword)
	}
	rq := socks5.NewNegotiationRequest(m)
	_, err := rq.WriteTo(conn)
	if err != nil {
		return err
	}
	rs, err := socks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		return err
	}
	if rs.Method == socks5.MethodUsernamePassword {
		urq := socks5.NewUserPassNegotiationRequest([]byte(c.Username), []byte(c.Password))
		_, err = urq.WriteTo(conn)
		if err != nil {
			return err
		}
		urs, err := socks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			return err
		}
		if urs.Status != socks5.UserPassStatusSuccess {
			return ErrUserPassAuth
		}
	} else if rs.Method != socks5.MethodNone {
		return errors.New("unsupported auth method")
	}
	return nil
}

func (c *Client) Request(conn *net.TCPConn, r *socks5.Request) (*socks5.Reply, error) {
	if _, err := r.WriteTo(conn); err != nil {
		return nil, err
	}
	reply, err := socks5.NewReplyFrom(conn)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) DialTCP(raddr *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := net.DialTCP("tcp", nil, c.ServerTCPAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(c.NegTimeout)); err != nil {
		return nil, err
	}
	err = c.negotiate(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var atyp byte
	var addr, port []byte
	if ip4 := raddr.IP.To4(); ip4 != nil {
		atyp = socks5.ATYPIPv4
		addr = ip4
	} else if ip6 := raddr.IP.To16(); ip6 != nil {
		atyp = socks5.ATYPIPv6
		addr = ip6
	} else {
		_ = conn.Close()
		return nil, errors.New("unsupported address type")
	}
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(raddr.Port))
	r := socks5.NewRequest(socks5.CmdConnect, atyp, addr, port)
	reply, err := c.Request(conn, r)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply.Rep != socks5.RepSuccess {
		_ = conn.Close()
		return nil, fmt.Errorf("request failed: %s", reply.Rep)
	}
	// Negotiation succeed, disable timeout
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}
