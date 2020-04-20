package core

import (
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"io"
)

const (
	closeErrorCodeGeneric         = 0
	closeErrorCodeProtocolFailure = 1
)

func readDataBlock(r io.Reader) ([]byte, error) {
	var sz uint32
	if err := binary.Read(r, controlProtocolEndian, &sz); err != nil {
		return nil, err
	}
	buf := make([]byte, sz)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeDataBlock(w io.Writer, data []byte) error {
	sz := uint32(len(data))
	if err := binary.Write(w, controlProtocolEndian, &sz); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readClientAuthRequest(r io.Reader) (*ClientAuthRequest, error) {
	bs, err := readDataBlock(r)
	if err != nil {
		return nil, err
	}
	var req ClientAuthRequest
	err = proto.Unmarshal(bs, &req)
	return &req, err
}

func writeClientAuthRequest(w io.Writer, req *ClientAuthRequest) error {
	bs, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	return writeDataBlock(w, bs)
}

func readServerAuthResponse(r io.Reader) (*ServerAuthResponse, error) {
	bs, err := readDataBlock(r)
	if err != nil {
		return nil, err
	}
	var resp ServerAuthResponse
	err = proto.Unmarshal(bs, &resp)
	return &resp, err
}

func writeServerAuthResponse(w io.Writer, resp *ServerAuthResponse) error {
	bs, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	return writeDataBlock(w, bs)
}

func readClientConnectRequest(r io.Reader) (*ClientConnectRequest, error) {
	bs, err := readDataBlock(r)
	if err != nil {
		return nil, err
	}
	var req ClientConnectRequest
	err = proto.Unmarshal(bs, &req)
	return &req, err
}

func writeClientConnectRequest(w io.Writer, req *ClientConnectRequest) error {
	bs, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	return writeDataBlock(w, bs)
}

func readServerConnectResponse(r io.Reader) (*ServerConnectResponse, error) {
	bs, err := readDataBlock(r)
	if err != nil {
		return nil, err
	}
	var resp ServerConnectResponse
	err = proto.Unmarshal(bs, &resp)
	return &resp, err
}

func writeServerConnectResponse(w io.Writer, resp *ServerConnectResponse) error {
	bs, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	return writeDataBlock(w, bs)
}
