package forwarder

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

func readClientSpeedRequest(r io.Reader) (*ClientSpeedRequest, error) {
	bs, err := readDataBlock(r)
	if err != nil {
		return nil, err
	}
	var req ClientSpeedRequest
	err = proto.Unmarshal(bs, &req)
	return &req, err
}

func writeClientSpeedRequest(w io.Writer, req *ClientSpeedRequest) error {
	bs, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	return writeDataBlock(w, bs)
}

func readServerSpeedResponse(r io.Reader) (*ServerSpeedResponse, error) {
	bs, err := readDataBlock(r)
	if err != nil {
		return nil, err
	}
	var resp ServerSpeedResponse
	err = proto.Unmarshal(bs, &resp)
	return &resp, err
}

func writeServerSpeedResponse(w io.Writer, resp *ServerSpeedResponse) error {
	bs, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	return writeDataBlock(w, bs)
}
