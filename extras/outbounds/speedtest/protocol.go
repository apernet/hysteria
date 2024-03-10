package speedtest

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	typeDownload = 0x1
	typeUpload   = 0x2
)

// DownloadRequest format:
// 0x1 (byte)
// Request data length (uint32 BE)

func readDownloadRequest(r io.Reader) (uint32, error) {
	var l uint32
	err := binary.Read(r, binary.BigEndian, &l)
	return l, err
}

func writeDownloadRequest(w io.Writer, l uint32) error {
	buf := make([]byte, 5)
	buf[0] = typeDownload
	binary.BigEndian.PutUint32(buf[1:], l)
	_, err := w.Write(buf)
	return err
}

// DownloadResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (uint16 BE)
// Message (bytes)

func readDownloadResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	var msgLen uint16
	if err := binary.Read(r, binary.BigEndian, &msgLen); err != nil {
		return false, "", err
	}
	// No message is fine
	if msgLen == 0 {
		return status[0] == 0, "", nil
	}
	msgBuf := make([]byte, msgLen)
	_, err := io.ReadFull(r, msgBuf)
	if err != nil {
		return false, "", err
	}
	return status[0] == 0, string(msgBuf), nil
}

func writeDownloadResponse(w io.Writer, ok bool, msg string) error {
	sz := 1 + 2 + len(msg)
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	binary.BigEndian.PutUint16(buf[1:], uint16(len(msg)))
	copy(buf[3:], msg)
	_, err := w.Write(buf)
	return err
}

// UploadRequest format:
// 0x2 (byte)
// Upload data length (uint32 BE)

func readUploadRequest(r io.Reader) (uint32, error) {
	var l uint32
	err := binary.Read(r, binary.BigEndian, &l)
	return l, err
}

func writeUploadRequest(w io.Writer, l uint32) error {
	buf := make([]byte, 5)
	buf[0] = typeUpload
	binary.BigEndian.PutUint32(buf[1:], l)
	_, err := w.Write(buf)
	return err
}

// UploadResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (uint16 BE)
// Message (bytes)

func readUploadResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	var msgLen uint16
	if err := binary.Read(r, binary.BigEndian, &msgLen); err != nil {
		return false, "", err
	}
	// No message is fine
	if msgLen == 0 {
		return status[0] == 0, "", nil
	}
	msgBuf := make([]byte, msgLen)
	_, err := io.ReadFull(r, msgBuf)
	if err != nil {
		return false, "", err
	}
	return status[0] == 0, string(msgBuf), nil
}

func writeUploadResponse(w io.Writer, ok bool, msg string) error {
	sz := 1 + 2 + len(msg)
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	binary.BigEndian.PutUint16(buf[1:], uint16(len(msg)))
	copy(buf[3:], msg)
	_, err := w.Write(buf)
	return err
}

// UploadSummary format:
// Duration (in milliseconds, uint32 BE)
// Received data length (uint32 BE)

func readUploadSummary(r io.Reader) (time.Duration, uint32, error) {
	var duration uint32
	if err := binary.Read(r, binary.BigEndian, &duration); err != nil {
		return 0, 0, err
	}
	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return 0, 0, err
	}
	return time.Duration(duration) * time.Millisecond, l, nil
}

func writeUploadSummary(w io.Writer, duration time.Duration, l uint32) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf, uint32(duration/time.Millisecond))
	binary.BigEndian.PutUint32(buf[4:], l)
	_, err := w.Write(buf)
	return err
}
