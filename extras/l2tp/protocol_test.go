package l2tp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeControlHeader(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	hdr := EncodeControlHeader(100, 200, 5, 3, len(payload))
	pkt := append(hdr, payload...)

	decoded, off, err := DecodeHeader(pkt)
	require.NoError(t, err)
	assert.True(t, decoded.IsControl)
	assert.True(t, decoded.HasLength)
	assert.Equal(t, uint16(100), decoded.Tunnel)
	assert.Equal(t, uint16(200), decoded.Session)
	assert.Equal(t, uint16(5), decoded.Ns)
	assert.Equal(t, uint16(3), decoded.Nr)
	assert.Equal(t, uint16(len(pkt)), decoded.Length)
	assert.Equal(t, payload, pkt[off:])
}

func TestEncodeDecodeDataHeader(t *testing.T) {
	hdr := EncodeDataHeader(100, 200)
	payload := []byte{0xC0, 0x21, 0x01, 0x02}
	pkt := append(hdr, payload...)

	decoded, off, err := DecodeHeader(pkt)
	require.NoError(t, err)
	assert.False(t, decoded.IsControl)
	assert.False(t, decoded.HasLength)
	assert.Equal(t, uint16(100), decoded.Tunnel)
	assert.Equal(t, uint16(200), decoded.Session)
	assert.Equal(t, payload, pkt[off:])
}

func TestEncodeDecodeAVPs(t *testing.T) {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeSCCRQ)...)
	buf = append(buf, EncodeStringAVP(AVPHostName, "test-lac")...)
	buf = append(buf, EncodeUint32AVP(AVPFramingCapabilities, FramingAsync|FramingSync)...)

	avps, err := DecodeAVPs(buf)
	require.NoError(t, err)
	require.Len(t, avps, 3)

	// Message Type
	assert.Equal(t, AVPMessageType, avps[0].Type)
	assert.True(t, avps[0].Mandatory)
	mt, err := AVPUint16(&avps[0])
	require.NoError(t, err)
	assert.Equal(t, MsgTypeSCCRQ, mt)

	// Host Name
	assert.Equal(t, AVPHostName, avps[1].Type)
	assert.Equal(t, "test-lac", string(avps[1].Value))

	// Framing Capabilities
	assert.Equal(t, AVPFramingCapabilities, avps[2].Type)
	fc, err := AVPUint32(&avps[2])
	require.NoError(t, err)
	assert.Equal(t, FramingAsync|FramingSync, fc)
}

func TestFindAVP(t *testing.T) {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeICRQ)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, 42)...)

	avps, err := DecodeAVPs(buf)
	require.NoError(t, err)

	found := FindAVP(avps, 0, AVPAssignedSessionID)
	require.NotNil(t, found)
	sid, err := AVPUint16(found)
	require.NoError(t, err)
	assert.Equal(t, uint16(42), sid)

	notFound := FindAVP(avps, 0, AVPHostName)
	assert.Nil(t, notFound)
}

func TestBuildSCCRQ(t *testing.T) {
	payload := BuildSCCRQ("my-lac", 1234, 4, nil)
	avps, err := DecodeAVPs(payload)
	require.NoError(t, err)

	mt, err := GetMessageType(avps)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeSCCRQ, mt)

	hn := FindAVP(avps, 0, AVPHostName)
	require.NotNil(t, hn)
	assert.Equal(t, "my-lac", string(hn.Value))

	tid := FindAVP(avps, 0, AVPAssignedTunnelID)
	require.NotNil(t, tid)
	v, _ := AVPUint16(tid)
	assert.Equal(t, uint16(1234), v)

	// No challenge when secret is nil
	ch := FindAVP(avps, 0, AVPChallenge)
	assert.Nil(t, ch)
}

func TestBuildSCCRQWithChallenge(t *testing.T) {
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload := BuildSCCRQ("my-lac", 1, 4, challenge)
	avps, err := DecodeAVPs(payload)
	require.NoError(t, err)

	ch := FindAVP(avps, 0, AVPChallenge)
	require.NotNil(t, ch)
	assert.Equal(t, challenge, ch.Value)
}

func TestBuildICCN(t *testing.T) {
	info := &ProxyInfo{
		InitialReceivedCONFREQ: []byte{1, 1, 0, 4},
		LastSentCONFREQ:        []byte{1, 2, 0, 10, 3, 5, 0xC2, 0x23, 5},
		LastReceivedCONFREQ:    []byte{1, 3, 0, 4},
		AuthType:               ProxyAuthenCHAP,
		AuthName:               "user@ispA.com",
		AuthChallenge:          []byte{0xAA, 0xBB},
		AuthID:                 7,
		AuthResponse:           []byte{0xCC, 0xDD},
	}
	payload := BuildICCN(info)
	avps, err := DecodeAVPs(payload)
	require.NoError(t, err)

	mt, _ := GetMessageType(avps)
	assert.Equal(t, MsgTypeICCN, mt)

	pat := FindAVP(avps, 0, AVPProxyAuthenType)
	require.NotNil(t, pat)
	patVal, _ := AVPUint16(pat)
	assert.Equal(t, ProxyAuthenCHAP, patVal)

	pan := FindAVP(avps, 0, AVPProxyAuthenName)
	require.NotNil(t, pan)
	assert.Equal(t, "user@ispA.com", string(pan.Value))

	pac := FindAVP(avps, 0, AVPProxyAuthenChallenge)
	require.NotNil(t, pac)
	assert.Equal(t, []byte{0xAA, 0xBB}, pac.Value)

	par := FindAVP(avps, 0, AVPProxyAuthenResponse)
	require.NotNil(t, par)
	assert.Equal(t, []byte{0xCC, 0xDD}, par.Value)
}

func TestComputeChallengeResponse(t *testing.T) {
	secret := []byte("mysecret")
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	resp := ComputeChallengeResponse(byte(MsgTypeSCCRP), secret, challenge)
	assert.Len(t, resp, 16) // MD5 output

	// Same inputs produce same output
	resp2 := ComputeChallengeResponse(byte(MsgTypeSCCRP), secret, challenge)
	assert.Equal(t, resp, resp2)

	// Different message type produces different output
	resp3 := ComputeChallengeResponse(byte(MsgTypeSCCCN), secret, challenge)
	assert.NotEqual(t, resp, resp3)
}
