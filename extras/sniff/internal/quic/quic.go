package quic

const (
	V1 uint32 = 0x1
	V2 uint32 = 0x6b3343cf

	hkdfLabelKeyV1 = "quic key"
	hkdfLabelKeyV2 = "quicv2 key"
	hkdfLabelIVV1  = "quic iv"
	hkdfLabelIVV2  = "quicv2 iv"
	hkdfLabelHPV1  = "quic hp"
	hkdfLabelHPV2  = "quicv2 hp"
)

var (
	quicSaltOld = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	// https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	// https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-initial-salt-2
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// isLongHeader reports whether b is the first byte of a long header packet.
func isLongHeader(b byte) bool {
	return b&0x80 > 0
}

func getSalt(v uint32) []byte {
	switch v {
	case V1:
		return quicSaltV1
	case V2:
		return quicSaltV2
	}
	return quicSaltOld
}

func keyLabel(v uint32) string {
	kl := hkdfLabelKeyV1
	if v == V2 {
		kl = hkdfLabelKeyV2
	}
	return kl
}

func ivLabel(v uint32) string {
	ivl := hkdfLabelIVV1
	if v == V2 {
		ivl = hkdfLabelIVV2
	}
	return ivl
}

func headerProtectionLabel(v uint32) string {
	if v == V2 {
		return hkdfLabelHPV2
	}
	return hkdfLabelHPV1
}
